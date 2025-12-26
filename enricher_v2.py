

from __future__ import annotations
import argparse
import json
import logging
import sys
import threading
import time
import queue
from datetime import datetime, timedelta
import warnings

warnings.filterwarnings("ignore")

import joblib
import pandas as pd
import numpy as np
from scipy.sparse import hstack
from elasticsearch import Elasticsearch, helpers

# ───────────────── LOGGING ─────────────────
LOG = logging.getLogger("enricher")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [SOAR] %(message)s")

# ───────────────── CONFIG ─────────────────
DEFAULT_ES_HOST = "http://[ip]:9200"
DEFAULT_DEST_ALIAS = "events-enriched-write"

AI_SENSITIVITY_THRESHOLD = 0.02

TRUSTED_USERS = {"root", "aamon", "kali"}

TRUSTED_PROCESSES = {
    "filebeat", "metricbeat", "packetbeat",
    "auditbeat", "systemd", "cron",
    "dbus-daemon", "tailscaled"
}

TRUSTED_COMMAND_KEYWORDS = {
    "apt ", "apt-get",
    "systemctl", "service ",
}

TRUSTED_ACTIVITY_RISK_MULTIPLIER = 0.15
TRUSTED_PROCESS_RISK_MULTIPLIER = 0.2

# ───────────────── GLOBALS ─────────────────
LOCAL_MODEL = None
PREPROCESSORS = None


# ───────────────── HELPERS ─────────────────
def extract_user(event):
    u = event.get("user")
    if isinstance(u, dict):
        return str(u.get("name", "")).lower()
    return ""


def extract_process(event):
    proc = event.get("process")
    if isinstance(proc, dict) and "name" in proc:
        return proc["name"].lower()

    meta = event.get("meta_process")
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
            return str(meta.get("name", "")).lower()
        except:
            pass

    return ""


def is_trusted_command(msg: str):
    msg = msg.lower()
    return any(k in msg for k in TRUSTED_COMMAND_KEYWORDS)


def is_infra_event(event):
    proc = extract_process(event)
    if proc in TRUSTED_PROCESSES:
        return True

    msg = str(event.get("message", "")).lower()
    return "monitoring" in msg or "metrics" in msg


def is_auth_failure(event):
    msg = str(event.get("message", "")).lower()
    proc = extract_process(event)

    return (
        "authentication failure" in msg or
        "failed password" in msg or
        "invalid user" in msg or
        proc.startswith("pam_unix")
    )


def clean_entity(x):
    if isinstance(x, dict):
        return str(x.get("name", "unknown"))
    return str(x) if pd.notna(x) else "unknown"


# ───────────────── ARTIFACTS ─────────────────
def load_artifacts(model_path, preproc_path):
    global LOCAL_MODEL, PREPROCESSORS
    try:
        LOG.info("Loading AI artifacts…")
        data = joblib.load(model_path)
        LOCAL_MODEL = data["model"] if isinstance(data, dict) else data
        PREPROCESSORS = joblib.load(preproc_path)
        LOG.info("✅ Model + preprocessors loaded")
    except Exception as e:
        LOG.error("Artifact load failed: %s", e)
        sys.exit(1)


# ───────────────── FEATURE ENGINEERING ─────────────────
def engineer_features(batch):
    df = pd.DataFrame(batch)

    for c in ["message", "user", "host", "@timestamp"]:
        if c not in df.columns:
            df[c] = ""

    df["message"] = df["message"].astype(str)
    df["user"] = df["user"].apply(clean_entity)
    df["host"] = df["host"].apply(clean_entity)

    def hour(ts):
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).hour
        except:
            return 0

    df["hour"] = df["@timestamp"].apply(hour)
    df["msg_len"] = df["message"].str.len()

    nums = PREPROCESSORS["scaler"].transform(df[["hour", "msg_len"]])
    cats = PREPROCESSORS["ohe"].transform(df[["user", "host"]])
    tfidf = PREPROCESSORS["tfidf"].transform(df["message"])
    hv = PREPROCESSORS["hv"].transform(df["message"])

    return hstack([nums, cats, tfidf, hv])


# ───────────────── INFERENCE ─────────────────
def infer_batch(batch):
    X = engineer_features(batch)
    scores = LOCAL_MODEL.decision_function(X)

    results = []

    for i, score in enumerate(scores):
        event = batch[i]
        user = extract_user(event)
        process = extract_process(event)
        message = str(event.get("message", ""))

        # 1️⃣ HARD INFRA BYPASS
        if is_infra_event(event):
            results.append({
                "is_anomaly": False,
                "risk_z_score": 0.001,
                "user_trust": "system",
                "activity_type": "infra",
                "model_version": "v5"
            })
            continue

        # 2️⃣ BASE RISK
        base_risk = abs(score - AI_SENSITIVITY_THRESHOLD)
        is_anomaly = score < AI_SENSITIVITY_THRESHOLD

        # 3️⃣ AUTH FAILURE BOOST
        if is_auth_failure(event):
            risk = max(base_risk * 3.0, 0.05)
            is_anomaly = True

        # 4️⃣ TRUSTED USER SUPPRESSION
        elif user in TRUSTED_USERS and is_trusted_command(message):
            risk = max(base_risk * TRUSTED_ACTIVITY_RISK_MULTIPLIER, 0.005)
            is_anomaly = risk > 0.03

        # 5️⃣ TRUSTED PROCESS SOFT SUPPRESSION
        elif process in TRUSTED_PROCESSES:
            risk = max(base_risk * TRUSTED_PROCESS_RISK_MULTIPLIER, 0.005)
            is_anomaly = risk > 0.02

        else:
            risk = base_risk

        results.append({
            "is_anomaly": is_anomaly,
            "risk_z_score": round(float(risk), 5),
            "user_trust": "trusted" if user in TRUSTED_USERS else "untrusted",
            "activity_type": "privileged" if is_trusted_command(message) else "normal",
            "model_version": "v5"
        })

    return results


# ───────────────── WORKER ─────────────────
def worker(es, dest, q):
    while True:
        batch = q.get()
        preds = infer_batch(batch)

        docs = []
        for src, pred in zip(batch, preds):
            doc = dict(src)
            doc.update(pred)
            doc.pop("_id", None)

            for k, v in list(doc.items()):
                if isinstance(v, (dict, list)) and k not in ["host", "source", "user"]:
                    try:
                        doc[f"meta_{k}"] = json.dumps(v, default=str)
                        del doc[k]
                    except:
                        pass

            docs.append({"_index": dest, "_source": doc})

        helpers.bulk(es, docs, raise_on_error=False)
        q.task_done()


# ───────────────── MAIN ─────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-index", required=True)
    parser.add_argument("--model-path", default="siem_model.pkl")
    parser.add_argument("--preproc-path", default="preprocessors.pkl")
    parser.add_argument("--lookback", type=int, default=10)
    args = parser.parse_args()

    load_artifacts(args.model_path, args.preproc_path)

    es = Elasticsearch(DEFAULT_ES_HOST)
    q = queue.Queue(maxsize=20)

    threading.Thread(
        target=worker,
        args=(es, DEFAULT_DEST_ALIAS, q),
        daemon=True
    ).start()

    last_tick = (datetime.utcnow() - timedelta(minutes=args.lookback)).isoformat() + "Z"
    LOG.info("AI Watchdog running from %s", last_tick)

    while True:
        try:
            query = {
                "query": {"range": {"@timestamp": {"gt": last_tick}}},
                "sort": [{"@timestamp": "asc"}]
            }
            res = es.search(index=args.source_index, body=query, size=500)
            hits = res["hits"]["hits"]

            if not hits:
                time.sleep(2)
                continue

            batch = [h["_source"] for h in hits]
            q.put(batch)

            last_tick = hits[-1]["_source"].get("@timestamp", last_tick)
            LOG.info("Processed %d events", len(batch))

        except Exception as e:
            LOG.error("Watchdog error: %s", e)
            time.sleep(5)


if __name__ == "__main__":
    main()
