from elasticsearch import Elasticsearch
import pandas as pd
import json
from datetime import datetime

# ── CONNECTION ────────────────────────────────────────────────────────────────
ES_URL = "http://192.168.0.105:9200"  # if ES runs in VM, put VM IP
ES_USER = None  # e.g., "elastic"
ES_PASS = None  # e.g., "changeme"

# If your Python client is 9.x talking to ES 8.x, keep headers below; else remove.
HEADERS_8_COMPAT = {
    "Accept": "application/vnd.elasticsearch+json; compatible-with=8",
    "Content-Type": "application/vnd.elasticsearch+json; compatible-with=8",
}

es = Elasticsearch(
    ES_URL,
    basic_auth=(ES_USER, ES_PASS) if ES_USER and ES_PASS else None,
    headers=HEADERS_8_COMPAT,
)

# ── QUERY (last 15 minutes) ──────────────────────────────────────────────────
query = {
    "query": {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
    "size": 10000,
    "_source": True,
}

print("[*] Querying Elasticsearch (filebeat-*) …")
res = es.search(index="filebeat-*", body=query, scroll="2m")
scroll_id = res.get("_scroll_id")
hits = res["hits"]["hits"]

rows = []

def try_json(s):
    if not isinstance(s, str):
        return None
    s = s.strip()
    if not s or s[0] not in "{[":
        return None
    try:
        return json.loads(s)
    except Exception:
        return None

def to_ecs(doc):
    """
    Map/derive a safe ECS-minimal view.
    Prefer existing ECS fields if present; otherwise derive from available data.
    """
    src = doc.get("_source", {})
    # raw/known fields
    ts = src.get("@timestamp")
    msg = src.get("message")
    log_level = (src.get("log", {}) or {}).get("level")
    user_name = (src.get("user", {}) or {}).get("name")
    proc = src.get("process", {}) or {}
    src_net = src.get("source", {}) or {}
    dst_net = src.get("destination", {}) or {}
    host = src.get("host", {}) or {}
    agent = src.get("agent", {}) or {}
    ecs_meta = src.get("ecs", {}) or {}
    event = src.get("event", {}) or {}

    # If message looks like JSON, extract supplemental keys (non-destructive)
    msg_json = try_json(msg)
    if msg_json:
        # pull common keys if missing
        if not log_level:
            log_level = msg_json.get("log.level") or msg_json.get("level")
        # some beats put real text under "message" too; avoid overriding if identical
        inner_message = msg_json.get("message")
        if inner_message and isinstance(inner_message, str) and inner_message != msg:
            msg = inner_message

    # event.dataset / module
    event_dataset = event.get("dataset")
    if not event_dataset:
        # filebeat often sets fields like "fileset.module" or uses input/module hints
        # fallbacks:
        event_dataset = src.get("fileset", {}).get("name") or src.get("log", {}).get("file", {}).get("path")
        # keep as None if not meaningful
    event_module = event.get("module")
    if not event_module and isinstance(event_dataset, str) and "." in event_dataset:
        event_module = event_dataset.split(".", 1)[0]

    # event.kind (safe default)
    event_kind = event.get("kind") or "event"

    # ecs.version (prefer source, else set a current ECS you target)
    ecs_version = ecs_meta.get("version") or "8.11.0"

    # Build ECS row (minimal but correct)
    row = {
        "@timestamp": ts,
        "message": msg,
        "log.level": log_level,
        "event.kind": event_kind,
        "event.dataset": event_dataset,
        "event.module": event_module,
        "host.name": host.get("name"),
        "user.name": user_name,
        "process.name": proc.get("name"),
        "process.command_line": proc.get("command_line"),
        "process.pid": proc.get("pid"),
        "source.ip": src_net.get("ip"),
        "source.port": src_net.get("port"),
        "destination.ip": dst_net.get("ip"),
        "destination.port": dst_net.get("port"),
        "agent.type": agent.get("type"),
        "agent.name": agent.get("name"),
        "agent.version": agent.get("version"),
        "ecs.version": ecs_version,
    }

    # Normalize timestamp to RFC3339 if possible (string pass-through is ok for ES)
    if isinstance(row["@timestamp"], (int, float)):
        row["@timestamp"] = datetime.utcfromtimestamp(row["@timestamp"]).isoformat() + "Z"

    return row

# process first page
for h in hits:
    rows.append(to_ecs(h))

# scroll remaining
while True:
    res = es.scroll(scroll_id=scroll_id, scroll="2m")
    hits = res["hits"]["hits"]
    if not hits:
        break
    for h in hits:
        rows.append(to_ecs(h))

# ── OUTPUTS ──────────────────────────────────────────────────────────────────
df = pd.DataFrame(rows)

# Optional: drop columns that are entirely empty
df = df.dropna(axis=1, how="all")

# CSV for analysis
csv_path = "events_ecs.csv"
df.to_csv(csv_path, index=False)

# NDJSON for bulk re-ingest (1 JSON per line)
ndjson_path = "events_ecs.ndjson"
with open(ndjson_path, "w", encoding="utf-8") as f:
    for rec in df.to_dict(orient="records"):
        f.write(json.dumps({k: v for k, v in rec.items() if v is not None}, ensure_ascii=False) + "\n")

print(f"[+] Export complete → {csv_path} ({len(df)} rows, {df.shape[1]} columns)")
print(f"[+] Bulk-ready NDJSON → {ndjson_path}")
