
from __future__ import annotations
import argparse
import json
import logging
import math
import os
import socket
import sys
import tempfile
import threading
import time
import queue
from typing import Any, Dict, Iterable, List, Optional, Tuple
import ipaddress

import requests
from elasticsearch import Elasticsearch, helpers
from elasticsearch.helpers import streaming_bulk
from elastic_transport import ConnectionError as ESTransportConnectionError
from urllib3.exceptions import ProtocolError as Urllib3ProtocolError

# Logging
LOG = logging.getLogger("enricher")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

# Defaults
DEFAULT_ES_HOST = "http://100.96.255.46:9200"
DEFAULT_DEST_ALIAS = "events-enriched-write"
DEFAULT_BATCH = 256
DEFAULT_INFERENCE_WORKERS = 2
DEFAULT_INDEXER_WORKERS = 2
DEFAULT_INFLIGHT = 8
MAX_RETRIES = 3
RETRY_BACKOFF = 1.0
TEMP_DIR = tempfile.gettempdir() if os.path.isdir(tempfile.gettempdir()) else os.getcwd()

# Utilities
def safe_save_json(obj: Any, filename_prefix: str = "dump") -> str:
    ts = int(time.time())
    fname = f"{filename_prefix}_{ts}.json"
    path = os.path.join(TEMP_DIR, fname)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, default=str, indent=2)
        return path
    except Exception:
        path2 = os.path.join(os.getcwd(), fname)
        with open(path2, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, default=str, indent=2)
        return path2

# ES client
def get_es_client(es_host: str, es_api_key: Optional[str], es_user: Optional[str], es_pass: Optional[str]) -> Elasticsearch:
    if es_api_key:
        return Elasticsearch([es_host], api_key=es_api_key, request_timeout=60)
    if es_user and es_pass:
        return Elasticsearch([es_host], http_auth=(es_user, es_pass), request_timeout=60)
    return Elasticsearch([es_host], request_timeout=60)

# Feature conversion & normalization
def record_to_vector(rec: Dict[str, Any], prefer_order: Optional[List[str]] = None) -> List[float]:
    # If the record already has a "features" list, use it and sanitize
    if "features" in rec and isinstance(rec["features"], (list, tuple)):
        out = []
        for v in rec["features"]:
            if isinstance(v, (list, tuple, dict)):
                out.append(float(len(v)))
            else:
                try:
                    out.append(float(v))
                except Exception:
                    try:
                        out.append(float(str(v)))
                    except Exception:
                        out.append(0.0)
        return out

    # Flatten logic
    keys = prefer_order if prefer_order else sorted(rec.keys())
    vec = []
    for k in keys:
        v = rec.get(k)
        if k.startswith("_") and k not in ("@timestamp",):
            continue
        if v is None:
            vec.append(0.0); continue
        if isinstance(v, bool):
            vec.append(1.0 if v else 0.0); continue
        if isinstance(v, (int, float)):
            try:
                fv = float(v)
                vec.append(fv if math.isfinite(fv) else 0.0)
            except Exception:
                vec.append(0.0)
            continue
        if isinstance(v, (list, tuple)):
            vec.append(float(len(v))); continue
        if isinstance(v, dict):
            vec.append(float(len(v))); continue
        if isinstance(v, str):
            s = v.strip()
            try:
                vec.append(float(s)); continue
            except Exception:
                try:
                    s2 = s.replace(",", "").replace("[", "").replace("]", "")
                    vec.append(float(s2)); continue
                except Exception:
                    vec.append(float(len(s))); continue
        try:
            vec.append(float(v))
        except Exception:
            vec.append(0.0)
    return vec

def normalize_batch_from_records(records: List[Dict[str, Any]], expected_n_features: Optional[int] = None,
                                  prefer_order: Optional[List[str]] = None, pad_value: float = 0.0
                                  ) -> Tuple[List[List[float]], Optional[str]]:
    feature_lists = []
    for rec in records:
        feature_lists.append(record_to_vector(rec, prefer_order=prefer_order))

    if expected_n_features:
        for i, fl in enumerate(feature_lists):
            if len(fl) < expected_n_features:
                feature_lists[i] = fl + [float(pad_value)] * (expected_n_features - len(fl))
            elif len(fl) > expected_n_features:
                feature_lists[i] = fl[:expected_n_features]

    lengths = [len(x) for x in feature_lists if isinstance(x, (list, tuple))]
    lengths_set = set(lengths)
    if len(lengths_set) != 1:
        path = safe_save_json({"records": records, "vectors": feature_lists, "lengths": lengths}, filename_prefix="bad_batch")
        LOG.error("Inhomogeneous record lengths after normalization: %s saved=%s", lengths_set, path)
        return feature_lists, path
    return feature_lists, None

def debug_inspect_batch(batch_features: List[Any], limit_print: int = 3) -> List[Tuple[int, str, Any]]:
    LOG.debug("batch length: %d", len(batch_features))
    bad = []
    for i, rec in enumerate(batch_features):
        if not isinstance(rec, (list, tuple)):
            bad.append((i, "not-list", type(rec))); continue
        for j, v in enumerate(rec):
            if v is None:
                bad.append((i, f"none-at-{j}", v)); break
            try:
                fv = float(v)
                if math.isinf(fv) or math.isnan(fv):
                    bad.append((i, f"nan_or_inf_at_{j}", v)); break
            except Exception as e:
                bad.append((i, f"non-numeric-at-{j}", str(e))); break
    if bad:
        LOG.warning("Found %d bad records in batch; sample: %s", len(bad), bad[:10])
    return bad

# Sanitizer to match mapping
def sanitize_enriched_event(ev: dict) -> dict:
    out = dict(ev)
    # remove accidental _id in source
    out.pop("_id", None)
    # move complex top-level values into meta_ except message
    for k in list(out.keys()):
        if k == "message":
            continue
        v = out[k]
        if isinstance(v, (list, dict)):
            try:
                out[f"meta_{k}"] = json.dumps(v, default=str)
            except Exception:
                out[f"meta_{k}"] = str(v)
            del out[k]
    # timestamp
    if "@timestamp" not in out or not out.get("@timestamp"):
        out["@timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # host normalization
    host = out.get("host")
    if isinstance(host, dict):
        if "name" in host:
            try:
                host["name"] = str(host["name"])
            except Exception:
                host["name"] = json.dumps(host["name"], default=str)
        if "ip" in host:
            try:
                ipstr = str(host["ip"])
                ipaddress.ip_address(ipstr)
                host["ip"] = ipstr
            except Exception:
                host.pop("ip", None)
        out["host"] = host
    # source.ip
    source = out.get("source")
    if isinstance(source, dict) and "ip" in source:
        try:
            ipstr = str(source["ip"])
            ipaddress.ip_address(ipstr)
            source["ip"] = ipstr
        except Exception:
            source.pop("ip", None)
        out["source"] = source
    # replace dots in keys
    for k in list(out.keys()):
        if "." in str(k):
            newk = k.replace(".", "_")
            out[newk] = out.pop(k)
    return out

# Inference caller (fixed)
def call_inference_with_retries(features, inference_url, headers, timeout, max_retries=3):
    """
    Sends 'features' as a JSON file via Multipart form-data.
    Structure: {"features": [[0.1, ...], [0.2, ...]]}
    """
    # Wrap in dict to match what API Server now expects (or handles correctly)
    payload_dict = {"features": features}
    payload_json = json.dumps(payload_dict, default=str)

    last_exc = None

    for attempt in range(1, max_retries + 1):
        try:
            # Files structure for requests
            # 'features' is the field name API server expects
            files = {
                "features": ("features.json", payload_json, "application/json")
            }

            resp = requests.post(
                inference_url,
                headers=headers,
                files=files,
                timeout=timeout
            )

            # Check HTTP success
            if 200 <= resp.status_code < 300:
                try:
                    out = resp.json()
                except Exception:
                    # If success but not JSON, something is odd, but return text as debug
                    return [resp.text] * len(features)

                # Return list of results
                if isinstance(out, list):
                    return out

                # If wrapped in dict
                if isinstance(out, dict):
                    for k in ("predictions", "results", "scores", "enriched_events"):
                        if k in out and isinstance(out[k], list):
                            return out[k]
                    return [out] * len(features)

                return [out] * len(features)

            # --- HTTP Error Handling ---
            diag = {
                "attempt": attempt,
                "status": resp.status_code,
                "response": resp.text,
            }
            path = safe_save_json(diag, "inference_multipart_failed")
            LOG.error("Inference failed HTTP %d; diag=%s", resp.status_code, path)

            # Retrying logic
            if attempt < max_retries:
                time.sleep(RETRY_BACKOFF * attempt)
                continue
            else:
                raise RuntimeError(f"Inference failed: {resp.status_code} {resp.text}")

        except Exception as exc:
            last_exc = exc
            LOG.warning("Inference network/conn error: %s", exc)
            if attempt < max_retries:
                time.sleep(RETRY_BACKOFF * attempt)
                continue
            raise RuntimeError(f"Inference failed after {max_retries} attempts: {exc}")

# Bulk indexer
def bulk_index_with_error_capture(es_client: Elasticsearch, actions: List[Dict[str, Any]],
                                  chunk_size: int = 500, max_attempts: int = 3) -> int:
    if not isinstance(actions, list):
        actions = list(actions)
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        errors = []
        total = 0
        try:
            for ok, resp in streaming_bulk(client=es_client, actions=actions, chunk_size=chunk_size, raise_on_error=False):
                total += 1
                if not ok:
                    errors.append(resp)
            if errors:
                path = safe_save_json({"error_count": len(errors), "errors_sample": errors[:50]}, filename_prefix="es_failed")
                raise RuntimeError(f"{len(errors)} document(s) failed to index; details saved to {path}")
            return total
        except (ESTransportConnectionError, Urllib3ProtocolError, socket.error) as exc:
            last_exc = exc
            LOG.warning("Bulk transport error attempt %d/%d: %s", attempt, max_attempts, exc)
            if attempt < max_attempts:
                time.sleep(RETRY_BACKOFF * attempt)
                continue
            raise RuntimeError(f"Bulk failed transport error: {exc}")
        except Exception as exc:
            path = safe_save_json({"exception": str(exc)}, filename_prefix="es_diag")
            LOG.error("Bulk failed; diagnostic saved to %s", path)
            raise

# Pipeline Workers
def producer_thread(es: Elasticsearch, source_index: str, batch_size: int, inference_q: queue.Queue, limit: int):
    count = 0
    batch = []
    LOG.info("Producer started scanning %s", source_index)

    # Use scan to efficiently scroll
    scan_iter = helpers.scan(client=es, index=source_index, query={"query": {"match_all": {}}}, size=1000, preserve_order=False)

    for hit in scan_iter:
        src = hit.get("_source", {}) or {}
        if "_id" not in src:
            src["_id"] = hit.get("_id")
        batch.append(src)

        if len(batch) >= batch_size:
            inference_q.put(batch)
            count += len(batch)
            batch = []
            if limit and count >= limit:
                break

    if batch:
        inference_q.put(batch)
        count += len(batch)

    LOG.info("Producer finished; pushed ~%d docs", count)
    inference_q.put(None)

def inference_worker(worker_id: int, inference_q: queue.Queue, index_q: queue.Queue, inference_url: str,
                     infer_api_key: Optional[str], expected_features: Optional[int], timeout: int):
    headers = {}
    if infer_api_key:
        headers["x-api-key"] = infer_api_key
    while True:
        batch = inference_q.get()
        if batch is None:
            inference_q.put(None)
            index_q.put(None)
            LOG.info("Inference worker %d exiting", worker_id)
            break

        # Normalize
        features, bad_path = normalize_batch_from_records(batch, expected_n_features=expected_features)
        if bad_path:
            LOG.error("Skipping batch due to invalid feature shapes: %s", bad_path)
            continue

        # Debug Inspect
        if LOG.isEnabledFor(logging.DEBUG):
            debug_inspect_batch(features, limit_print=2)

        # Call Inference
        try:
            preds = call_inference_with_retries(features, inference_url, headers=headers, timeout=timeout, max_retries=MAX_RETRIES)
        except Exception as e:
            path = safe_save_json({"error": str(e), "batch_sample": batch[:5]}, filename_prefix="inference_failed")
            LOG.exception("Inference failed; batch saved to %s", path)
            continue

        # Merge Results
        enriched = []
        # Handle case where preds len != batch len (should be handled by list multiplication on error, but safety first)
        if len(preds) != len(batch):
            LOG.error("Prediction count mismatch: got %d, expected %d", len(preds), len(batch))
            continue

        for orig, pred in zip(batch, preds):
            merged = dict(orig)
            if isinstance(pred, dict):
                merged.update(pred)
            else:
                merged["model_prediction"] = pred
            enriched.append(merged)

        sanitized = [sanitize_enriched_event(ev) for ev in enriched]
        index_q.put(sanitized)

def indexer_worker(worker_id: int, es_client: Elasticsearch, index_q: queue.Queue, dest_alias: str, chunk_size: int):
    while True:
        batch = index_q.get()
        if batch is None:
            index_q.put(None)
            LOG.info("Indexer worker %d exiting", worker_id)
            break
        actions = []
        for ev in batch:
            doc_id = ev.pop("_id", None)
            action = {"_op_type": "index", "_index": dest_alias, "_source": ev}
            if doc_id:
                action["_id"] = doc_id
            actions.append(action)
        try:
            cnt = bulk_index_with_error_capture(es_client, actions, chunk_size=chunk_size, max_attempts=MAX_RETRIES)
            LOG.info("Indexer %d bulk indexed %d docs", worker_id, cnt)
        except Exception:
            # Error already logged/saved in function
            pass

def main():
    parser = argparse.ArgumentParser(description="Optimized enricher pipeline (fixed)")
    parser.add_argument("--es-host", default=DEFAULT_ES_HOST)
    parser.add_argument("--es-user", default=None)
    parser.add_argument("--es-pass", default=None)
    parser.add_argument("--es-api-key", default=None)
    parser.add_argument("--source-index", required=True)
    parser.add_argument("--dest-alias", default=DEFAULT_DEST_ALIAS)
    parser.add_argument("--inference-url", required=True)
    parser.add_argument("--infer-api-key", default=None)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH)
    parser.add_argument("--expected-features", type=int, default=0)
    parser.add_argument("--inference-workers", type=int, default=DEFAULT_INFERENCE_WORKERS)
    parser.add_argument("--indexer-workers", type=int, default=DEFAULT_INDEXER_WORKERS)
    parser.add_argument("--inflight", type=int, default=DEFAULT_INFLIGHT)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--chunk-size", type=int, default=500)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        LOG.setLevel(logging.DEBUG)

    es = get_es_client(args.es_host, args.es_api_key, args.es_user, args.es_pass)
    LOG.info("Starting pipeline: %s -> %s (inference=%s)", args.source_index, args.dest_alias, args.inference_url)

    inference_q: queue.Queue = queue.Queue(maxsize=args.inflight)
    index_q: queue.Queue = queue.Queue(maxsize=args.inflight * 2)

    prod = threading.Thread(target=producer_thread, args=(es, args.source_index, args.batch_size, inference_q, args.limit), daemon=True)
    prod.start()

    inf_workers = []
    for wid in range(args.inference_workers):
        t = threading.Thread(target=inference_worker, args=(wid, inference_q, index_q, args.inference_url, args.infer_api_key, (args.expected_features or None), args.timeout), daemon=True)
        t.start()
        inf_workers.append(t)

    idx_workers = []
    for wid in range(args.indexer_workers):
        t = threading.Thread(target=indexer_worker, args=(wid, es, index_q, args.dest_alias, args.chunk_size), daemon=True)
        t.start()
        idx_workers.append(t)

    prod.join()
    LOG.info("Producer done; waiting for inference workers")
    for t in inf_workers:
        t.join()
    LOG.info("Inference workers finished; waiting for indexers")
    for t in idx_workers:
        t.join()
    LOG.info("Pipeline complete.")

if __name__ == "__main__":
    while True:
        main()
