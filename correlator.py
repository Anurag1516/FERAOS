import time
import json
import logging
import socket
from elasticsearch import Elasticsearch
from response_engine import isolate_host

# ───────────────── CONFIG ─────────────────
ES_HOST_IP = "10.73.63.109"
ES_URL = f"http://{ES_HOST_IP}:9200"

WINDOW_MINUTES = 15

RISK_THRESHOLD = 0.1
PROCESS_CRITICALITY_FLOOR = 0.02

# Re-arm & enforcement
QUARANTINE_TTL_SECONDS = 20 * 60      # 20 minutes
RECHECK_INTERVAL_SECONDS = 30         # liveness check

BLOCK_LOG_FILE = "blocked_entities.jsonl"

TRUSTED_PROCESSES = {
    "filebeat", "metricbeat", "packetbeat",
    "auditbeat", "tailscaled", "systemd",
    "cron", "networkmanager", "docker",
    "dbus-daemon"
}

SAFE_IPS = {
    "127.0.0.1", "::1", "localhost",
    ES_HOST_IP, "172.18.0.1", "172.17.0.1",
    "100.96.255.46",
    "fe80::42:2fff:fe6c:d3cd",
    "fe80::a846:62ff:fe21:7e3b",
    "fe80::e405:a1ff:fe56:76f2"
}

# ───────────────── LOGGING ─────────────────
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [SOAR] %(message)s")
LOG = logging.getLogger("correlator")

es = Elasticsearch(ES_URL)

# hostname → {timestamp, ip}
quarantined_hosts = {}

# ───────────────── HELPERS ─────────────────
def log_block(entity_type, value, reason):
    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "type": entity_type,
        "value": value,
        "reason": reason
    }
    with open(BLOCK_LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")

def safe_json(field):
    try:
        return json.loads(field) if isinstance(field, str) else {}
    except:
        return {}

def extract_process_name(src):
    proc = safe_json(src.get("meta_process"))
    return str(proc.get("name", "")).lower()

def extract_hostname(src):
    host = src.get("host", {})
    if isinstance(host, dict):
        return host.get("hostname") or host.get("name")
    meta_host = safe_json(src.get("meta_host"))
    return meta_host.get("name", "unknown")

def get_best_ip(src):
    candidates = []

    host = src.get("host", {})
    if isinstance(host, dict):
        ips = host.get("ip", [])
        if isinstance(ips, str):
            ips = [ips]
        candidates.extend(ips)

    src_ip = src.get("source", {}).get("ip")
    if src_ip:
        candidates.append(src_ip)

    dst_ip = src.get("destination", {}).get("ip")
    if dst_ip:
        candidates.append(dst_ip)

    for ip in candidates:
        if not ip or ip in SAFE_IPS:
            continue
        if ":" in ip or ip.startswith("172."):
            continue
        return ip

    return None

def is_host_alive(ip):
    try:
        socket.create_connection((ip, 22), timeout=3)
        return True
    except:
        return False

def quarantine_active(hostname):
    q = quarantined_hosts.get(hostname)
    if not q:
        return False
    if time.time() - q["timestamp"] > QUARANTINE_TTL_SECONDS:
        del quarantined_hosts[hostname]
        return False
    return True

# ───────────────── CORE LOGIC ─────────────────
def check_correlations():
    LOG.info(f"🔎 Scanning last {WINDOW_MINUTES} minutes for anomalies")

    query = {
        "size": 500,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{WINDOW_MINUTES}m"}}},
                    {"term": {"is_anomaly": True}}
                ]
            }
        }
    }

    try:
        resp = es.search(index="events-enriched-*", body=query, ignore_unavailable=True)
        hits = resp["hits"]["hits"]

        for hit in hits:
            src = hit["_source"]

            risk = float(src.get("risk_z_score", 0))
            process = extract_process_name(src)
            hostname = extract_hostname(src)
            ip = get_best_ip(src)

            is_trusted = process in TRUSTED_PROCESSES

            actionable = (
                risk >= RISK_THRESHOLD or
                (not is_trusted and risk >= PROCESS_CRITICALITY_FLOOR)
            )

            if not actionable:
                continue

            # ─── ALREADY QUARANTINED ───
            if quarantine_active(hostname):
                if ip and is_host_alive(ip):
                    LOG.warning(f"🔁 {hostname} active again → re-isolating")
                    isolate_host(ip)
                    log_block("ip", ip, "re-isolation after recovery")
                    quarantined_hosts[hostname]["timestamp"] = time.time()
                continue

            # ─── NEW ISOLATION ───
            LOG.warning(f"🚨 THREAT | host={hostname} process={process} risk={risk:.3f}")

            if ip:
                isolate_host(ip)
                log_block("ip", ip, "initial isolation")
            else:
                isolate_host(hostname)
                log_block("host", hostname, "initial isolation")

            quarantined_hosts[hostname] = {
                "timestamp": time.time(),
                "ip": ip
            }

    except Exception as e:
        LOG.error(f"❌ Correlation error: {e}")

# ───────────────── LOOP ─────────────────
if __name__ == "__main__":
    print("🛡️  SOAR Correlator (Continuous Enforcement) Running")
    while True:
        check_correlations()
        time.sleep(RECHECK_INTERVAL_SECONDS)
