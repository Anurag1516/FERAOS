# siem_feature_extractor.py
"""
Comprehensive SIEM feature extraction pipeline for Parquet event files.
Produces:
 - event_level_features.parquet  (one row per raw event + derived fields)
 - aggregated_features.parquet   (grouped/session/host/user aggregates per time window)
 - feature_matrix.npz            (X, feature_names for ML)
Author: ChatGPT (for user's AI-SIEM pipeline)
"""

import argparse
import os
from datetime import timedelta
import numpy as np
import pandas as pd
# helper: safe column accessor (place after imports)

def column_series_or_default(df: pd.DataFrame, col_name: str, default=np.nan) -> pd.Series:
    """
    Return df[col_name] if it exists, otherwise return a Series of `default` values
    with the same index as df. This prevents AttributeError when calling .apply().
    """
    if col_name in df.columns:
        return df[col_name]
    return pd.Series([default] * len(df), index=df.index)



from tqdm import tqdm
from dateutil import parser as date_parser
from sklearn.feature_extraction.text import TfidfVectorizer, HashingVectorizer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from scipy.sparse import hstack, csr_matrix, save_npz
# add this helper near the top (after imports)



# -------------------------
# Configurable parameters
# -------------------------
AGG_WINDOWS = ["5min", "15min", "1h"]  # pandas offsets (5 minutes, 15 minutes, 1 hour)
TOP_N_MESSAGE_TOKENS = 500
TFIDF_MAX_FEATURES = 1024
HASHING_FEATURES = 512

# -------------------------
# Helpers
# -------------------------
def ensure_timestamp(df, ts_col="@timestamp"):
    """
    Ensure df[ts_col] is a pandas datetime64[ns] column.
    Handles:
      - already-datetime values (pd.Timestamp)
      - ISO strings '2025-11-20T12:05:00Z'
      - unix timestamps (ints/floats)
      - other parseable strings
    Returns df with normalized datetime column.
    """
    # If column missing, create it as NaT
    if ts_col not in df.columns:
        df[ts_col] = pd.NaT
        return df

    col = df[ts_col]

    # If it is already a datetime dtype, just coerce to tz-naive (optional)
    if pd.api.types.is_datetime64_any_dtype(col):
        # keep as-is but ensure pandas dtype (and coerce tz to UTC-less)
        df[ts_col] = pd.to_datetime(col, errors="coerce")
        return df

    # Try fast vectorized conversion: handles strings, ints, floats
    # pass unit='s' only if values look numeric unix timestamps -- we'll try both
    # First attempt generic to_datetime
    df[ts_col] = pd.to_datetime(col, errors="coerce", utc=False)

    # If many NaT remain but values are numeric strings or numbers, try numeric conversion
    if df[ts_col].isna().sum() > 0:
        # try interpreting as unix (seconds) for numeric-like
        try:
            numeric_mask = col.dropna().astype(str).str.match(r'^\d+(\.\d+)?$')
            if numeric_mask.any():
                # convert numeric unix timestamps (seconds)
                # create a series of floats/ints where possible
                numeric_vals = pd.to_numeric(col, errors="coerce")
                maybe_unix = pd.to_datetime(numeric_vals, unit="s", errors="coerce")
                # fill only where original conversion failed and maybe_unix is valid
                df[ts_col] = df[ts_col].fillna(maybe_unix)
        except Exception:
            pass

    # Last fallback: try elementwise parse for remaining (rare). This is slow but only for leftovers.
    if df[ts_col].isna().any():
        mask = df[ts_col].isna()
        try:
            parsed = col[mask].astype(str).apply(lambda x: date_parser.parse(x) if x and x != 'nan' else pd.NaT)
            df.loc[mask, ts_col] = pd.to_datetime(parsed, errors="coerce")
        except Exception:
            # if that still fails, leave as NaT
            df.loc[mask, ts_col] = pd.NaT

    return df

def basic_normalize(df):
    """
    Build normalized DataFrame in a non-fragmented way (collect columns then concat).
    Maps common field names to canonical names and ensures key columns exist.
    """
    import numpy as np

    col_map = {
        "@timestamp": "@timestamp",
        "timestamp": "@timestamp",
        "host.name": "host.name",
        "host": "host.name",
        "source.ip": "src_ip",
        "src_ip": "src_ip",
        "sourceIPAddress": "src_ip",      # CloudTrail
        "destination.ip": "dst_ip",
        "dst_ip": "dst_ip",
        "source.port": "src_port",
        "destination.port": "dst_port",
        "message": "message",
        "msg": "message",
        "user.name": "user",
        "user": "user",
        "process.name": "process_name",
        "process.command_line": "process_cmdline",
        "event.action": "event_action",
        "event.id": "event_id",
        "event.dataset": "event_dataset",
        "event.module": "event_module",
        "log.level": "log_level",
        "agent.name": "agent_name",
    }

    # Collect columns to build once
    frames = {}
    # Use mapping priority: if source exists, assign to destination
    for src, dst in col_map.items():
        if src in df.columns and dst not in frames:
            frames[dst] = df[src]

    # Keep any remaining original columns not already mapped
    for c in df.columns:
        if c not in frames:
            frames[c] = df[c]

    # Convert dict of series to DataFrame via concat (single allocation)
    norm = pd.concat(frames, axis=1)

    # Normalize timestamp column with vectorized function
    norm = ensure_timestamp(norm, "@timestamp")

    # Safe port casting using vectorized pd.to_numeric (faster than apply)
    if "src_port" in norm.columns:
        norm["src_port"] = pd.to_numeric(norm["src_port"], errors="coerce")
    else:
        norm["src_port"] = np.nan

    if "dst_port" in norm.columns:
        norm["dst_port"] = pd.to_numeric(norm["dst_port"], errors="coerce")
    else:
        norm["dst_port"] = np.nan

    # Fill canonical missing columns with default values (avoid later df.get(...)=None)
    for c, default in {
        "host.name": None,
        "user": None,
        "process_name": None,
        "event_dataset": None,
        "event_module": None,
        "log_level": None,
        "agent_name": None,
        "src_ip": np.nan,
        "dst_ip": np.nan,
        "message": "",
    }.items():
        if c not in norm.columns:
            norm[c] = default

    # Optional: copy to defragment memory layout
    norm = norm.copy()

    return norm
# -------------------------
# Event-level features (raw)
# -------------------------
def event_level_features(df):
    import ipaddress
    def is_private_ip(ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except Exception:
            return False

    # time features
    df["hour_of_day"] = df["@timestamp"].dt.hour
    df["day_of_week"] = df["@timestamp"].dt.dayofweek

    # message metrics (safe)
    df["message"] = column_series_or_default(df, "message", default="").fillna("").astype(str)
    df["message_len"] = df["message"].str.len()
    df["message_tokens"] = df["message"].str.split().apply(len)

    # ip flags (use safe accessor)
    src_ip_series = column_series_or_default(df, "src_ip", default=np.nan)
    dst_ip_series = column_series_or_default(df, "dst_ip", default=np.nan)
    df["src_internal"] = src_ip_series.apply(lambda x: is_private_ip(x) if pd.notna(x) and x != "" else False)
    df["dst_internal"] = dst_ip_series.apply(lambda x: is_private_ip(x) if pd.notna(x) and x != "" else False)

    # port categories (safe)
    src_port_series = column_series_or_default(df, "src_port", default=np.nan)
    dst_port_series = column_series_or_default(df, "dst_port", default=np.nan)
    df["src_port_known"] = src_port_series.apply(lambda p: 1 if (pd.notna(p) and str(p).isdigit() and 0 <= int(p) <= 1023) else 0)
    df["dst_port_known"] = dst_port_series.apply(lambda p: 1 if (pd.notna(p) and str(p).isdigit() and 0 <= int(p) <= 1023) else 0)

    # presence flags (safe)
    df["has_user"] = column_series_or_default(df, "user", default=None).notna().astype(int)
    df["has_process_cmdline"] = column_series_or_default(df, "process_cmdline", default=None).notna().astype(int)
    df["has_event_dataset"] = column_series_or_default(df, "event_dataset", default=None).notna().astype(int)

    return df

# -------------------------
# Aggregation features (per host/user/session/time-window)
# -------------------------
def aggregate_features(df, groupby_cols=["host.name"], windows=AGG_WINDOWS):
    """
    For each specified group (host.name, user, src_ip), produce aggregates per time window.
    Returns DataFrame with MultiIndex: (group_value, window_end)
    """
    # ensure sorted
    df = df.sort_values("@timestamp").reset_index(drop=True)
    aggregations = []
    groups = groupby_cols
    out_frames = []
    for g in groups:
        # set group key column exists
        if g not in df.columns:
            continue
        # group by the key and time window -> use pandas.Grouper with freq
        for w in windows:
            # set time-indexed frame
            tmp = df.set_index("@timestamp")
            # compute rolling (resample) per group by key
            # We use resample on time and groupby on group key
            grouped = tmp.groupby(g)
            records = []
            for name, group in tqdm(grouped, desc=f"agg {g} {w}", leave=False):
                # resample by window ending at label (right)
                r = group.resample(w, label="right", closed="right")
                # compute aggregates
                agg = r.agg({
                    "message_len": ["count", "mean", "max"],
                    "message_tokens": ["mean"],
                    "src_port_known": ["sum"],
                    "dst_port_known": ["sum"],
                    "has_user": ["sum"],
                })
                # flatten
                agg.columns = ["_".join(col).strip() for col in agg.columns.values]
                agg = agg.reset_index()
                agg[g] = name
                agg["window"] = w
                records.append(agg)
            if records:
                out = pd.concat(records, ignore_index=True)
                out_frames.append(out)
    if out_frames:
        return pd.concat(out_frames, ignore_index=True)
    else:
        return pd.DataFrame()

# -------------------------
# Sequence features (event-type transition counts)
# -------------------------
def sequence_features(df, event_col="event_dataset", k=2):
    """
    Create n-gram like features of event sequences per host within a sliding window.
    Produces counts of common transitions (e.g., login->exec->network)
    """
    # Build host-centric sequences ordered by timestamp
    seq_counts = {}
    df_sorted = df.sort_values("@timestamp")
    for host, group in df_sorted.groupby("host.name"):
        events = group[event_col].fillna("unknown").astype(str).tolist()
        # produce k-grams
        for i in range(len(events) - (k - 1)):
            gram = tuple(events[i:i+k])
            seq_counts[gram] = seq_counts.get(gram, 0) + 1
    # convert to df of top grams
    top = sorted(seq_counts.items(), key=lambda x: x[1], reverse=True)
    top_k = top[:500]  # limit
    seq_df = pd.DataFrame([{"gram": ".".join(k), "count": v} for k, v in top_k])
    return seq_df

# -------------------------
# Text features (TF-IDF + Hashing)
# -------------------------
def text_vectorize(df, text_col="message"):
    # TF-IDF for most common tokens (dense-ish)
    tfidf = TfidfVectorizer(max_features=TFIDF_MAX_FEATURES, ngram_range=(1,2), stop_words="english")
    tfidf_matrix = tfidf.fit_transform(df[text_col].fillna("").astype(str).values)
    # Hashing vectorizer for larger token coverage
    hv = HashingVectorizer(n_features=HASHING_FEATURES, ngram_range=(1,2), alternate_sign=False)
    hash_matrix = hv.transform(df[text_col].fillna("").astype(str).values)
    # combine as sparse horizontal stack
    text_sparse = hstack([tfidf_matrix, hash_matrix], format="csr")
    feature_names = [f"tfidf_{i}" for i in range(tfidf_matrix.shape[1])] + [f"hash_{i}" for i in range(hash_matrix.shape[1])]
    return text_sparse, feature_names, tfidf, hv

# -------------------------
# Categorical encoding & numerical scaling
# -------------------------
def encode_and_scale(df, categorical_columns=None, numeric_columns=None, sparse_text=None):
    """
    Encodes categorical columns (one-hot) and scales numeric columns.
    Returns combined sparse matrix (csr) and feature name list.
    """
    if categorical_columns is None:
        categorical_columns = ["user", "process_name", "event_dataset", "event_module", "log_level"]
    if numeric_columns is None:
        numeric_columns = ["message_len", "message_tokens", "hour_of_day", "day_of_week",
                           "src_port", "dst_port", "src_port_known", "dst_port_known", "has_user"]
    present_cat = [c for c in categorical_columns if c in df.columns]
    present_num = [c for c in numeric_columns if c in df.columns]

    # fill NaNs
    cat_data = df[present_cat].fillna("NA").astype(str) if present_cat else pd.DataFrame(index=df.index)
    num_data = df[present_num].fillna(0.0).astype(float) if present_num else pd.DataFrame(index=df.index)

    # One-hot encode categories (sparse)
    if not cat_data.empty:
        ohe = OneHotEncoder(handle_unknown="ignore")
        cat_sparse = ohe.fit_transform(cat_data)
        cat_feature_names = []
        # safe get feature names if available
        try:
            cat_feature_names = ohe.get_feature_names_out(present_cat).tolist()
        except Exception:
            cat_feature_names = [f"cat_{i}" for i in range(cat_sparse.shape[1])]
    else:
        cat_sparse = csr_matrix((df.shape[0], 0))
        cat_feature_names = []

    # scale numerics
    if not num_data.empty:
        scaler = StandardScaler()
        num_scaled = scaler.fit_transform(num_data)
        num_sparse = csr_matrix(num_scaled)
        num_feature_names = present_num
    else:
        num_sparse = csr_matrix((df.shape[0], 0))
        num_feature_names = []

    # combine all: [num | cat | text]
    parts = [num_sparse, cat_sparse]
    feature_names = num_feature_names + cat_feature_names

    if sparse_text is not None:
        parts.append(sparse_text)
    combined = hstack(parts, format="csr")
    return combined, feature_names

# -------------------------
# Main pipeline
# -------------------------
def run_pipeline(input_path, out_dir):
    print(f"[+] Loading Parquet: {input_path}")
    df = pd.read_parquet(input_path)
    print(f"[+] Rows loaded: {len(df)}")

    # 1) normalize column names and ensure timestamp
    df_norm = basic_normalize(df)
    print("[+] Basic normalization done")

    # 2) event-level derived features
    df_events = event_level_features(df_norm)
    event_out_path = os.path.join(out_dir, "event_level_features.parquet")
    df_events.to_parquet(event_out_path, index=False)
    print(f"[+] Event-level features saved -> {event_out_path}")

    # 3) text vectorization
    print("[+] Building text features (TF-IDF + Hashing)")
    text_sparse, text_feature_names, tfidf_obj, hash_obj = text_vectorize(df_events, text_col="message")
    print(f"[+] Text sparse shape: {text_sparse.shape}")

    # 4) encode & scale numeric + categorical
    print("[+] Encoding categorical columns and scaling numerics")
    combined_sparse, basic_feature_names = encode_and_scale(df_events, sparse_text=None)
    # now add text
    full_sparse = hstack([combined_sparse, text_sparse], format="csr")
    feature_names = basic_feature_names + text_feature_names
    print(f"[+] Final sparse shape: {full_sparse.shape}")

    # 5) Save ML feature matrix
    X_path = os.path.join(out_dir, "feature_matrix.npz")
    save_npz(X_path, full_sparse)
    meta_path = os.path.join(out_dir, "feature_names.txt")
    with open(meta_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(feature_names))
    print(f"[+] Feature matrix saved -> {X_path}")
    print(f"[+] Feature names saved -> {meta_path}")

    # 6) Aggregations (per-host, per-user)
    print("[+] Generating aggregation features per host and per user")
    agg_host = aggregate_features(df_events, groupby_cols=["host.name"], windows=AGG_WINDOWS)
    agg_user = aggregate_features(df_events, groupby_cols=["user"], windows=AGG_WINDOWS)
    if not agg_host.empty:
        agg_host.to_parquet(os.path.join(out_dir, "agg_host.parquet"), index=False)
    if not agg_user.empty:
        agg_user.to_parquet(os.path.join(out_dir, "agg_user.parquet"), index=False)
    print("[+] Aggregates saved")

    # 7) Sequence features
    seq_df = sequence_features(df_events, event_col="event_dataset", k=2)
    seq_out = os.path.join(out_dir, "sequence_grams.csv")
    seq_df.to_csv(seq_out, index=False)
    print("[+] Sequence n-grams saved ->", seq_out)

    print("[+] Pipeline complete. Tip: use agg_host/agg_user for sessionization and label enrichment for supervised models.")

# -------------------------
# CLI
# -------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SIEM Feature Extraction from Parquet")
    parser.add_argument("--input", "-i", required=True, help="Input Parquet file (events)")
    parser.add_argument("--out", "-o", default="features_out", help="Output directory")
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)
    run_pipeline(args.input, args.out)
