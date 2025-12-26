# compute_thresholds.py
import os
import glob
import joblib
import numpy as np
import json
import argparse
from tqdm import tqdm

def score_in_batches(npy_path, model_wrapper, batch_size=200_000):
    """
    Yield decision_function scores for the full dataset without loading all into memory.
    model_wrapper: dict-like with keys "model" and "scaler"
    """
    size = os.path.getsize(npy_path)
    # use mmap_mode to avoid loading entire file
    arr = np.load(npy_path, mmap_mode='r')
    n = arr.shape[0]
    scores = []
    for start in tqdm(range(0, n, batch_size), desc=f"Scoring {os.path.basename(npy_path)}"):
        end = min(n, start + batch_size)
        Xbatch = arr[start:end].astype(np.float32)
        Xs = model_wrapper["scaler"].transform(Xbatch)
        s = model_wrapper["model"].decision_function(Xs)
        scores.append(s)
    if scores:
        return np.concatenate(scores, axis=0)
    return np.array([])

def compute_thresholds(models_dir, data_dir, out_file="thresholds.json", percentiles=[0.1,0.5,1,2,5], batch_size=200_000):
    models = sorted(glob.glob(os.path.join(models_dir, "*_iforest.pkl")))
    results = {}
    for mfile in models:
        base = os.path.basename(mfile).rsplit("_iforest.pkl",1)[0]
        datafile = os.path.join(data_dir, f"{base}.npy")
        if not os.path.exists(datafile):
            print(f"[!] Missing data file for model {base} -> expected {datafile}, skipping")
            continue
        print(f"[+] Loading model {mfile}")
        saved = joblib.load(mfile)
        scores = score_in_batches(datafile, saved, batch_size=batch_size)
        if scores.size == 0:
            print(f"[!] No scores computed for {base}, skipping")
            continue
        pct_values = {str(p): float(np.percentile(scores, p)) for p in percentiles}
        stats = {
            "n_rows": int(scores.shape[0]),
            "min": float(scores.min()),
            "max": float(scores.max()),
            "mean": float(scores.mean()),
            "std": float(scores.std()),
            "percentiles": pct_values
        }
        results[base] = stats
        print(f"  -> computed percentiles for {base}: {pct_values}")
    # save JSON
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[✔] thresholds saved -> {out_file}")
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--models_dir", "-m", default="models_per_dataset", help="Folder with model .pkl files")
    parser.add_argument("--data_dir", "-d", default="normalized_chunks", help="Folder with corresponding .npy data files")
    parser.add_argument("--out", "-o", default="thresholds.json")
    parser.add_argument("--batch", type=int, default=200000, help="Batch size for scoring")
    args = parser.parse_args()
    compute_thresholds(args.models_dir, args.data_dir, args.out, batch_size=args.batch)
