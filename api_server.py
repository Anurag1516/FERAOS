from fastapi import FastAPI, UploadFile, File, HTTPException
import numpy as np
import json
from inference_engine import load_models
from treshold_engine import AdaptiveThreshold  # Fixed typo in filename if necessary

app = FastAPI()

# 1. Load Models
models = load_models()

# 2. Load Thresholds (Bootstrap)
try:
    with open("thresholds.json", "r") as f:
        static_thresholds = json.load(f)
except FileNotFoundError:
    static_thresholds = {}

# 3. Initialize Adaptive Engines
threshold_engines = {}
for name in models.keys():
    # Map dataset names to json keys if they differ, or match strict
    key = f"{name}_train_normalized"
    stats = static_thresholds.get(key)
    # Sensitivity 3.5 is roughly top 0.1% (Very Anomalous)
    threshold_engines[name] = AdaptiveThreshold(name, initial_stats=stats, sensitivity=3.5)

@app.post("/predict")
async def predict(dataset: str, features: UploadFile = File(...)):
    if dataset not in models:
        raise HTTPException(status_code=404, detail="Dataset not found")

    # --- START: MISSING DATA PARSING LOGIC ---
    try:
        content_bytes = await features.read()
        raw_data = json.loads(content_bytes)

        # Unwrap "features" key if present (Fixes the 400 Error)
        if isinstance(raw_data, dict) and "features" in raw_data:
            data_list = raw_data["features"]
        else:
            data_list = raw_data

        # Convert to NumPy
        # Handle list of dicts -> list of lists conversion if necessary
        if isinstance(data_list, list) and len(data_list) > 0 and isinstance(data_list[0], dict):
            X_input = [list(d.values()) for d in data_list]
        else:
            X_input = data_list

        # DEFINING X HERE
        X = np.array(X_input, dtype=float)

        # Ensure 2D array (n_samples, n_features)
        if X.ndim == 1:
            X = X.reshape(1, -1)

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file format")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not convert data to float array: {str(e)}")
    # --- END: MISSING DATA PARSING LOGIC ---

    # 1. Inference
    try:
        model_wrapper = models[dataset]
        Xs = model_wrapper.scaler.transform(X)
        raw_scores = model_wrapper.model.decision_function(Xs) # Returns negative for anomaly
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Feature mismatch: {str(e)}")

    # 2. Update Threshold Engine (Learn from this batch)
    # We update with raw scores; the engine handles the statistics
    threshold_engines[dataset].update(raw_scores)

    # 3. Dynamic Check
    results = []
    for score in raw_scores:
        # Check anomaly using the sliding window stats
        is_anom, z_score = threshold_engines[dataset].check_anomaly(score)

        results.append({
            "dataset": dataset,
            "score": float(score),           # Original raw score
            "risk_z_score": float(z_score),  # Standard deviations from median
            "is_anomaly": bool(is_anom),
            "threshold_model": "adaptive_mad"
        })

    return results
