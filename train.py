import os
import joblib
import scipy.sparse
from sklearn.ensemble import IsolationForest

# --- CONFIGURATION ---
MATRIX_PATH = "feature_matrix.npz"
MODEL_DIR = "./"
CONTAMINATION = 0.01  # 1% of data is expected to be anomalous
# ---------------------

print(f"[+] Loading feature matrix from: {MATRIX_PATH}")
if not os.path.exists(MATRIX_PATH):
    raise FileNotFoundError("Run 1_extract.py first!")

X = scipy.sparse.load_npz(MATRIX_PATH)
print(f"[+] Training on {X.shape[0]} events...")

# Train Model
# n_jobs=-1 uses all available CPU cores
model = IsolationForest(
    n_estimators=300,
    max_samples='auto',
    contamination=CONTAMINATION,
    random_state=42,
    n_jobs=-1,
    verbose=1
)

model.fit(X)

# Save Model
save_path = os.path.join(MODEL_DIR, "siem_model.pkl")
joblib.dump({"model": model}, save_path)

print(f"\n[✔] Model trained and saved to: {save_path}")
