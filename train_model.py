"""
Train Isolation Forest on historical "normal" interface samples.
กรองค่าขยะจาก GNS3 ออกก่อนเทรน เพื่อให้ AI เรียนรู้ baseline ที่ถูกต้อง
"""
import os
import sys
import warnings

import joblib
import numpy as np
import pandas as pd
import yaml
from dotenv import load_dotenv
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sqlalchemy import create_engine

warnings.filterwarnings("ignore")

load_dotenv()

print("Loading config and database...")
with open("config/config.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

model_cfg = config.get("model", {})
DB_URL = os.getenv("DB_URL", config.get("database", {}).get("url", ""))
engine = create_engine(DB_URL)

test_size = float(model_cfg.get("train_validation_fraction", 0.2))
test_size = min(max(test_size, 0.05), 0.5)
random_state = int(model_cfg.get("random_state", 42))
contamination = float(model_cfg.get("contamination", 0.05))
contamination = min(max(contamination, 0.001), 0.5)

# ── Features ที่ AI จะเรียนรู้ ──────────────────────────────────────────────
FEATURES = ["reliability", "network_load", "rxload", "input_errors"]

print("Querying normal traffic from database...")
df = pd.read_sql(
    """
    SELECT reliability, network_load, rxload, input_errors
    FROM interface_logs
    WHERE status = 'up' AND protocol = 'up'
      AND label = 'normal'
      AND interface_name != 'ALL'
    """,
    engine,
)

if len(df) == 0:
    print("Error: No normal traffic data found for training.", file=sys.stderr)
    sys.exit(1)

# ── กรองค่าขยะจาก GNS3 ────────────────────────────────────────────────────
# ค่าที่ผิดปกติชัดเจน: rxload/txload > 255 หรือ reliability = 0 ทั้งที่ up
before = len(df)
df = df[
    (df["reliability"] > 0) &
    (df["reliability"] <= 255) &
    (df["network_load"] >= 0) &
    (df["network_load"] <= 255) &
    (df["rxload"] >= 0) &
    (df["rxload"] <= 255)
]
after = len(df)
if before != after:
    print(f"Filtered out {before - after} junk rows (GNS3 garbage values)")

if len(df) < 10:
    print(f"Error: Only {len(df)} clean rows after filtering. Need more data.", file=sys.stderr)
    sys.exit(1)

X = df[FEATURES]

print(f"\n── Data Summary ──")
print(f"  Total clean rows : {len(X)}")
print(f"  Features         : {FEATURES}")
print(f"  Contamination    : {contamination}")
print(f"\n  Feature stats:")
print(X.describe().round(2).to_string())

X_train, X_val = train_test_split(
    X, test_size=test_size, random_state=random_state, shuffle=True
)

print(f"\n  Training rows    : {len(X_train)}")
print(f"  Validation rows  : {len(X_val)}")

print("\nTraining Isolation Forest...")
model = IsolationForest(
    n_estimators=200,       # เพิ่มจาก 100 → 200 ให้แม่นขึ้น
    contamination=contamination,
    random_state=random_state,
    max_features=1.0,
    bootstrap=True,
)
model.fit(X_train)

# ── Validation ──────────────────────────────────────────────────────────────
if len(X_val) > 0:
    val_pred = model.predict(X_val)
    val_scores = model.decision_function(X_val)
    outlier_rate = (val_pred == -1).mean() * 100
    print(f"\n── Validation Results ──")
    print(f"  Outlier rate     : {outlier_rate:.2f}%")
    print(f"  Score range      : [{val_scores.min():.4f}, {val_scores.max():.4f}]")
    print(f"  Score mean       : {val_scores.mean():.4f}")

print("\nTraining complete.")

out_path = model_cfg["path"]
parent = os.path.dirname(out_path)
if parent:
    os.makedirs(parent, exist_ok=True)
joblib.dump(model, out_path)
print(f"\nModel saved to {out_path}")
