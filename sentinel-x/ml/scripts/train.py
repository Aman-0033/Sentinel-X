"""Train baseline XGBoost classifier and Isolation Forest anomaly detector.

Produces production artifacts, computes SHA-256 integrity checksums,
and outputs evaluation metrics per Section 6 and Section 41.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

# Ensure backend root is in sys.path to access feature engineering
ml_scripts_dir = Path(__file__).resolve().parent
backend_dir = ml_scripts_dir.parents[1] / "backend"
sys.path.insert(0, str(backend_dir))

from app.ml.feature_engineering.features import (
    ATTACK_CLASSES,
    FEATURE_NAMES,
    extract_flow_features,
)
from prepare_dataset import generate_synthetic_dataset


def compute_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Train baseline intrusion detection models"
    )
    parser.add_argument("--version", type=str, default="1.0.0", help="Semantic version")
    parser.add_argument(
        "--samples", type=int, default=3000, help="Training dataset samples"
    )
    args = parser.parse_args()

    ml_dir = Path(__file__).resolve().parents[1]
    data_path = ml_dir / "datasets" / "processed" / "network_flows.csv"

    if data_path.exists():
        df = pd.read_csv(data_path)
    else:
        print("Generating synthetic dataset...")
        df = generate_synthetic_dataset(num_samples=args.samples)
        data_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(data_path, index=False)

    print(f"Loaded {len(df)} telemetry samples.")

    # 1. Feature Extraction
    features_list = []
    labels = []
    class_to_idx = {name: i for i, name in enumerate(ATTACK_CLASSES)}

    for _, row in df.iterrows():
        feat_dict = extract_flow_features(row.to_dict())
        features_list.append([feat_dict[k] for k in FEATURE_NAMES])
        lbl = row.get("label", "Benign")
        labels.append(class_to_idx.get(lbl, 0))

    X = np.array(features_list, dtype=np.float32)
    y = np.array(labels, dtype=np.int32)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 2. Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 3. Train Supervised Classifier (XGBoost)
    print("Training XGBoost Classifier...")
    clf = XGBClassifier(
        n_estimators=100,
        max_depth=5,
        learning_rate=0.1,
        eval_metric="mlogloss",
        random_state=42,
    )
    clf.fit(X_train_scaled, y_train)

    y_pred = clf.predict(X_test_scaled)
    prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    print(f"Classifier Metrics: Precision={prec:.4f}, Recall={rec:.4f}, F1={f1:.4f}")
    report_dict = classification_report(
        y_test, y_pred, target_names=ATTACK_CLASSES, output_dict=True, zero_division=0
    )

    # 4. Train Anomaly Detector (Isolation Forest)
    print("Training Isolation Forest Anomaly Detector...")
    # Fit anomaly detector primarily on benign traffic
    benign_mask = y_train == class_to_idx["Benign"]
    X_benign = X_train_scaled[benign_mask]
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.08,
        random_state=42,
    )
    iso_forest.fit(X_benign)

    # 5. Save Artifacts
    models_dir = ml_dir / "artifacts" / "models"
    preprocessors_dir = ml_dir / "artifacts" / "preprocessors"
    metrics_dir = ml_dir / "artifacts" / "metrics"

    for d in [models_dir, preprocessors_dir, metrics_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # Main bundled artifact
    model_artifact_name = "sentinel_xgb_v1.joblib"
    model_path = models_dir / model_artifact_name
    payload = {
        "classifier": clf,
        "scaler": scaler,
        "anomaly_detector": iso_forest,
        "attack_classes": ATTACK_CLASSES,
        "feature_names": FEATURE_NAMES,
        "version": args.version,
    }
    joblib.dump(payload, model_path)

    # Separate anomaly detector and scaler
    iso_path = models_dir / f"isolation_forest_{args.version}.joblib"
    joblib.dump(iso_forest, iso_path)

    scaler_path = preprocessors_dir / f"scaler_{args.version}.joblib"
    joblib.dump(scaler, scaler_path)

    # Compute checksum
    checksum = compute_sha256(model_path)

    # Save metrics
    metrics_summary = {
        "model_name": "SENTINEL-XGBoost",
        "version": args.version,
        "algorithm": "XGBoost + IsolationForest",
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "checksum": checksum,
        "artifact_file": model_artifact_name,
        "classification_report": report_dict,
    }

    metrics_path = metrics_dir / f"evaluation_{args.version}.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics_summary, f, indent=2)

    print("\nTraining complete!")
    print(f"Artifact: {model_path}")
    print(f"SHA-256 Checksum: {checksum}")
    print(f"Metrics saved: {metrics_path}")


if __name__ == "__main__":
    main()
