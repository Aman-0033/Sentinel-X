"""Evaluate trained model artifacts against test dataset."""

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

backend_dir = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(backend_dir))

from app.ml.feature_engineering.features import (
    ATTACK_CLASSES,
    FEATURE_NAMES,
    extract_flow_features,
)


def main():
    parser = argparse.ArgumentParser(description="Evaluate model artifact")
    parser.add_argument("--model-path", type=str, default=None)
    args = parser.parse_args()

    ml_dir = Path(__file__).resolve().parents[1]
    model_file = (
        Path(args.model_path)
        if args.model_path
        else (ml_dir / "artifacts" / "models" / "sentinel_xgb_v1.joblib")
    )

    if not model_file.exists():
        print(f"Error: Model file {model_file} does not exist.")
        sys.exit(1)

    payload = joblib.load(model_file)
    clf = payload["classifier"]
    scaler = payload["scaler"]
    attack_classes = payload.get("attack_classes", ATTACK_CLASSES)

    data_path = ml_dir / "datasets" / "processed" / "network_flows.csv"
    if not data_path.exists():
        print(f"Error: Dataset {data_path} not found.")
        sys.exit(1)

    df = pd.read_csv(data_path)
    features_list = []
    labels = []
    class_to_idx = {name: i for i, name in enumerate(attack_classes)}

    for _, row in df.iterrows():
        feat_dict = extract_flow_features(row.to_dict())
        features_list.append([feat_dict[k] for k in FEATURE_NAMES])
        lbl = row.get("label", "Benign")
        labels.append(class_to_idx.get(lbl, 0))

    X = np.array(features_list, dtype=np.float32)
    y = np.array(labels, dtype=np.int32)
    X_scaled = scaler.transform(X)

    y_pred = clf.predict(X_scaled)

    print("\n--- Model Evaluation Summary ---")
    print(
        classification_report(y, y_pred, target_names=attack_classes, zero_division=0)
    )
    print("\nConfusion Matrix:")
    print(confusion_matrix(y, y_pred))


if __name__ == "__main__":
    main()
