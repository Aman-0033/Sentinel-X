"""Register trained model artifact in the database model_versions table."""

import argparse
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

backend_dir = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(backend_dir))

from app.db.models.model_version import ModelVersion
from app.db.models.user import User
from app.ml.feature_engineering.features import FEATURE_NAMES
from app.ml.inference.model_loader import compute_file_sha256


def main():
    parser = argparse.ArgumentParser(description="Register model artifact in database")
    parser.add_argument("--version", type=str, default="1.0.0")
    parser.add_argument(
        "--status",
        type=str,
        default="ACTIVE",
        choices=["APPROVED", "ACTIVE", "TRAINED", "EVALUATED"],
    )
    parser.add_argument(
        "--db-url", type=str, default=None, help="Database connection URL"
    )
    args = parser.parse_args()

    ml_dir = Path(__file__).resolve().parents[1]
    artifact_name = "sentinel_xgb_v1"
    model_file = ml_dir / "artifacts" / "models" / f"{artifact_name}.joblib"

    if not model_file.exists():
        print(f"Error: Model file {model_file} not found. Run train.py first.")
        sys.exit(1)

    checksum = compute_file_sha256(model_file)

    metrics_file = ml_dir / "artifacts" / "metrics" / f"evaluation_{args.version}.json"
    metrics = {}
    if metrics_file.exists():
        with open(metrics_file, "r", encoding="utf-8") as f:
            metrics = json.load(f)

    db_url = args.db_url or os.getenv("DATABASE_URL")
    if not db_url:
        try:
            from app.core.config import get_settings

            db_url = get_settings().DATABASE_URL
        except Exception:  # noqa: BLE001
            db_url = "sqlite:///sentinel_dev.db"

    engine = create_engine(db_url)
    session_factory = sessionmaker(bind=engine)
    db = session_factory()

    try:
        # Find first admin user to assign as creator
        admin_user = (
            db.query(User).first()
            if "users" in engine.dialect.get_table_names(engine.connect())
            else None
        )
        admin_id = admin_user.id if admin_user else str(uuid.uuid4())

        # Check if already registered
        existing = (
            db.query(ModelVersion)
            .filter(
                ModelVersion.name == "SENTINEL-XGBoost",
                ModelVersion.version == args.version,
            )
            .first()
        )

        now = datetime.now(UTC)
        feature_schema = {
            "feature_names": FEATURE_NAMES,
            "feature_count": len(FEATURE_NAMES),
            "scaler": "StandardScaler",
        }

        if existing:
            existing.checksum = checksum
            existing.status = args.status
            existing.metrics = metrics
            existing.feature_schema = feature_schema
            if args.status == "ACTIVE":
                existing.activated_by = admin_id
                existing.activated_at = now
            print(
                f"Updated existing model version {existing.id} to status '{args.status}'."
            )
        else:
            model_record = ModelVersion(
                id=str(uuid.uuid4()),
                name="SENTINEL-XGBoost",
                version=args.version,
                algorithm="XGBoost + IsolationForest",
                artifact_uri="models/sentinel_xgb_v1.joblib",
                checksum=checksum,
                feature_schema=feature_schema,
                metrics=metrics,
                status=args.status,
                trained_at=now,
                created_by=admin_id,
                created_at=now,
            )
            db.add(model_record)
            print(
                f"Registered new model version {model_record.id} with status '{args.status}'."
            )

        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    main()
