"""Unit tests for ML model loading and artifact integrity verification (Section 41)."""

import uuid
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pytest
from sklearn.ensemble import RandomForestClassifier
from sqlalchemy.orm import Session

from app.core.exceptions import AppValidationError
from app.db.models.model_version import ModelVersion
from app.db.models.role import Role
from app.db.models.user import User
from app.ml.feature_engineering.features import ATTACK_CLASSES, FEATURE_NAMES
from app.ml.inference.model_loader import (
    LoadedModelBundle,
    ModelLoader,
    compute_file_sha256,
)


@pytest.fixture
def mock_model_artifact(tmp_path: Path):
    """Create a temporary valid model artifact bundle."""
    models_dir = tmp_path / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    rf = RandomForestClassifier(n_estimators=5, random_state=42)
    # Fit dummy data
    X = [[1.0] * len(FEATURE_NAMES)] * 10
    y = [0] * 10
    rf.fit(X, y)

    payload = {
        "classifier": rf,
        "scaler": None,
        "anomaly_detector": None,
        "attack_classes": ATTACK_CLASSES,
        "feature_names": FEATURE_NAMES,
    }

    artifact_path = models_dir / "test_model_v1.joblib"
    joblib.dump(payload, artifact_path)
    checksum = compute_file_sha256(artifact_path)
    return artifact_path, checksum, models_dir


def test_model_loader_verifies_checksum_and_loads(db_session: Session, mock_model_artifact):
    artifact_path, checksum, models_dir = mock_model_artifact
    ModelLoader.clear_cache()

    # Create dummy admin user for foreign key
    role = db_session.query(Role).first()
    if not role:
        role = Role(id=str(uuid.uuid4()), name="ADMIN")
        db_session.add(role)
        db_session.commit()

    admin = db_session.query(User).first()
    if not admin:
        admin = User(
            id=str(uuid.uuid4()),
            role_id=role.id,
            email=f"loader.admin.{uuid.uuid4().hex[:6]}@sentinel.internal",
            password_hash="argon2id$mock",
            full_name="Loader Admin",
        )
        db_session.add(admin)
        db_session.commit()

    # Create active model version record
    now = datetime.now(timezone.utc)
    mv = ModelVersion(
        id=str(uuid.uuid4()),
        name="Test Intrusions Model",
        version="1.0.0",
        algorithm="RandomForest",
        artifact_uri="test_model_v1.joblib",
        feature_schema={"features": FEATURE_NAMES},
        metrics={"f1": 1.0},
        checksum=checksum,
        status="ACTIVE",
        trained_at=now,
        created_by=admin.id,
        created_at=now,
    )
    db_session.add(mv)
    db_session.commit()

    # Load active model
    bundle = ModelLoader.load_active_model(
        db_session,
        artifacts_dir=models_dir.parent,
        force_reload=True,
    )

    assert isinstance(bundle, LoadedModelBundle)
    assert bundle.version == "1.0.0"
    assert bundle.checksum == checksum
    assert bundle.classifier is not None


def test_model_loader_rejects_corrupted_checksum(db_session: Session, mock_model_artifact):
    artifact_path, checksum, models_dir = mock_model_artifact
    ModelLoader.clear_cache()

    admin = db_session.query(User).first()
    now = datetime.now(timezone.utc)

    # Deactivate existing active models
    db_session.query(ModelVersion).filter(ModelVersion.status == "ACTIVE").update(
        {"status": "RETIRED"}
    )

    # Create active model version with mismatched corrupted checksum
    mv = ModelVersion(
        id=str(uuid.uuid4()),
        name="Tampered Model",
        version="2.0.0",
        algorithm="RandomForest",
        artifact_uri="test_model_v1.joblib",
        feature_schema={"features": FEATURE_NAMES},
        metrics={"f1": 1.0},
        checksum="0000000000000000000000000000000000000000000000000000000000000000",  # Fraudulent
        status="ACTIVE",
        trained_at=now,
        created_by=admin.id,
        created_at=now,
    )
    db_session.add(mv)
    db_session.commit()

    with pytest.raises(AppValidationError) as exc_info:
        ModelLoader.load_active_model(
            db_session,
            artifacts_dir=models_dir.parent,
            force_reload=True,
        )

    assert "checksum failure" in str(exc_info.value).lower()
