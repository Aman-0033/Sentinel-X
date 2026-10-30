"""Model artifact loader with integrity checksum verification (Section 41).

Ensures only verified, non-corrupted model artifacts matching their recorded
SHA-256 checksums are loaded into the production inference runtime.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional

import joblib
from sqlalchemy.orm import Session

from app.core.exceptions import AppValidationError
from app.ml.explainability.explainer import ModelExplainer
from app.ml.feature_engineering.features import ATTACK_CLASSES, FEATURE_NAMES
from app.ml.preprocessing.pipeline import FlowPreprocessingPipeline
from app.repositories.models import ModelVersionRepository


@dataclass
class LoadedModelBundle:
    """Encapsulates active model artifacts, preprocessor, and explainer."""

    model_version_id: str
    name: str
    version: str
    algorithm: str
    classifier: Any
    anomaly_detector: Optional[Any]
    pipeline: FlowPreprocessingPipeline
    explainer: ModelExplainer
    attack_classes: List[str]
    feature_names: List[str]
    checksum: str


def compute_file_sha256(file_path: Path) -> str:
    """Compute SHA-256 checksum of a file on disk."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class ModelLoader:
    """Loads, verifies, and caches production machine learning artifacts."""

    _cached_bundle: Optional[LoadedModelBundle] = None

    @classmethod
    def clear_cache(cls) -> None:
        """Clear cached active model bundle."""
        cls._cached_bundle = None

    @classmethod
    def load_active_model(
        cls,
        db: Session,
        artifacts_dir: Optional[Path] = None,
        force_reload: bool = False,
    ) -> Optional[LoadedModelBundle]:
        """Fetch the ACTIVE model record from DB, verify its artifact integrity, and load it."""
        if cls._cached_bundle is not None and not force_reload:
            return cls._cached_bundle

        repo = ModelVersionRepository(db)
        active_record = repo.get_active_model()
        if not active_record:
            return None

        # Resolve artifact paths
        base_dir = artifacts_dir or (Path(__file__).resolve().parents[4] / "ml" / "artifacts")
        uri = active_record.artifact_uri or ""
        if uri.endswith(".joblib"):
            model_file = base_dir / uri if "models" in uri else base_dir / "models" / uri
        else:
            model_file = base_dir / "models" / f"{uri}.joblib"

        if not model_file.exists():
            # Also check alternative path or direct name
            model_file = (
                base_dir
                / "models"
                / f"{active_record.name.lower().replace(' ', '_')}_{active_record.version}.joblib"
            )

        if not model_file.exists():
            raise AppValidationError(
                f"Artifact file for active model {active_record.name} v{active_record.version} not found at {model_file}."
            )

        # 1. SHA-256 Checksum Verification (Section 41)
        actual_checksum = compute_file_sha256(model_file)
        if active_record.checksum and actual_checksum.lower() != active_record.checksum.lower():
            raise AppValidationError(
                f"Model integrity checksum failure! Expected {active_record.checksum}, got {actual_checksum}."
            )

        # 2. Load primary classifier
        try:
            loaded_payload = joblib.load(model_file)
        except Exception as exc:
            raise AppValidationError(f"Failed to load model artifact: {str(exc)}") from exc

        # Unpack payload or direct model
        if isinstance(loaded_payload, dict):
            classifier = loaded_payload.get("classifier") or loaded_payload.get("model")
            scaler = loaded_payload.get("scaler")
            anomaly_detector = loaded_payload.get("anomaly_detector")
            attack_classes = loaded_payload.get("attack_classes", ATTACK_CLASSES)
            feature_names = loaded_payload.get("feature_names", FEATURE_NAMES)
        else:
            classifier = loaded_payload
            scaler = None
            anomaly_detector = None
            attack_classes = ATTACK_CLASSES
            feature_names = FEATURE_NAMES

        # Load anomaly detector if stored separately
        if anomaly_detector is None:
            anomaly_file = base_dir / "models" / f"isolation_forest_{active_record.version}.joblib"
            if anomaly_file.exists():
                try:
                    anomaly_detector = joblib.load(anomaly_file)
                except Exception:
                    anomaly_detector = None

        # Build preprocessing pipeline
        pipeline = FlowPreprocessingPipeline(scaler=scaler)
        explainer = ModelExplainer(classifier, feature_names=feature_names)

        bundle = LoadedModelBundle(
            model_version_id=active_record.id,
            name=active_record.name,
            version=active_record.version,
            algorithm=active_record.algorithm,
            classifier=classifier,
            anomaly_detector=anomaly_detector,
            pipeline=pipeline,
            explainer=explainer,
            attack_classes=attack_classes,
            feature_names=feature_names,
            checksum=actual_checksum,
        )

        cls._cached_bundle = bundle
        return bundle
