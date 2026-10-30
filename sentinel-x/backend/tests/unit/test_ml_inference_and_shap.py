"""Unit tests for ML ThreatPredictor and SHAP explainability (Section 7 and Section 41)."""

from pathlib import Path

import pytest

from app.ml.explainability.explainer import ModelExplainer
from app.ml.feature_engineering.features import ATTACK_CLASSES, FEATURE_NAMES
from app.ml.inference.predictor import ThreatPredictionResult, ThreatPredictor


@pytest.fixture
def baseline_bundle():
    """Load baseline trained model bundle from repository artifacts."""
    artifacts_dir = Path(__file__).resolve().parents[3] / "ml" / "artifacts"
    model_file = artifacts_dir / "models" / "sentinel_xgb_v1.joblib"
    if not model_file.exists():
        pytest.skip("Baseline model artifact not yet generated on disk.")

    import joblib

    from app.ml.inference.model_loader import LoadedModelBundle, compute_file_sha256
    from app.ml.preprocessing.pipeline import FlowPreprocessingPipeline

    payload = joblib.load(model_file)
    clf = payload["classifier"]
    scaler = payload.get("scaler")
    ad = payload.get("anomaly_detector")
    checksum = compute_file_sha256(model_file)

    pipeline = FlowPreprocessingPipeline(scaler=scaler)
    explainer = ModelExplainer(clf, feature_names=FEATURE_NAMES)

    return LoadedModelBundle(
        model_version_id="00000000-0000-0000-0000-000000000001",
        name="SENTINEL-XGBoost",
        version="1.0.0",
        algorithm="XGBoost + IsolationForest",
        classifier=clf,
        anomaly_detector=ad,
        pipeline=pipeline,
        explainer=explainer,
        attack_classes=payload.get("attack_classes", ATTACK_CLASSES),
        feature_names=FEATURE_NAMES,
        checksum=checksum,
    )


def test_threat_predictor_benign_flow(baseline_bundle):
    predictor = ThreatPredictor(baseline_bundle)

    flow = {
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.1",
        "source_port": 50123,
        "destination_port": 443,
        "protocol": "TCP",
        "packets": 15,
        "bytes": 2000,
        "duration_ms": 120.0,
        "direction": "INBOUND",
        "failed_connection_ratio": 0.0,
        "request_frequency": 1.0,
    }

    result = predictor.predict_flow(flow)
    assert isinstance(result, ThreatPredictionResult)
    assert result.attack_type in ATTACK_CLASSES
    assert 0.0 <= result.confidence <= 1.0
    assert isinstance(result.explanation, dict)
    assert "important_factors" in result.explanation
    assert len(result.explanation["important_factors"]) > 0


def test_threat_predictor_ddos_flow(baseline_bundle):
    predictor = ThreatPredictor(baseline_bundle)

    flow = {
        "source_ip": "203.0.113.88",
        "destination_ip": "10.0.0.1",
        "source_port": 45123,
        "destination_port": 80,
        "protocol": "TCP",
        "packets": 5000,
        "bytes": 3500000,
        "duration_ms": 200.0,
        "direction": "INBOUND",
        "failed_connection_ratio": 0.95,
        "request_frequency": 500.0,
    }

    result = predictor.predict_flow(flow)
    assert result.attack_type in ["DDoS", "Brute Force", "Port Scan"]
    assert result.confidence >= 0.80

    # Verify SHAP factors structure
    factors = result.explanation["important_factors"]
    assert all("feature" in f and "importance" in f and "direction" in f for f in factors)
    assert any(
        f["feature"] in ["request_frequency", "packet_count", "bytes_per_second"] for f in factors
    )


def test_threat_predictor_batch(baseline_bundle):
    predictor = ThreatPredictor(baseline_bundle)
    flows = [
        {"source_ip": "192.168.1.1", "destination_ip": "10.0.0.1", "packets": 10, "bytes": 500},
        {"source_ip": "192.168.1.2", "destination_ip": "10.0.0.1", "packets": 20, "bytes": 1000},
    ]
    results = predictor.predict_flow_batch(flows)
    assert len(results) == 2
    assert all(isinstance(r, ThreatPredictionResult) for r in results)
