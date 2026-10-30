"""Unit tests for ML feature engineering and preprocessing pipeline."""

import numpy as np
import pytest

from app.core.exceptions import AppValidationError
from app.ml.feature_engineering.features import (
    FEATURE_NAMES,
    extract_flow_features,
    flow_features_to_vector,
)
from app.ml.preprocessing.pipeline import FlowPreprocessingPipeline
from app.ml.preprocessing.validators import validate_flow_for_ml


def test_extract_flow_features_valid():
    flow = {
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.1",
        "source_port": 54321,
        "destination_port": 443,
        "protocol": "TCP",
        "packets": 50,
        "bytes": 25000,
        "duration_ms": 1000.0,
        "direction": "INBOUND",
        "failed_connection_ratio": 0.1,
        "request_frequency": 2.5,
    }

    features = extract_flow_features(flow)
    assert len(features) == len(FEATURE_NAMES)
    assert features["packet_count"] == 50.0
    assert features["byte_count"] == 25000.0
    assert features["bytes_per_packet"] == 500.0
    assert features["is_well_known_port"] == 1.0  # 443 is well-known (< 1024)
    assert features["is_ephemeral_port"] == 0.0
    assert features["protocol_tcp"] == 1.0
    assert features["protocol_udp"] == 0.0
    assert features["direction_inbound"] == 1.0
    assert features["direction_outbound"] == 0.0


def test_extract_flow_features_defaults_and_null_safety():
    # Empty flow should safely assign defaults without dividing by zero
    flow = {}
    features = extract_flow_features(flow)
    assert len(features) == len(FEATURE_NAMES)
    assert features["packet_count"] == 1.0
    assert features["byte_count"] == 0.0
    assert features["bytes_per_second"] == 0.0
    assert features["is_well_known_port"] == 0.0


def test_flow_features_to_vector():
    flow = {
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "packets": 10,
        "bytes": 1000,
        "duration_ms": 500,
    }
    feat_dict = extract_flow_features(flow)
    vec = flow_features_to_vector(feat_dict)
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (len(FEATURE_NAMES),)
    assert vec.dtype == np.float32


def test_preprocessing_pipeline_transform():
    pipeline = FlowPreprocessingPipeline()
    flows = [
        {"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "packets": 10, "bytes": 1000},
        {"source_ip": "10.0.0.3", "destination_ip": "10.0.0.4", "packets": 20, "bytes": 5000},
    ]
    mat = pipeline.transform_batch(flows)
    assert mat.shape == (2, len(FEATURE_NAMES))

    single_mat = pipeline.transform_single(flows[0])
    assert single_mat.shape == (1, len(FEATURE_NAMES))


def test_validate_flow_for_ml():
    with pytest.raises(AppValidationError):
        validate_flow_for_ml({})  # No source or destination IP

    with pytest.raises(AppValidationError):
        validate_flow_for_ml("not-a-dict")  # type: ignore

    # Valid
    validate_flow_for_ml({"source_ip": "10.0.0.1"})
