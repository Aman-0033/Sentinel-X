"""Preprocessing pipeline for machine learning feature transformation."""

from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from app.ml.feature_engineering.features import (
    FEATURE_NAMES,
    extract_flow_features,
)
from app.ml.preprocessing.validators import validate_flow_for_ml


class FlowPreprocessingPipeline:
    """Transforms raw flow records into scaled feature matrices for model inference."""

    def __init__(self, scaler: Optional[StandardScaler] = None):
        self.scaler = scaler or StandardScaler()
        self.feature_names = FEATURE_NAMES

    def transform_single(self, flow: Dict[str, Any]) -> np.ndarray:
        """Process a single raw flow dictionary into a 2D feature matrix (1, n_features)."""
        validate_flow_for_ml(flow)
        feat_dict = extract_flow_features(flow)
        vec = np.array([[feat_dict[k] for k in self.feature_names]], dtype=np.float32)

        if hasattr(self.scaler, "mean_") and self.scaler.mean_ is not None:
            return self.scaler.transform(vec)
        return vec

    def transform_batch(self, flows: List[Dict[str, Any]]) -> np.ndarray:
        """Process a batch of flow dictionaries into a 2D feature matrix (n_samples, n_features)."""
        if not flows:
            return np.empty((0, len(self.feature_names)), dtype=np.float32)

        rows = []
        for flow in flows:
            validate_flow_for_ml(flow)
            feat_dict = extract_flow_features(flow)
            rows.append([feat_dict[k] for k in self.feature_names])

        mat = np.array(rows, dtype=np.float32)
        if hasattr(self.scaler, "mean_") and self.scaler.mean_ is not None:
            return self.scaler.transform(mat)
        return mat

    def fit_transform(self, df_or_flows: Any) -> np.ndarray:
        """Fit scaler on dataset and return transformed matrix."""
        if isinstance(df_or_flows, pd.DataFrame):
            # Ensure all columns present
            for col in self.feature_names:
                if col not in df_or_flows.columns:
                    df_or_flows[col] = 0.0
            mat = df_or_flows[self.feature_names].to_numpy(dtype=np.float32)
        elif isinstance(df_or_flows, list):
            rows = []
            for flow in df_or_flows:
                feat_dict = extract_flow_features(flow)
                rows.append([feat_dict[k] for k in self.feature_names])
            mat = np.array(rows, dtype=np.float32)
        else:
            mat = np.array(df_or_flows, dtype=np.float32)

        return self.scaler.fit_transform(mat)
