"""Explainable AI (XAI) layer using SHAP (SHapley Additive exPlanations).

Provides model-agnostic and tree-based local explanation summaries for
network threat detections, serializing top contributing factors into
structured JSONB format.
"""

from typing import Any, Dict, List, Optional

import numpy as np

try:
    import shap

    SHAP_AVAILABLE = True
except ImportError:
    shap = None
    SHAP_AVAILABLE = False

from app.ml.feature_engineering.features import FEATURE_NAMES


class ModelExplainer:
    """Computes SHAP explanations and generates structured JSONB factors for detections."""

    def __init__(self, model: Any, feature_names: Optional[List[str]] = None):
        self.model = model
        self.feature_names = feature_names or FEATURE_NAMES
        self._tree_explainer: Optional[Any] = None

        if SHAP_AVAILABLE and model is not None:
            try:
                # TreeExplainer is optimized for tree-based models like XGBoost & Random Forest
                self._tree_explainer = shap.TreeExplainer(model)
            except Exception:
                self._tree_explainer = None

    def explain_instance(
        self,
        feature_vector: np.ndarray,
        predicted_class: str,
        top_k: int = 4,
    ) -> Dict[str, Any]:
        """Compute local explanation factors for a single feature vector (1, n_features).

        Returns structured JSONB-ready explanation data per Section 7.
        """
        # Ensure 2D shape (1, n_features)
        if feature_vector.ndim == 1:
            vec_2d = feature_vector.reshape(1, -1)
        else:
            vec_2d = feature_vector

        factors: List[Dict[str, Any]] = []
        base_value: float = 0.0
        method: str = "Heuristic-Attribution"

        # Attempt SHAP computation if available
        if self._tree_explainer is not None:
            try:
                shap_values = self._tree_explainer.shap_values(vec_2d)
                method = "SHAP-TreeExplainer"

                # Handle multi-class vs binary shapes
                # shap_values could be list of arrays (one per class) or 3D array (samples, features, classes)
                if isinstance(shap_values, list):
                    vals = np.array(shap_values[0][0])
                elif shap_values.ndim == 3:
                    # Shape: (samples, features, classes) -> take first sample, first or max class
                    vals = shap_values[0, :, 0]
                elif shap_values.ndim == 2:
                    vals = shap_values[0]
                else:
                    vals = np.array(shap_values).flatten()

                raw_base = getattr(self._tree_explainer, "expected_value", 0.0)
                if isinstance(raw_base, (list, np.ndarray)):
                    base_value = float(raw_base[0]) if len(raw_base) > 0 else 0.0
                else:
                    base_value = float(raw_base)

                # Pair feature name, raw value, and shap value
                indexed_impacts = []
                for i, name in enumerate(self.feature_names):
                    if i < len(vals) and i < vec_2d.shape[1]:
                        imp = float(vals[i])
                        raw_v = float(vec_2d[0, i])
                        indexed_impacts.append((name, raw_v, imp, abs(imp)))

                # Sort by absolute SHAP impact descending
                indexed_impacts.sort(key=lambda x: x[3], reverse=True)

                for name, raw_v, imp, _ in indexed_impacts[:top_k]:
                    factors.append(
                        {
                            "feature": name,
                            "value": round(raw_v, 4),
                            "importance": round(imp, 4),
                            "direction": "positive" if imp >= 0 else "negative",
                        }
                    )
            except Exception:
                factors = []

        # Graceful fallback attribution if SHAP failed or was unavailable
        if not factors:
            method = "Normalized-Magnitude-Fallback"
            indexed_mags = []
            for i, name in enumerate(self.feature_names):
                if i < vec_2d.shape[1]:
                    v = float(vec_2d[0, i])
                    indexed_mags.append((name, v, abs(v)))

            indexed_mags.sort(key=lambda x: x[2], reverse=True)
            for name, val, mag in indexed_mags[:top_k]:
                factors.append(
                    {
                        "feature": name,
                        "value": round(val, 4),
                        "importance": round(mag / max(sum(m[2] for m in indexed_mags), 1.0), 4),
                        "direction": "positive" if val >= 0 else "negative",
                    }
                )

        factor_names = [f["feature"] for f in factors]
        summary = (
            f"Key telemetry indicators ({', '.join(factor_names)}) "
            f"strongly influenced the classification toward '{predicted_class}'."
        )

        return {
            "prediction": predicted_class,
            "method": method,
            "base_value": round(base_value, 4),
            "important_factors": factors,
            "summary": summary,
        }
