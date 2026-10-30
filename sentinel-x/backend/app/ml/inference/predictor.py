"""Production ML predictor for threat classification and anomaly detection."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import numpy as np

from app.ml.feature_engineering.features import ATTACK_CLASSES
from app.ml.inference.model_loader import LoadedModelBundle


@dataclass
class ThreatPredictionResult:
    """Structured inference output from classifier and anomaly detector."""

    attack_type: str
    confidence: float
    is_anomaly: bool
    anomaly_score: Optional[float]
    explanation: Dict[str, Any]
    model_version_id: str


class ThreatPredictor:
    """Executes high-performance threat classification, anomaly detection, and XAI."""

    def __init__(self, bundle: LoadedModelBundle):
        self.bundle = bundle

    def predict_flow(self, flow: Dict[str, Any]) -> ThreatPredictionResult:
        """Run ML inference on a single raw network flow dictionary."""
        # 1. Feature extraction & scaling
        X = self.bundle.pipeline.transform_single(flow)

        # 2. Classifier Prediction
        classifier = self.bundle.classifier
        attack_classes = self.bundle.attack_classes or ATTACK_CLASSES

        if hasattr(classifier, "predict_proba"):
            probs = classifier.predict_proba(X)[0]
            pred_idx = int(np.argmax(probs))
            confidence = float(probs[pred_idx])
            attack_type = (
                attack_classes[pred_idx] if pred_idx < len(attack_classes) else "Unknown Threat"
            )
        else:
            pred = classifier.predict(X)[0]
            confidence = 0.90
            if isinstance(pred, (int, np.integer)):
                attack_type = (
                    attack_classes[pred] if pred < len(attack_classes) else f"Attack-{pred}"
                )
            else:
                attack_type = str(pred)

        # 3. Anomaly Detection
        is_anomaly = False
        anomaly_score: Optional[float] = None

        if self.bundle.anomaly_detector is not None:
            try:
                ad = self.bundle.anomaly_detector
                # Isolation Forest: -1 = anomaly, 1 = normal
                raw_pred = ad.predict(X)[0]
                is_anomaly = raw_pred == -1

                if hasattr(ad, "decision_function"):
                    # Lower score = more anomalous
                    raw_score = float(ad.decision_function(X)[0])
                    # Invert so higher score represents higher anomaly degree (0.0 to 1.0 approx)
                    anomaly_score = round(max(0.0, min(1.0, 0.5 - raw_score)), 4)
                else:
                    anomaly_score = 0.85 if is_anomaly else 0.15
            except Exception:
                is_anomaly = False
                anomaly_score = None

        # 4. Explainability (SHAP)
        explanation = self.bundle.explainer.explain_instance(X[0], attack_type)

        return ThreatPredictionResult(
            attack_type=attack_type,
            confidence=round(confidence, 4),
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            explanation=explanation,
            model_version_id=self.bundle.model_version_id,
        )

    def predict_flow_batch(self, flows: List[Dict[str, Any]]) -> List[ThreatPredictionResult]:
        """Run inference across a batch of flow records."""
        if not flows:
            return []
        return [self.predict_flow(f) for f in flows]
