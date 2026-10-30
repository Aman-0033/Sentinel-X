"""Detection analysis application service.

Coordinates ML inference, XAI explanation, deterministic risk scoring,
database persistence, and automated incident correlation.
"""

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from app.core.exceptions import AppValidationError, NotFoundError
from app.db.models.detection import Detection
from app.ml.inference.model_loader import ModelLoader
from app.ml.inference.predictor import ThreatPredictor
from app.repositories.detections import DetectionRepository
from app.repositories.flows import FlowRepository
from app.services.incident_service import IncidentService
from app.services.risk_service import calculate_risk_score


class DetectionService:
    """Service for running intrusion detection on network flows."""

    def __init__(self, db: Session):
        self.db = db
        self.det_repo = DetectionRepository(db)
        self.flow_repo = FlowRepository(db)
        self.incident_service = IncidentService(db)

    def analyze_flow(
        self,
        flow_id: str,
        threat_intel_score: Optional[float] = None,
        system_user_id: Optional[str] = None,
    ) -> Detection:
        """Run ML analysis on an ingested network flow and record detection."""
        flow = self.flow_repo.get_by_id(flow_id)
        if not flow:
            raise NotFoundError(f"Network flow '{flow_id}' not found.")

        # 1. Load active model bundle
        bundle = ModelLoader.load_active_model(self.db)
        if not bundle:
            raise AppValidationError("No active machine learning model found in registry.")

        predictor = ThreatPredictor(bundle)

        # 2. Extract flow dictionary
        flow_dict = {
            "source_ip": flow.source_ip,
            "destination_ip": flow.destination_ip,
            "source_port": flow.source_port,
            "destination_port": flow.destination_port,
            "protocol": flow.protocol,
            "packets": flow.packets,
            "bytes": flow.bytes,
            "duration_ms": flow.duration_ms,
            "direction": flow.direction,
        }

        # 3. Predict threat and anomaly
        pred_res = predictor.predict_flow(flow_dict)

        # 4. Deterministic Risk Evaluation (Section 42)
        risk_res = calculate_risk_score(
            attack_type=pred_res.attack_type,
            confidence=pred_res.confidence,
            is_anomaly=pred_res.is_anomaly,
            anomaly_score=pred_res.anomaly_score,
            threat_intel_score=threat_intel_score,
        )

        now = datetime.now(timezone.utc)

        # 5. Persist detection record
        detection = self.det_repo.create(
            flow_id=flow.id,
            model_version_id=pred_res.model_version_id,
            attack_type=pred_res.attack_type,
            confidence=pred_res.confidence,
            anomaly_score=pred_res.anomaly_score,
            risk_score=risk_res.risk_score,
            severity=risk_res.severity,
            is_anomaly=pred_res.is_anomaly,
            explanation=pred_res.explanation,
            detected_at=now,
        )
        self.db.commit()
        self.db.refresh(detection)

        # 6. Automated Incident Correlation (Section 43)
        self.incident_service.correlate_detection(
            detection=detection,
            flow=flow,
            system_user_id=system_user_id,
        )

        return detection

    def analyze_flow_batch(
        self,
        flow_ids: List[str],
        system_user_id: Optional[str] = None,
    ) -> List[Detection]:
        """Analyze a list of network flows in sequence."""
        detections = []
        for fid in flow_ids:
            try:
                det = self.analyze_flow(fid, system_user_id=system_user_id)
                detections.append(det)
            except Exception:
                # Log or skip individual flow errors to prevent batch failure
                pass
        return detections
