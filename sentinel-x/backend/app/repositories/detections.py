"""Detection and Analyst Feedback Repository.

Data access layer for detection classifications and ground-truth feedback.
"""

from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session

from app.db.models.analyst_feedback import AnalystFeedback
from app.db.models.detection import Detection


class DetectionRepository:
    """Repository handling database operations for Detections and AnalystFeedback."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, detection_id: str) -> Optional[Detection]:
        """Fetch detection by primary key ID."""
        return self.db.query(Detection).filter(Detection.id == detection_id).first()

    def create(self, **kwargs) -> Detection:
        """Create and persist a detection event."""
        detection = Detection(**kwargs)
        self.db.add(detection)
        self.db.commit()
        self.db.refresh(detection)
        return detection

    def list_detections(
        self,
        skip: int = 0,
        limit: int = 50,
        severity: Optional[str] = None,
        attack_type: Optional[str] = None,
        is_anomaly: Optional[bool] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Detection]:
        """List detections with filtering and pagination."""
        query = self.db.query(Detection)
        if severity:
            query = query.filter(Detection.severity == severity.upper())
        if attack_type:
            query = query.filter(Detection.attack_type == attack_type)
        if is_anomaly is not None:
            query = query.filter(Detection.is_anomaly == is_anomaly)
        if start_time:
            query = query.filter(Detection.detected_at >= start_time)
        if end_time:
            query = query.filter(Detection.detected_at <= end_time)
        return query.order_by(Detection.detected_at.desc()).offset(skip).limit(limit).all()

    def count_detections(
        self,
        severity: Optional[str] = None,
        attack_type: Optional[str] = None,
        is_anomaly: Optional[bool] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> int:
        """Count total matching detections."""
        query = self.db.query(Detection)
        if severity:
            query = query.filter(Detection.severity == severity.upper())
        if attack_type:
            query = query.filter(Detection.attack_type == attack_type)
        if is_anomaly is not None:
            query = query.filter(Detection.is_anomaly == is_anomaly)
        if start_time:
            query = query.filter(Detection.detected_at >= start_time)
        if end_time:
            query = query.filter(Detection.detected_at <= end_time)
        return query.count()

    def add_feedback(
        self, detection_id: str, analyst_id: str, verdict: str, comment: Optional[str] = None
    ) -> AnalystFeedback:
        """Record analyst review verdict for a detection."""
        feedback = AnalystFeedback(
            detection_id=detection_id,
            analyst_id=analyst_id,
            verdict=verdict.upper(),
            comment=comment,
        )
        self.db.add(feedback)
        self.db.commit()
        self.db.refresh(feedback)
        return feedback


class AnalystFeedbackRepository:
    """Repository handling database operations for AnalystFeedback."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def list_for_detection(self, detection_id: str) -> List[AnalystFeedback]:
        """List feedback items submitted for a specific detection."""
        return (
            self.db.query(AnalystFeedback)
            .filter(AnalystFeedback.detection_id == detection_id)
            .order_by(AnalystFeedback.created_at.asc())
            .all()
        )

    def create(
        self, detection_id: str, analyst_id: str, verdict: str, comment: Optional[str] = None
    ) -> AnalystFeedback:
        """Record analyst triage feedback."""
        feedback = AnalystFeedback(
            detection_id=detection_id,
            analyst_id=analyst_id,
            verdict=verdict.upper(),
            comment=comment,
        )
        self.db.add(feedback)
        self.db.commit()
        self.db.refresh(feedback)
        return feedback
