"""Incident and Investigation Repository.

Data access layer for Incidents, IncidentDetections, and IncidentEvents.
"""

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from app.db.models.incident import Incident
from app.db.models.incident_detection import IncidentDetection
from app.db.models.incident_event import IncidentEvent


class IncidentRepository:
    """Repository handling database operations for Incidents, links, and event timelines."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, incident_id: str) -> Optional[Incident]:
        """Fetch incident by primary key ID."""
        return self.db.query(Incident).filter(Incident.id == incident_id).first()

    def create(self, **kwargs) -> Incident:
        """Create and persist a new security incident."""
        incident = Incident(**kwargs)
        self.db.add(incident)
        self.db.commit()
        self.db.refresh(incident)
        return incident

    def update(self, incident: Incident | str, **kwargs) -> Optional[Incident]:
        """Update incident properties by instance or primary key ID."""
        if isinstance(incident, str):
            inc_obj = self.get_by_id(incident)
            if not inc_obj:
                return None
        else:
            inc_obj = incident

        for key, value in kwargs.items():
            if hasattr(inc_obj, key) and value is not None:
                setattr(inc_obj, key, value)
        inc_obj.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(inc_obj)
        return inc_obj

    def update_status(
        self, incident_id: str, status: str, resolved_at: Optional[datetime] = None
    ) -> Optional[Incident]:
        """Update incident status and resolution timestamp."""
        incident = self.get_by_id(incident_id)
        if incident:
            incident.status = status.upper()
            if resolved_at is not None:
                incident.resolved_at = resolved_at
            incident.updated_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(incident)
        return incident

    def list_incidents(
        self,
        skip: int = 0,
        limit: int = 50,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assigned_to: Optional[str] = None,
    ) -> List[Incident]:
        """List incidents with filtering and pagination."""
        query = self.db.query(Incident)
        if status:
            query = query.filter(Incident.status == status.upper())
        if severity:
            query = query.filter(Incident.severity == severity.upper())
        if assigned_to:
            query = query.filter(Incident.assigned_to == assigned_to)
        return query.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()

    def count_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assigned_to: Optional[str] = None,
    ) -> int:
        """Count total matching incidents."""
        query = self.db.query(Incident)
        if status:
            query = query.filter(Incident.status == status.upper())
        if severity:
            query = query.filter(Incident.severity == severity.upper())
        if assigned_to:
            query = query.filter(Incident.assigned_to == assigned_to)
        return query.count()

    def link_detection(
        self,
        incident_id: str,
        detection_id: str,
        linked_at: Optional[datetime] = None,
    ) -> IncidentDetection:
        """Associate a detection with an incident."""
        existing = (
            self.db.query(IncidentDetection)
            .filter(
                IncidentDetection.incident_id == incident_id,
                IncidentDetection.detection_id == detection_id,
            )
            .first()
        )
        if existing:
            return existing
        link = IncidentDetection(
            incident_id=incident_id,
            detection_id=detection_id,
            linked_at=linked_at or datetime.now(timezone.utc),
        )
        self.db.add(link)
        self.db.commit()
        return link

    def add_event(
        self,
        incident_id: str,
        event_type: str,
        message: str,
        actor_id: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> IncidentEvent:
        """Add timeline event to incident."""
        event = IncidentEvent(
            incident_id=incident_id,
            event_type=event_type,
            message=message,
            actor_id=actor_id,
            metadata_=metadata,
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event

    def list_events(self, incident_id: str) -> List[IncidentEvent]:
        """Fetch all timeline events for an incident."""
        return (
            self.db.query(IncidentEvent)
            .filter(IncidentEvent.incident_id == incident_id)
            .order_by(IncidentEvent.created_at.asc())
            .all()
        )
