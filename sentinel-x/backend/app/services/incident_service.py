"""Incident Management and Automated Correlation Engine (Section 43).

Correlates incoming detections with existing active incidents to prevent
alert fatigue, creates new incidents when appropriate, and tracks full
incident lifecycle transitions and audit timeline events.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.core.exceptions import AppValidationError, NotFoundError
from app.db.models.detection import Detection
from app.db.models.incident import Incident
from app.db.models.network_flow import NetworkFlow
from app.repositories.incidents import IncidentRepository
from app.repositories.users import UserRepository

# Severity hierarchy for escalation checks
SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

VALID_STATUSES = {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"}


class IncidentService:
    """Manages security incidents and correlation logic."""

    def __init__(self, db: Session):
        self.db = db
        self.repo = IncidentRepository(db)

    def correlate_detection(
        self,
        detection: Detection,
        flow: Optional[NetworkFlow] = None,
        system_user_id: Optional[str] = None,
        correlation_window_hours: int = 2,
    ) -> Optional[Incident]:
        """Correlate a detection against active incidents within the correlation window."""
        # 1. Benign non-anomalous telemetry does not trigger incidents
        if (
            detection.attack_type.upper() in ("BENIGN", "NORMAL")
            and not detection.is_anomaly
            and float(detection.risk_score) < 40.0
        ):
            return None

        # Fetch associated network flow if not provided
        if flow is None and detection.flow_id:
            flow = self.db.query(NetworkFlow).filter(NetworkFlow.id == detection.flow_id).first()

        source_ip = flow.source_ip if flow else "unknown"
        dest_ip = flow.destination_ip if flow else "unknown"

        # 2. Look for existing related active incidents within time window
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=correlation_window_hours)
        active_incidents = (
            self.db.query(Incident)
            .filter(
                Incident.status.in_(["OPEN", "INVESTIGATING"]),
                Incident.created_at >= cutoff_time,
            )
            .order_by(Incident.created_at.desc())
            .all()
        )

        matched_incident: Optional[Incident] = None
        for inc in active_incidents:
            # Check if incident title references the same source IP or attack
            if source_ip != "unknown" and source_ip in inc.title:
                matched_incident = inc
                break
            # Check linked detections for matching source_ip
            for linked_det in inc.detections:
                if linked_det.flow and linked_det.flow.source_ip == source_ip:
                    matched_incident = inc
                    break
            if matched_incident:
                break

        now = datetime.now(timezone.utc)

        # 3. Existing related incident found -> attach detection and evaluate escalation
        if matched_incident:
            # Link detection if not already linked
            existing_ids = {d.id for d in matched_incident.detections}
            if detection.id not in existing_ids:
                self.repo.link_detection(matched_incident.id, detection.id, linked_at=now)

                # Escalation check
                current_sev_level = SEVERITY_ORDER.get(matched_incident.severity.upper(), 1)
                new_sev_level = SEVERITY_ORDER.get(detection.severity.upper(), 1)

                escalated = False
                if new_sev_level > current_sev_level:
                    matched_incident.severity = detection.severity
                    escalated = True

                matched_incident.updated_at = now

                # Add correlation timeline event
                event_msg = (
                    f"Correlated detection {detection.id} ({detection.attack_type}, "
                    f"Risk {detection.risk_score})."
                )
                if escalated:
                    event_msg += f" Escalated incident severity to {detection.severity}."

                self.repo.add_event(
                    incident_id=matched_incident.id,
                    event_type="DETECTION_CORRELATED",
                    message=event_msg,
                    metadata={
                        "detection_id": detection.id,
                        "attack_type": detection.attack_type,
                        "risk_score": float(detection.risk_score),
                        "source_ip": source_ip,
                        "destination_ip": dest_ip,
                    },
                )
                self.db.commit()
                self.db.refresh(matched_incident)

            return matched_incident

        # 4. No matching incident found -> Create new incident
        # Resolve creator ID (system admin or fallback)
        creator_id = system_user_id
        if not creator_id:
            user_repo = UserRepository(self.db)
            admin = user_repo.get_by_email("admin@sentinel.internal")
            if admin:
                creator_id = admin.id
            else:
                first_user = self.db.query(Incident).first()
                creator_id = (
                    first_user.created_by if first_user else "00000000-0000-0000-0000-000000000001"
                )

        title = f"{detection.attack_type} activity detected from {source_ip}"
        description = (
            f"Automated security incident initiated by detection {detection.id}. "
            f"Target: {dest_ip}. Risk score: {detection.risk_score} ({detection.severity})."
        )

        new_incident = self.repo.create(
            title=title,
            description=description,
            severity=detection.severity,
            status="OPEN",
            created_by=creator_id,
        )

        # Link initial detection
        self.repo.link_detection(new_incident.id, detection.id, linked_at=now)

        # Add initial timeline event
        self.repo.add_event(
            incident_id=new_incident.id,
            event_type="INCIDENT_CREATED",
            message="Incident created via automated correlation engine.",
            metadata={
                "trigger_detection_id": detection.id,
                "attack_type": detection.attack_type,
                "risk_score": float(detection.risk_score),
                "source_ip": source_ip,
                "destination_ip": dest_ip,
            },
        )
        self.db.commit()
        self.db.refresh(new_incident)

        return new_incident

    def update_status(
        self,
        incident_id: str,
        new_status: str,
        actor_id: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> Incident:
        """Update incident lifecycle status with validation and audit timeline entry."""
        status_clean = (new_status or "").strip().upper()
        if status_clean not in VALID_STATUSES:
            raise AppValidationError(
                f"Invalid incident status '{new_status}'. Allowed: {sorted(VALID_STATUSES)}"
            )

        incident = self.repo.get_by_id(incident_id)
        if not incident:
            raise NotFoundError(f"Incident '{incident_id}' not found.")

        old_status = incident.status
        now = datetime.now(timezone.utc)
        resolved_at = now if status_clean in ("RESOLVED", "FALSE_POSITIVE") else None

        updated = self.repo.update_status(
            incident_id=incident_id,
            status=status_clean,
            resolved_at=resolved_at,
        )

        event_msg = f"Status changed from {old_status} to {status_clean}."
        if comment:
            event_msg += f" Note: {comment}"

        self.repo.add_event(
            incident_id=incident_id,
            event_type="STATUS_CHANGED",
            message=event_msg,
            actor_id=actor_id,
            metadata={"old_status": old_status, "new_status": status_clean},
        )
        self.db.commit()
        return updated

    def assign_incident(
        self,
        incident_id: str,
        analyst_id: Optional[str],
        actor_id: Optional[str] = None,
    ) -> Incident:
        """Assign incident to an analyst."""
        incident = self.repo.get_by_id(incident_id)
        if not incident:
            raise NotFoundError(f"Incident '{incident_id}' not found.")

        updated = self.repo.update(incident_id, assigned_to=analyst_id)
        self.repo.add_event(
            incident_id=incident_id,
            event_type="ANALYST_ASSIGNED",
            message=f"Incident assigned to analyst '{analyst_id}'."
            if analyst_id
            else "Incident unassigned.",
            actor_id=actor_id,
            metadata={"assigned_to": analyst_id},
        )
        self.db.commit()
        return updated
