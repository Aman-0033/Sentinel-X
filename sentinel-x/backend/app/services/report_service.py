"""Report Generation and Export Service (Section 11.13 and Section 22).

Supports asynchronous and on-demand generation of SOC security summary and
incident forensic reports in PDF, CSV, and JSON formats with secure storage.
"""

import csv
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.core.exceptions import AppValidationError, NotFoundError
from app.db.models.detection import Detection
from app.db.models.incident import Incident
from app.db.models.report import Report
from app.repositories.reports import ReportRepository

ALLOWED_FORMATS = {"PDF", "CSV", "JSON"}
ALLOWED_STATUSES = {"QUEUED", "PROCESSING", "COMPLETED", "FAILED"}


class ReportService:
    """Manages generation, storage, and retrieval of security reports."""

    def __init__(self, db: Session, storage_dir: Optional[Path] = None):
        self.db = db
        self.repo = ReportRepository(db)
        if storage_dir:
            self.storage_dir = storage_dir
        else:
            backend_dir = Path(__file__).resolve().parents[2]
            self.storage_dir = backend_dir / "storage" / "reports"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def request_report(
        self,
        generated_by: str,
        period_start: datetime,
        period_end: datetime,
        format_type: str = "JSON",
        incident_id: Optional[str] = None,
    ) -> Report:
        """Create a new report generation record with QUEUED status."""
        fmt_clean = (format_type or "").strip().upper()
        if fmt_clean not in ALLOWED_FORMATS:
            raise AppValidationError(
                f"Unsupported report format '{format_type}'. Allowed: {sorted(ALLOWED_FORMATS)}"
            )

        if period_start > period_end:
            raise AppValidationError("period_start cannot be greater than period_end.")

        now = datetime.now(timezone.utc)
        report = self.repo.create(
            generated_by=generated_by,
            period_start=period_start,
            period_end=period_end,
            format=fmt_clean,
            status="QUEUED",
            incident_id=incident_id,
            created_at=now,
        )
        self.db.commit()
        self.db.refresh(report)
        return report

    def generate_report_content(self, report_id: str) -> Path:
        """Execute data aggregation and write formatted report file to secure storage."""
        report = self.repo.get_by_id(report_id)
        if not report:
            raise NotFoundError(f"Report '{report_id}' not found.")

        self.repo.update_status(report_id, "PROCESSING")
        self.db.commit()

        try:
            # 1. Gather report data
            if report.incident_id:
                data = self._compile_incident_data(report.incident_id)
            else:
                data = self._compile_summary_data(report.period_start, report.period_end)

            # 2. Write file with non-predictable UUID filename
            file_uuid = str(uuid.uuid4())
            fmt = report.format.lower()
            file_name = f"report_{file_uuid}.{fmt}"
            file_path = self.storage_dir / file_name

            if fmt == "json":
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, default=str)

            elif fmt == "csv":
                self._write_csv(data, file_path)

            elif fmt == "pdf":
                # Generate clean structured text/PDF document
                self._write_pdf_placeholder(data, file_path)

            # 3. Update report record
            self.repo.update_status(report_id, "COMPLETED", file_path=str(file_path))
            self.db.commit()
            return file_path

        except Exception as exc:
            self.repo.update_status(report_id, "FAILED")
            self.db.commit()
            raise AppValidationError(f"Report generation failed: {str(exc)}") from exc

    def _compile_summary_data(self, start: datetime, end: datetime) -> Dict[str, Any]:
        """Aggregate security statistics across the given time window."""
        incidents = (
            self.db.query(Incident)
            .filter(Incident.created_at >= start, Incident.created_at <= end)
            .all()
        )
        detections = (
            self.db.query(Detection)
            .filter(Detection.detected_at >= start, Detection.detected_at <= end)
            .all()
        )

        sev_counts: Dict[str, int] = {}
        for d in detections:
            sev_counts[d.severity] = sev_counts.get(d.severity, 0) + 1

        attack_counts: Dict[str, int] = {}
        for d in detections:
            attack_counts[d.attack_type] = attack_counts.get(d.attack_type, 0) + 1

        return {
            "title": "Sentinel-X SOC Security Summary",
            "period_start": start.isoformat(),
            "period_end": end.isoformat(),
            "total_detections": len(detections),
            "total_incidents": len(incidents),
            "severity_breakdown": sev_counts,
            "attack_type_breakdown": attack_counts,
            "incidents": [
                {
                    "id": inc.id,
                    "title": inc.title,
                    "severity": inc.severity,
                    "status": inc.status,
                    "created_at": inc.created_at.isoformat(),
                }
                for inc in incidents
            ],
        }

    def _compile_incident_data(self, incident_id: str) -> Dict[str, Any]:
        """Compile detailed forensic record for a single incident."""
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise NotFoundError(f"Incident '{incident_id}' not found.")

        return {
            "title": f"Forensic Investigation: {incident.title}",
            "incident_id": incident.id,
            "severity": incident.severity,
            "status": incident.status,
            "created_at": incident.created_at.isoformat(),
            "updated_at": incident.updated_at.isoformat(),
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
            "description": incident.description,
            "linked_detections_count": len(incident.detections),
            "timeline_events": [
                {
                    "event_type": ev.event_type,
                    "message": ev.message,
                    "timestamp": ev.created_at.isoformat(),
                }
                for ev in incident.events
            ],
        }

    def _write_csv(self, data: Dict[str, Any], path: Path) -> None:
        """Write summary dictionary to flat CSV format."""
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Key", "Value"])
            for k, v in data.items():
                if not isinstance(v, (list, dict)):
                    writer.writerow([k, v])
            # Write incident rows if available
            if "incidents" in data and isinstance(data["incidents"], list):
                writer.writerow([])
                writer.writerow(["Incident ID", "Title", "Severity", "Status", "Created At"])
                for inc in data["incidents"]:
                    writer.writerow(
                        [inc["id"], inc["title"], inc["severity"], inc["status"], inc["created_at"]]
                    )

    def _write_pdf_placeholder(self, data: Dict[str, Any], path: Path) -> None:
        """Write structured plain text / PDF format document."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"%PDF-1.4\n1 0 obj\n<< /Title ({data.get('title')}) >>\nendobj\n")
            f.write(f"\nSENTINEL-X SECURITY REPORT\n{'=' * 40}\n")
            for k, v in data.items():
                if not isinstance(v, (list, dict)):
                    f.write(f"{k}: {v}\n")
            f.write(
                f"\nGenerated by Sentinel-X Forensic Engine at {datetime.now(timezone.utc).isoformat()}\n"
            )
