"""Report Repository.

Data access layer for compliance and forensic reports.
"""

from typing import List, Optional

from sqlalchemy.orm import Session

from app.db.models.report import Report


class ReportRepository:
    """Repository handling database operations for generated reports."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, report_id: str) -> Optional[Report]:
        """Fetch report by primary key ID."""
        return self.db.query(Report).filter(Report.id == report_id).first()

    def create(self, **kwargs) -> Report:
        """Create a new report record."""
        report = Report(**kwargs)
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)
        return report

    def update_status(
        self, report_id: str, status: str, file_path: Optional[str] = None
    ) -> Optional[Report]:
        """Update report status and output file path."""
        report = self.get_by_id(report_id)
        if report:
            report.status = status.upper()
            if file_path:
                report.file_path = file_path
            self.db.commit()
            self.db.refresh(report)
        return report

    def list_reports(
        self, skip: int = 0, limit: int = 50, user_id: Optional[str] = None
    ) -> List[Report]:
        """List reports with pagination and optional user filter."""
        query = self.db.query(Report)
        if user_id:
            query = query.filter(Report.generated_by == user_id)
        return query.order_by(Report.created_at.desc()).offset(skip).limit(limit).all()

    def count_reports(self, user_id: Optional[str] = None) -> int:
        """Count total reports."""
        query = self.db.query(Report)
        if user_id:
            query = query.filter(Report.generated_by == user_id)
        return query.count()
