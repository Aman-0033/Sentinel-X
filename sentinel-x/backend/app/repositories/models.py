"""Model Version Registry Repository.

Data access layer for ML model lifecycle entities.
"""

from typing import List, Optional

from sqlalchemy.orm import Session

from app.db.models.model_version import ModelVersion


class ModelVersionRepository:
    """Repository handling database operations for ModelVersion entities."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, model_id: str) -> Optional[ModelVersion]:
        """Fetch model version by primary key ID."""
        return self.db.query(ModelVersion).filter(ModelVersion.id == model_id).first()

    def get_by_name_and_version(self, name: str, version: str) -> Optional[ModelVersion]:
        """Fetch model by unique name and version string."""
        return (
            self.db.query(ModelVersion)
            .filter(ModelVersion.name == name, ModelVersion.version == version)
            .first()
        )

    def get_active_model(self, name: Optional[str] = None) -> Optional[ModelVersion]:
        """Fetch currently active model version for inference."""
        query = self.db.query(ModelVersion).filter(ModelVersion.status == "ACTIVE")
        if name:
            query = query.filter(ModelVersion.name == name)
        return query.order_by(ModelVersion.created_at.desc()).first()

    def create(self, **kwargs) -> ModelVersion:
        """Register a new model version record."""
        model = ModelVersion(**kwargs)
        self.db.add(model)
        self.db.commit()
        self.db.refresh(model)
        return model

    def set_status(self, model_id: str, new_status: str) -> Optional[ModelVersion]:
        """Update model status (TRAINED, EVALUATED, APPROVED, ACTIVE, RETIRED)."""
        model = self.get_by_id(model_id)
        if model:
            # If activating, deactivate other models with same name
            if new_status == "ACTIVE":
                self.db.query(ModelVersion).filter(
                    ModelVersion.name == model.name,
                    ModelVersion.id != model.id,
                    ModelVersion.status == "ACTIVE",
                ).update({"status": "RETIRED"})
            model.status = new_status
            self.db.commit()
            self.db.refresh(model)
        return model

    def list_models(
        self, skip: int = 0, limit: int = 50, status: Optional[str] = None
    ) -> List[ModelVersion]:
        """List registered models with pagination and status filter."""
        query = self.db.query(ModelVersion)
        if status:
            query = query.filter(ModelVersion.status == status.upper())
        return query.order_by(ModelVersion.created_at.desc()).offset(skip).limit(limit).all()

    def count_models(self, status: Optional[str] = None) -> int:
        """Count total registered models matching status."""
        query = self.db.query(ModelVersion)
        if status:
            query = query.filter(ModelVersion.status == status.upper())
        return query.count()
