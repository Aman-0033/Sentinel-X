"""Machine Learning Model Registry REST endpoints (Section 21)."""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import (
    RoleChecker,
    get_current_user,
    get_db,
    get_request_meta,
)
from app.core.exceptions import NotFoundError
from app.db.models.model_version import ModelVersion
from app.db.models.user import User
from app.ml.inference.model_loader import ModelLoader
from app.repositories.models import ModelVersionRepository
from app.schemas.common import CollectionMeta, CollectionResponse, ResponseMeta, SuccessResponse
from app.schemas.model import ModelActivateResponse, ModelVersionItem

router = APIRouter(prefix="/models", tags=["Models"])


@router.get(
    "",
    response_model=CollectionResponse[ModelVersionItem],
    summary="List all registered machine learning models",
)
def list_models(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> CollectionResponse[ModelVersionItem]:
    """Retrieve catalog of model artifacts and their training metrics."""
    repo = ModelVersionRepository(db)
    skip = (page - 1) * page_size
    models_raw = repo.list_models(skip=skip, limit=page_size, status=status)
    total = repo.count_models(status=status)

    items = [
        ModelVersionItem(
            id=m.id,
            name=m.name,
            version=m.version,
            algorithm=m.algorithm,
            artifact_uri=m.artifact_uri,
            status=m.status,
            checksum=m.checksum,
            feature_schema=m.feature_schema,
            metrics=m.metrics,
            trained_at=m.trained_at,
            created_at=m.created_at,
        )
        for m in models_raw
    ]

    col_meta = CollectionMeta(
        page=page,
        page_size=page_size,
        total=total,
        request_id=meta.request_id,
    )
    return CollectionResponse(data=items, meta=col_meta)


@router.get(
    "/{model_id}",
    response_model=SuccessResponse[ModelVersionItem],
    summary="Get detailed specifications and evaluation metrics for a model",
)
def get_model(
    model_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[ModelVersionItem]:
    """Fetch model version by ID."""
    repo = ModelVersionRepository(db)
    m = repo.get_by_id(model_id)
    if not m:
        raise NotFoundError(f"Model version '{model_id}' not found.")

    data = ModelVersionItem(
        id=m.id,
        name=m.name,
        version=m.version,
        algorithm=m.algorithm,
        artifact_uri=m.artifact_uri,
        status=m.status,
        checksum=m.checksum,
        feature_schema=m.feature_schema,
        metrics=m.metrics,
        trained_at=m.trained_at,
        created_at=m.created_at,
    )
    return SuccessResponse(data=data, meta=meta)


@router.post(
    "/{model_id}/activate",
    response_model=SuccessResponse[ModelActivateResponse],
    dependencies=[Depends(RoleChecker(["ADMIN"]))],
    summary="Promote model version to ACTIVE in production (ADMIN only)",
)
def activate_model(
    model_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[ModelActivateResponse]:
    """Promote model version to ACTIVE, retiring any currently active models."""
    repo = ModelVersionRepository(db)
    model = repo.get_by_id(model_id)
    if not model:
        raise NotFoundError(f"Model version '{model_id}' not found.")

    # Retire currently active model versions
    db.query(ModelVersion).filter(ModelVersion.status == "ACTIVE").update({"status": "RETIRED"})

    now = datetime.now(timezone.utc)
    model.status = "ACTIVE"
    db.commit()
    db.refresh(model)

    # Invalidate model loader in-memory cache to reload new active bundle
    ModelLoader.clear_cache()

    data = ModelActivateResponse(
        id=model.id,
        model_id=model.id,
        name=model.name,
        version=model.version,
        status="ACTIVE",
        activated_at=now,
    )
    return SuccessResponse(data=data, meta=meta)
