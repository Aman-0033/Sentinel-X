"""API v1 router aggregator."""

from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.audit_logs import router as audit_logs_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.detections import router as detections_router
from app.api.v1.health import router as health_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.ingestion import router as ingestion_router
from app.api.v1.models import router as models_router
from app.api.v1.reports import router as reports_router
from app.api.v1.threat_intel import router as threat_intel_router
from app.api.v1.users import router as users_router
from app.api.v1.websocket import router as websocket_router

api_router = APIRouter()

api_router.include_router(health_router, prefix="/health", tags=["Health"])
api_router.include_router(auth_router)
api_router.include_router(audit_logs_router)
api_router.include_router(dashboard_router)
api_router.include_router(ingestion_router)
api_router.include_router(detections_router)
api_router.include_router(incidents_router)
api_router.include_router(threat_intel_router)
api_router.include_router(models_router)
api_router.include_router(reports_router)
api_router.include_router(users_router)
api_router.include_router(websocket_router)

__all__ = ["api_router"]
