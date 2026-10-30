"""Sentinel-X FastAPI Application Entrypoint.

Configures middlewares, security headers, CORS, exception handlers, and API routing.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import api_router
from app.api.v1.health import router as health_router
from app.core.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import setup_logging
from app.core.redis import close_redis_connection
from app.core.security_headers import SecurityHeadersMiddleware
from app.middleware.audit import AuditMiddleware
from app.middleware.authentication import AuthenticationMiddleware
from app.middleware.request_id import RequestIdMiddleware

logger = logging.getLogger("sentinel.app")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager handling application startup and shutdown lifecycle."""
    settings = get_settings()
    setup_logging(settings.LOG_LEVEL)
    logger.info(
        f"Starting {settings.PROJECT_NAME} (v{settings.VERSION}) in [{settings.ENVIRONMENT}] mode",
        extra={"action": "app_startup", "environment": settings.ENVIRONMENT},
    )
    yield
    logger.info(
        f"Shutting down {settings.PROJECT_NAME}",
        extra={"action": "app_shutdown"},
    )
    close_redis_connection()


def create_app() -> FastAPI:
    """Application factory initializing FastAPI with full defensive configuration."""
    settings = get_settings()

    # Disable interactive documentation endpoints in production for attack surface reduction
    docs_url = "/docs" if settings.ENVIRONMENT != "production" else None
    redoc_url = None
    openapi_url = "/openapi.json" if settings.ENVIRONMENT != "production" else None

    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )

    # 1. Register centralized safe exception handlers
    register_exception_handlers(app)

    # 2. Register middlewares (Executed in reverse order of addition: RequestId -> SecurityHeaders -> CORS)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
        max_age=600,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(AuditMiddleware)
    app.add_middleware(AuthenticationMiddleware)
    app.add_middleware(RequestIdMiddleware)

    # 3. Mount health probe routes (root /health) and API v1 endpoints
    app.include_router(health_router, prefix="/health", tags=["Health"])
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    return app


app = create_app()
