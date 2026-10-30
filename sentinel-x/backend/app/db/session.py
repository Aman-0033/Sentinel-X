"""SQLAlchemy Database Engine, Session Factory, and Health Check.

Configures resilient connection pooling with pre-ping validation.
Supports PostgreSQL (production) and SQLite (in-memory unit testing).
"""

import logging
from typing import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings

logger = logging.getLogger("sentinel.db")

settings = get_settings()

# Engine creation parameters
engine_kwargs = {
    "pool_pre_ping": settings.DB_POOL_PRE_PING,
}

if "sqlite" in settings.DATABASE_URL.lower():
    engine_kwargs["connect_args"] = {"check_same_thread": False}
    if ":memory:" in settings.DATABASE_URL.lower():
        engine_kwargs["poolclass"] = StaticPool
else:
    engine_kwargs["pool_size"] = settings.DB_POOL_SIZE
    engine_kwargs["max_overflow"] = settings.DB_MAX_OVERFLOW

engine = create_engine(settings.DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency generator yielding an isolated database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_connection() -> bool:
    """Safe database readiness probe. Executes a fast ping without leaking internals."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.warning(f"Database readiness check failed: {exc.__class__.__name__}")
        return False
