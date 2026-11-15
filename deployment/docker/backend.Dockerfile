FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/pyproject.toml backend/requirements.txt ./
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

COPY backend/app ./app
COPY backend/alembic.ini ./
COPY backend/migrations ./migrations
COPY scripts ./scripts
COPY ml ./ml

RUN mkdir -p /app/storage/reports /app/storage/quarantine /app/storage/models && \
    useradd -m -u 10001 sentinel && \
    chown -R sentinel:sentinel /app

USER sentinel

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health/live || exit 1

CMD ["sh", "-c", "alembic upgrade head && python scripts/seed_database.py && python scripts/create_admin.py && python scripts/demo_data.py && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
