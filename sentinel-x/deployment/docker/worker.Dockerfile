FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/pyproject.toml backend/requirements.txt ./
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

COPY backend/app ./app

RUN useradd -m -u 10001 sentinel && \
    chown -R sentinel:sentinel /app

USER sentinel

CMD ["celery", "-A", "app.workers.celery_app", "worker", "--loglevel=info"]
