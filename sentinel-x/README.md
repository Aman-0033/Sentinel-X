# SENTINEL-X

> Autonomous Cyber Threat Detection and Response Platform

Sentinel-X is an enterprise-grade AI-powered intrusion detection and autonomous response system designed for Security Operations Centers (SOCs). It delivers high-throughput network flow ingestion, hybrid machine-learning threat classification, explainable AI diagnostics (SHAP), automated threat-intelligence enrichment, and unified incident response workflows.

## Technology Stack

- **Backend**: Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0, Alembic
- **Async & Workers**: Redis 7, Celery
- **Database**: PostgreSQL 16
- **ML & Analytics**: Scikit-Learn, XGBoost, SHAP, Pandas, NumPy
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, Recharts, React Flow

## Architecture

Modular monolith with clean boundary layers:
- `app/api/v1`: Route controllers and endpoints.
- `app/core`: Configuration, security headers, logging, and exceptions.
- `app/db`: Database session management and SQLAlchemy models.
- `app/middleware`: Request tracking and audit logging.
- `app/schemas`: Pydantic validation contracts and standard API envelopes.
- `app/services`: Pure business logic orchestration.
- `app/workers`: Asynchronous Celery background processing.

## Development Setup

```bash
# 1. Clone repository and copy environment configuration
cp .env.example .env

# 2. Run with Docker Compose
docker compose up -d

# 3. Check health
curl http://localhost:8000/health/live
curl http://localhost:8000/health/ready
```
