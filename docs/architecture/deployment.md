# Sentinel-X: Production Deployment Guide

## 1. Overview

Sentinel-X is distributed as a multi-container Docker Compose application comprising:
1. `sentinel_postgres`: PostgreSQL 16 database.
2. `sentinel_redis`: Redis 7 in-memory cache and task broker.
3. `sentinel_backend`: FastAPI Python 3.12 application server.
4. `sentinel_worker`: Celery background processing worker.
5. `sentinel_frontend`: Static React 18 production bundle served via Nginx.
6. `sentinel_nginx`: Hardened reverse proxy gateway terminating HTTP/TLS and routing traffic.

---

## 2. Docker Architecture & Hardening

```mermaid
flowchart TD
    Client["Client Request (Port 80/443)"]
    Nginx["sentinel_nginx (Nginx 1.27-alpine)"]
    Client --> Nginx

    subgraph InternalNet ["Internal Docker Bridge Network: sentinel_net"]
        Nginx -- "/ -> static SPA" --> Frontend["sentinel_frontend (Nginx Alpine)"]
        Nginx -- "/api/*, /health/*, /ws/*" --> Backend["sentinel_backend (FastAPI / Uvicorn)"]
        
        Backend -- "Task Queue" --> Redis["sentinel_redis (Redis 7 Alpine)"]
        Worker["sentinel_worker (Celery Worker)"] -- "Consume Tasks" --> Redis
        
        Backend -- "ORM (Port 5432)" --> Postgres["sentinel_postgres (Postgres 16 Alpine)"]
        Worker -- "Persist Detections" --> Postgres
    end
```

### Security Hardening Measures:
* **Non-Root Execution:** Backend and Worker containers execute under dedicated non-root UID `10001 (sentinel)`.
* **Minimal Base Images:** Built using `python:3.12-slim` and `alpine` images to minimize Common Vulnerabilities and Exposures (CVE) surface.
* **Health Checks:** Every service defines a native `healthcheck` ensuring automatic restart and reliable dependency ordering (`condition: service_healthy`).
* **Zero Baked Secrets:** No secrets, passwords, or keys are hardcoded in Dockerfiles. All credentials are injected at container startup via runtime environment variables.

---

## 3. Environment Variables Reference

| Variable | Description | Default / Example | Required |
| :--- | :--- | :--- | :--- |
| `ENVIRONMENT` | Deployment environment name | `production` / `development` | Yes |
| `DATABASE_URL` | PostgreSQL connection DSN | `postgresql+psycopg2://user:pass@postgres:5432/sentinel_x` | Yes |
| `REDIS_URL` | Redis connection URL | `redis://redis:6379/0` | Yes |
| `JWT_SECRET` | 256-bit cryptographically random HMAC secret | High-entropy 32+ char hex string | Yes |
| `JWT_REFRESH_SECRET`| 256-bit secret for refresh token rotation | High-entropy 32+ char hex string | Yes |
| `ADMIN_BOOTSTRAP_SECRET` | One-time secret to seed admin account | High-entropy 32+ char secret | Yes |
| `MODEL_SIGNING_KEY` | HMAC key to verify model pickle artifacts | High-entropy 32+ char secret | Yes |
| `VIRUSTOTAL_API_KEY`| Optional API key for VirusTotal v3 | Hex string | No |
| `ABUSEIPDB_API_KEY` | Optional API key for AbuseIPDB v2 | Hex string | No |
| `CORS_ORIGINS` | JSON array of permitted web origins | `["https://soc.company.internal"]` | Yes |

---

## 4. Production Deployment Steps

### Step 1: Clone Repository & Configure Environment
```bash
git clone https://github.com/organization/sentinel-x.git
cd sentinel-x
cp .env.example .env
# Edit .env and replace all default secrets with secure 32+ character keys
```

### Step 2: Build and Launch Containers
```bash
docker compose build --no-cache
docker compose up -d
```

### Step 3: Run Database Migrations
```bash
docker compose exec backend alembic upgrade head
```

### Step 4: Seed Initial Admin User
```bash
docker compose exec backend python scripts/create_admin.py \
  --email "admin@sentinel.internal" \
  --password "YourStrongPassword123!" \
  --name "Lead SOC Administrator" \
  --bootstrap-secret "$ADMIN_BOOTSTRAP_SECRET"
```

### Step 5: Verify Health
```bash
curl -f http://localhost/health/ready
# Expected: {"status":"healthy","database":true,"redis":true}
```

---

## 5. Render Cloud Deployment (Blueprint IaC)

Sentinel-X includes a production `render.yaml` Blueprint at the repository root:

1. Link your GitHub repository to [Render.com](https://render.com).
2. Navigate to **Blueprints** -> **New Blueprint Instance**.
3. Select your repository. Render automatically discovers `render.yaml` and provisions:
   - **PostgreSQL 16 Database**: `sentinel-postgres`
   - **Redis Instance**: `sentinel-redis`
   - **FastAPI Backend**: `sentinel-backend` with automated `alembic upgrade head`, role seeding, admin initialization, and demo data generation.
   - **Celery Worker**: `sentinel-worker` for asynchronous threat correlation and report tasks.
   - **React SPA Frontend**: `sentinel-frontend` static site automatically linked to `VITE_API_URL` and `VITE_WS_URL`.
4. Click **Apply** to deploy the full cluster with zero manual configuration.

---

## 6. Railway Cloud Deployment

Sentinel-X provides native `railway.json` and `railway.toml` configurations:

1. In [Railway.app](https://railway.app), create a **New Project**.
2. Add a **PostgreSQL** database and a **Redis** instance from the Railway marketplace.
3. Deploy the GitHub repository as a web service; Railway uses `deployment/docker/backend.Dockerfile` and runs database migrations + seeding on startup.
4. Add a second service from the same repo for the Celery worker with start command `celery -A app.workers.celery_app worker --loglevel=info`.
5. Deploy the frontend static service pointing to the `frontend/` directory with `VITE_API_URL` set to the backend's public domain.


