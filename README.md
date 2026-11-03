# SENTINEL-X

> **Autonomous Cyber Threat Detection and Response Platform (SOC)**  
> Production-style AI-driven Network Intrusion Detection System with Explainable AI (SHAP), Real-Time Telemetry, Risk Scoring Engine, and Interactive Incident Response.

---

## 🌟 Overview

**SENTINEL-X** is an enterprise-grade AI-assisted Security Operations Center (SOC) platform designed for autonomous network intrusion detection, hybrid threat classification, and interactive cyber defense.

- **High-Throughput Telemetry Ingestion**: Validated flow normalization across CSV, JSON, live simulators, and quarantine pipelines.
- **Hybrid AI Engine**: Multi-class XGBoost threat classification + Isolation Forest unsupervised anomaly detection.
- **Explainable AI (XAI)**: SHAP waterfall & force-plot feature attribution for transparent SOC analyst triage.
- **Deterministic Risk Engine**: Multi-factor contextual risk scoring (0–100) combining threat severity, asset criticality, anomaly scores, and temporal velocity.
- **Threat Intelligence Integration**: Automated IOC enrichment (VirusTotal, AlienVault OTX, abuse databases) and MITRE ATT&CK technique mapping.
- **Autonomous Incident Management**: Full incident lifecycle with role-based access control (RBAC), audit logging, analyst feedback, and executive PDF reporting.
- **Real-Time SOC Interface**: High-density React + TypeScript dashboard with dark terminal theme, dynamic attack topology maps (React Flow), Recharts telemetry streams, and live WebSocket broadcasts.

---

## 🚀 Quick Start (One-Click Launch)

### Prerequisites
- **Python 3.12+**
- **Node.js 18+** & **npm**

### Windows (Single Command)
Run the automated launcher:
```cmd
start.bat
```
This automatically:
1. Detects Python virtual environment (`.venv`)
2. Verifies environment configuration (`.env`)
3. Applies Alembic database migrations to head
4. Seeds default SOC accounts, roles, and realistic network telemetry
5. Launches FastAPI backend on port `8000`
6. Launches Vite React SOC dashboard on port `5173`

### Linux / macOS
```bash
chmod +x start.sh
./start.sh
```

---

## 🐳 Docker Deployment

To launch the full production stack with PostgreSQL, Redis, Celery workers, and Nginx reverse proxy:

```bash
# 1. Copy environment variables
cp .env.example .env

# 2. Start services
docker compose up -d

# 3. Health checks
curl http://localhost:8000/health/live
curl http://localhost:8000/health/ready
```

---

## 🛠️ Technology Stack

| Layer | Technologies |
|---|---|
| **Backend API** | Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0, Alembic, Uvicorn |
| **Machine Learning** | Scikit-Learn, XGBoost, SHAP (Explainable AI), Pandas, NumPy, Joblib |
| **Data & Cache** | PostgreSQL 16 (or SQLite for dev demo), Redis 7 |
| **Task Queue** | Celery 5.4, Redis broker |
| **Frontend UI** | React 18, TypeScript, Vite, Tailwind CSS, Recharts, React Flow, Lucide Icons |
| **Testing & Quality** | Pytest, pytest-asyncio, Pyrefly (Meta type checker), Ruff, Coverage |

---

## 🧪 Testing & Verification

Run the test suite across unit, integration, security, and end-to-end demonstration flows:

```bash
# Run complete test suite
pytest

# Run the 17-step end-to-end system demonstration flow
pytest sentinel-x/tests/e2e/test_end_to_end_demonstration.py

# Verify static type safety with Pyrefly
pyrefly check sentinel-x/ml/scripts/evaluate.py sentinel-x/tests/e2e/test_end_to_end_demonstration.py
```

---

## 🔒 Security & Default Credentials (Development)

- **Admin Account**: `admin@sentinelx.local`
- **Default Password**: `Admin@123456`
- **Analyst Account**: `analyst@sentinelx.local`
- **Auditor Account**: `auditor@sentinelx.local`

*(For production deployments, change all default secrets in `.env`)*

---

## 📖 System Specification

For full architectural blueprints, entity-relationship schemas, API schemas, and deployment topology, refer to [architecture.md](architecture.md).
