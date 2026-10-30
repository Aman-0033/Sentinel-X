# SENTINEL-X — Architecture & Implementation Specification

> **Purpose:** This document is the authoritative implementation specification for an autonomous AI coding agent building SENTINEL-X.
>
> **Project:** AI-Based Intrusion Detection and Cyber Threat Prediction System
>
> **Primary objective:** Build a production-style, modular cybersecurity platform that ingests network-flow data, detects and classifies threats using machine learning, calculates risk, explains predictions, enriches indicators with threat intelligence, manages security incidents, and presents findings through a professional SOC-style web interface.
>
> **Important:** Do not implement the project as a notebook connected directly to a frontend. Separate ML experimentation, production inference, business logic, API handling, and persistence.

---

# 1. PROJECT OVERVIEW

## 1.1 Product Name

**SENTINEL-X**

## 1.2 Product Description

SENTINEL-X is a web-based Security Operations Center (SOC)-style platform for AI-assisted network intrusion detection and cyber-threat analysis.

The system shall support:

1. Network-flow ingestion from controlled datasets, CSV/JSON uploads, simulators, and a future live collector interface.
2. Data validation and normalization.
3. Feature extraction and feature engineering.
4. Supervised attack classification.
5. Anomaly detection.
6. Risk scoring.
7. Explainable AI using feature-level explanations.
8. Threat-intelligence enrichment.
9. Detection and incident management.
10. Real-time dashboard updates.
11. Analyst feedback and audit logging.
12. Security report generation.
13. Model versioning and model activation.
14. Role-based access control.

The core product flow is:

    DATA INGESTION
          |
          v
    FEATURE ENGINEERING
          |
          v
    AI DETECTION
       /       \
      v         v
 CLASSIFIER   ANOMALY DETECTOR
       \       /
        v     v
       RISK ENGINE
           |
           v
     EXPLAINABILITY
           |
           v
  THREAT INTELLIGENCE
           |
           v
       INCIDENTS
           |
           v
       SOC DASHBOARD

---

# 2. ARCHITECTURAL PRINCIPLES

The coding agent MUST follow these principles:

1. Prefer a **modular monolith** over unnecessary microservices.
2. Use a dedicated asynchronous worker for expensive/background operations.
3. Keep ML training separate from production inference.
4. Keep business logic out of API route handlers.
5. Validate every external input.
6. Never trust frontend-supplied authorization decisions.
7. Never store plaintext passwords.
8. Never hardcode secrets.
9. Never expose secrets through frontend bundles, logs, API responses, or exception messages.
10. Treat third-party API responses as untrusted input.
11. Make external threat-intelligence integrations optional and failure-tolerant.
12. Record model version information with every ML detection.
13. Record security-sensitive administrative actions in audit logs.
14. Prefer deterministic, testable components over hidden global state.
15. Design all security-sensitive behavior explicitly rather than relying on framework defaults.

---

# 3. CORE TECH STACK

## 3.1 Frontend

### React + TypeScript

Use for:

- SOC dashboard
- threat tables
- incident investigation
- charts
- live monitoring
- AI explanation views
- reports
- administration

Reason:

- reusable component architecture
- strong typing
- maintainable large UI
- suitable for real-time dashboard applications

### Vite

Use as frontend build/development tooling.

### Tailwind CSS

Use for:

- design system
- responsive layout
- consistent spacing/typography
- SOC-style dark interface
- reusable visual states

### Recharts

Use for:

- threat trends
- attack distribution
- traffic metrics
- severity charts
- time-series visualization

### React Flow

Use for:

- source-to-target attack visualization
- incident relationship diagrams
- network/attack-path displays

---

# 4. BACKEND STACK

## 4.1 Python

Use as the primary backend and ML language.

## 4.2 FastAPI

Use for:

- REST APIs
- authentication endpoints
- dashboard endpoints
- ingestion endpoints
- incident management
- model management
- threat-intelligence APIs
- WebSocket endpoints

## 4.3 Pydantic

Use for:

- request validation
- response schemas
- configuration validation
- strict typing

Do NOT use untyped `dict`/`Any` request bodies where a known schema exists.

## 4.4 SQLAlchemy

Use as the ORM and database abstraction layer.

## 4.5 Alembic

Use for all database schema migrations.

Never manually modify production schema without a migration.

---

# 5. DATA AND BACKGROUND PROCESSING

## PostgreSQL

Primary persistent database.

Use relational tables for:

- users
- roles
- flows
- detections
- incidents
- model versions
- threat-intelligence records
- analyst feedback
- audit logs
- reports

Use JSONB only where flexible metadata is genuinely useful.

## Redis

Use for:

1. caching
2. background job queues
3. real-time event distribution where appropriate
4. rate-limiting state

## Celery

Use for:

- bulk ML inference
- threat-intelligence enrichment
- large dataset processing
- report generation
- other expensive asynchronous jobs

Do not run expensive operations synchronously inside normal API requests.

---

# 6. MACHINE LEARNING STACK

Use:

- Pandas
- NumPy
- scikit-learn
- XGBoost
- SHAP
- Joblib

## 6.1 ML Components

### Supervised classification

Primary candidates:

- XGBoost
- Random Forest
- Logistic Regression
- Neural network only if justified by evaluation

### Anomaly detection

Candidate:

- Isolation Forest

Do not assume a model is good because it has high accuracy.

Evaluate:

- Precision
- Recall
- F1-score
- ROC-AUC where appropriate
- Confusion matrix
- per-class performance

## 6.2 Production ML Separation

Training/research:

    /ml/

Production inference:

    /backend/app/ml/

Business logic:

    /backend/app/services/

Never make a production API execute an entire Jupyter notebook.

---

# 7. EXPLAINABLE AI

Every production ML detection should be traceable to:

- model version
- feature schema
- prediction
- confidence
- anomaly score where applicable
- explanation

The explanation should identify the important contributing features.

Example:

    Prediction: Brute Force
    Confidence: 96.8%

    Important factors:
      - failed_connection_rate
      - request_frequency
      - destination_port_pattern
      - packet_rate

Store explanation data in structured JSONB.

Do not claim that SHAP proves causality. It explains the model's output according to the model/explanation method.

---

# 8. THREAT-INTELLIGENCE ARCHITECTURE

Implement a provider abstraction.

    threat_intel/
        base.py
        service.py
        virustotal.py
        abuseipdb.py
        response_validator.py

The service MUST NOT accept arbitrary user-provided URLs.

The user supplies an indicator such as:

- IP address
- domain
- hash

The backend determines the appropriate approved provider endpoint.

External providers are enrichment sources only.

If a provider is unavailable:

- detection still succeeds
- incident creation still works
- the system records enrichment failure
- the API returns degraded-but-valid information

Never make SENTINEL-X completely dependent on an external threat-intelligence service.

---

# 9. EXACT REPOSITORY STRUCTURE

```text
sentinel-x/
│
├── README.md
├── LICENSE
├── .gitignore
├── .env.example
├── docker-compose.yml
├── Makefile
│
├── docs/
│   ├── architecture/
│   │   ├── system-architecture.md
│   │   ├── data-flow.md
│   │   ├── threat-model.md
│   │   └── deployment.md
│   │
│   ├── api/
│   │   └── api-spec.md
│   │
│   ├── database/
│   │   └── schema.md
│   │
│   ├── security/
│   │   ├── threat-model.md
│   │   ├── security-requirements.md
│   │   ├── authentication.md
│   │   ├── authorization-matrix.md
│   │   ├── input-validation.md
│   │   ├── secrets-management.md
│   │   └── incident-response.md
│   │
│   └── project/
│       ├── requirements.md
│       ├── test-plan.md
│       └── viva-notes.md
│
├── frontend/
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   │
│   └── src/
│       ├── app/
│       │   ├── router.tsx
│       │   ├── providers.tsx
│       │   └── store.ts
│       │
│       ├── assets/
│       │
│       ├── components/
│       │   ├── ui/
│       │   ├── dashboard/
│       │   ├── threats/
│       │   ├── incidents/
│       │   ├── network/
│       │   └── charts/
│       │
│       ├── pages/
│       │   ├── Login.tsx
│       │   ├── Dashboard.tsx
│       │   ├── LiveMonitoring.tsx
│       │   ├── Threats.tsx
│       │   ├── ThreatDetail.tsx
│       │   ├── Incidents.tsx
│       │   ├── IncidentDetail.tsx
│       │   ├── Network.tsx
│       │   ├── AIAnalysis.tsx
│       │   ├── ThreatIntelligence.tsx
│       │   ├── Models.tsx
│       │   ├── Reports.tsx
│       │   ├── AuditLogs.tsx
│       │   └── Settings.tsx
│       │
│       ├── services/
│       │   ├── api.ts
│       │   ├── auth.ts
│       │   ├── websocket.ts
│       │   └── threatIntel.ts
│       │
│       ├── hooks/
│       ├── types/
│       ├── utils/
│       └── styles/
│
├── backend/
│   ├── pyproject.toml
│   │
│   ├── app/
│   │   ├── main.py
│   │
│   │   ├── core/
│   │   │   ├── config.py
│   │   │   ├── security.py
│   │   │   ├── authorization.py
│   │   │   ├── rate_limit.py
│   │   │   ├── validation.py
│   │   │   ├── secrets.py
│   │   │   ├── logging.py
│   │   │   ├── security_headers.py
│   │   │   └── exceptions.py
│   │
│   │   ├── middleware/
│   │   │   ├── request_id.py
│   │   │   ├── authentication.py
│   │   │   ├── rate_limit.py
│   │   │   └── audit.py
│   │
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── auth.py
│   │   │       ├── dashboard.py
│   │   │       ├── ingestion.py
│   │   │       ├── detections.py
│   │   │       ├── incidents.py
│   │   │       ├── threat_intel.py
│   │   │       ├── models.py
│   │   │       ├── reports.py
│   │   │       ├── users.py
│   │   │       └── websocket.py
│   │
│   │   ├── db/
│   │   │   ├── session.py
│   │   │   ├── base.py
│   │   │   └── models/
│   │   │       ├── user.py
│   │   │       ├── role.py
│   │   │       ├── data_source.py
│   │   │       ├── network_flow.py
│   │   │       ├── model_version.py
│   │   │       ├── detection.py
│   │   │       ├── threat_intel.py
│   │   │       ├── incident.py
│   │   │       ├── incident_event.py
│   │   │       ├── analyst_feedback.py
│   │   │       ├── audit_log.py
│   │   │       └── report.py
│   │
│   │   ├── schemas/
│   │   │   ├── auth.py
│   │   │   ├── dashboard.py
│   │   │   ├── ingestion.py
│   │   │   ├── detection.py
│   │   │   ├── incident.py
│   │   │   ├── threat_intel.py
│   │   │   ├── model.py
│   │   │   ├── report.py
│   │   │   └── common.py
│   │
│   │   ├── repositories/
│   │   │   ├── users.py
│   │   │   ├── flows.py
│   │   │   ├── detections.py
│   │   │   ├── incidents.py
│   │   │   ├── models.py
│   │   │   ├── threat_intel.py
│   │   │   ├── reports.py
│   │   │   └── audit_logs.py
│   │
│   │   ├── services/
│   │   │   ├── auth_service.py
│   │   │   ├── dashboard_service.py
│   │   │   ├── ingestion_service.py
│   │   │   ├── detection_service.py
│   │   │   ├── risk_service.py
│   │   │   ├── incident_service.py
│   │   │   ├── threat_intel_service.py
│   │   │   ├── model_service.py
│   │   │   └── report_service.py
│   │
│   │   ├── ml/
│   │   │   ├── inference/
│   │   │   │   ├── predictor.py
│   │   │   │   └── model_loader.py
│   │   │   ├── preprocessing/
│   │   │   │   ├── pipeline.py
│   │   │   │   └── validators.py
│   │   │   ├── feature_engineering/
│   │   │   │   └── features.py
│   │   │   ├── explainability/
│   │   │   │   └── explainer.py
│   │   │   ├── training/
│   │   │   └── registry/
│   │   │
│   │   ├── threat_intel/
│   │   │   ├── base.py
│   │   │   ├── service.py
│   │   │   ├── virustotal.py
│   │   │   ├── abuseipdb.py
│   │   │   ├── allowlist.py
│   │   │   └── response_validator.py
│   │
│   │   ├── workers/
│   │   │   ├── celery_app.py
│   │   │   ├── detection_tasks.py
│   │   │   ├── enrichment_tasks.py
│   │   │   ├── ingestion_tasks.py
│   │   │   └── report_tasks.py
│   │
│   │   └── utils/
│   │       ├── datetime.py
│   │       ├── pagination.py
│   │       └── identifiers.py
│   │
│   └── tests/
│       ├── unit/
│       ├── integration/
│       └── security/
│
├── ml/
│   ├── datasets/
│   │   ├── raw/
│   │   ├── processed/
│   │   └── README.md
│   │
│   ├── notebooks/
│   │   ├── 01_exploration.ipynb
│   │   ├── 02_preprocessing.ipynb
│   │   ├── 03_baseline_models.ipynb
│   │   ├── 04_model_comparison.ipynb
│   │   └── 05_explainability.ipynb
│   │
│   ├── scripts/
│   │   ├── prepare_dataset.py
│   │   ├── train.py
│   │   ├── evaluate.py
│   │   └── register_model.py
│   │
│   └── artifacts/
│       ├── models/
│       ├── preprocessors/
│       └── metrics/
│
├── migrations/
│   └── versions/
│
├── scripts/
│   ├── seed_database.py
│   ├── create_admin.py
│   └── demo_data.py
│
├── tests/
│   └── e2e/
│
└── deployment/
    ├── docker/
    │   ├── backend.Dockerfile
    │   ├── frontend.Dockerfile
    │   └── worker.Dockerfile
    └── nginx/
        └── nginx.conf
````

---

# 10. NAMING CONVENTIONS

## Python

* files: `snake_case.py`
* functions: `snake_case`
* variables: `snake_case`
* classes: `PascalCase`
* constants: `UPPER_SNAKE_CASE`

## TypeScript/React

* components: `PascalCase.tsx`
* hooks: `useSomething.ts`
* utility files: `camelCase.ts` or `snake_case.ts`, but remain consistent
* interfaces/types: `PascalCase`
* variables/functions: `camelCase`

## Database

* table names: `snake_case`
* column names: `snake_case`
* primary keys: `id`
* foreign keys: `<entity>_id`
* timestamps: `created_at`, `updated_at`
* boolean names: `is_*`, `has_*`, `can_*`

## API

Use:

```
/api/v1/<resource>
```

Use plural resource names:

```
/incidents
/detections
/models
/reports
```

Use IDs as path parameters:

```
/incidents/{incident_id}
```

Do not use verbs in resource URLs unless the operation genuinely represents an action:

```
/models/{model_id}/activate
```

---

# 11. DATABASE SCHEMA

PostgreSQL is the system of record.

Use UUID primary keys unless there is a documented reason not to.

Use UTC timestamps.

## 11.1 roles

```
id              UUID PK
name            VARCHAR(30) UNIQUE NOT NULL
description     TEXT NULL
created_at      TIMESTAMPTZ NOT NULL
```

Seed:

```
ADMIN
ANALYST
VIEWER
```

---

## 11.2 users

```
id              UUID PK
role_id         UUID FK -> roles.id NOT NULL
email           VARCHAR(255) UNIQUE NOT NULL
password_hash   TEXT NOT NULL
full_name       VARCHAR(120) NOT NULL
is_active       BOOLEAN NOT NULL DEFAULT TRUE
last_login_at   TIMESTAMPTZ NULL
created_at      TIMESTAMPTZ NOT NULL
updated_at      TIMESTAMPTZ NOT NULL
```

Never store plaintext passwords.

---

## 11.3 data_sources

```
id              UUID PK
name            VARCHAR(100) NOT NULL
source_type     VARCHAR(30) NOT NULL
description     TEXT NULL
configuration   JSONB NULL
created_by      UUID FK -> users.id
created_at      TIMESTAMPTZ NOT NULL
```

Allowed source types:

```
DATASET
CSV_UPLOAD
JSON_UPLOAD
SIMULATOR
LIVE_COLLECTOR
```

Do not store secret values in `configuration`.

---

## 11.4 network_flows

```
id                  UUID PK
source_id           UUID FK -> data_sources.id
timestamp           TIMESTAMPTZ NOT NULL
source_ip           INET NOT NULL
source_port         INTEGER NULL
destination_ip      INET NOT NULL
destination_port    INTEGER NULL
protocol            VARCHAR(20) NULL
packets             BIGINT NULL
bytes               BIGINT NULL
duration_ms         NUMERIC NULL
direction           VARCHAR(20) NULL
raw_features        JSONB NULL
created_at          TIMESTAMPTZ NOT NULL
```

Validation:

```
source_port: 1-65535
destination_port: 1-65535
packets >= 0
bytes >= 0
duration_ms >= 0
```

---

## 11.5 model_versions

```
id                  UUID PK
name                VARCHAR(100) NOT NULL
version             VARCHAR(50) NOT NULL
algorithm           VARCHAR(50) NOT NULL
artifact_uri        TEXT NOT NULL
feature_schema      JSONB NOT NULL
metrics             JSONB NOT NULL
checksum            VARCHAR(128) NOT NULL
status              VARCHAR(30) NOT NULL
trained_at          TIMESTAMPTZ NOT NULL
created_by          UUID FK -> users.id
created_at          TIMESTAMPTZ NOT NULL
```

Allowed lifecycle:

```
TRAINED
EVALUATED
APPROVED
ACTIVE
RETIRED
```

Never silently overwrite an active model.

---

## 11.6 detections

```
id                  UUID PK
flow_id             UUID FK -> network_flows.id NOT NULL
model_version_id    UUID FK -> model_versions.id NOT NULL
attack_type         VARCHAR(100) NOT NULL
confidence          NUMERIC(5,4) NOT NULL
anomaly_score       NUMERIC(8,5) NULL
risk_score          NUMERIC(5,2) NOT NULL
severity             VARCHAR(20) NOT NULL
is_anomaly          BOOLEAN NOT NULL
explanation         JSONB NULL
detected_at         TIMESTAMPTZ NOT NULL
```

Constraints:

```
confidence >= 0 AND confidence <= 1
risk_score >= 0 AND risk_score <= 100
```

---

## 11.7 threat_intel_enrichments

```
id                  UUID PK
detection_id        UUID FK -> detections.id NOT NULL
indicator_type      VARCHAR(20) NOT NULL
indicator_value     VARCHAR(255) NOT NULL
provider            VARCHAR(50) NOT NULL
reputation_score    NUMERIC NULL
verdict              VARCHAR(50) NULL
country              VARCHAR(5) NULL
asn                  BIGINT NULL
response_data       JSONB NULL
checked_at          TIMESTAMPTZ NOT NULL
expires_at          TIMESTAMPTZ NULL
```

Treat `response_data` as untrusted external data.

Do not render arbitrary HTML from this field.

---

## 11.8 incidents

```
id                  UUID PK
title               VARCHAR(255) NOT NULL
description         TEXT NULL
severity            VARCHAR(20) NOT NULL
status              VARCHAR(30) NOT NULL
assigned_to         UUID FK -> users.id NULL
created_by          UUID FK -> users.id NOT NULL
created_at          TIMESTAMPTZ NOT NULL
updated_at          TIMESTAMPTZ NOT NULL
resolved_at         TIMESTAMPTZ NULL
```

Allowed statuses:

```
OPEN
INVESTIGATING
CONTAINED
RESOLVED
FALSE_POSITIVE
```

Allowed severity:

```
LOW
MEDIUM
HIGH
CRITICAL
```

---

## 11.9 incident_detections

```
incident_id         UUID PK/FK -> incidents.id
detection_id        UUID PK/FK -> detections.id
linked_at           TIMESTAMPTZ NOT NULL
```

This is a many-to-many relationship between incidents and detections.

---

## 11.10 incident_events

```
id                  UUID PK
incident_id         UUID FK -> incidents.id NOT NULL
event_type          VARCHAR(50) NOT NULL
message             TEXT NOT NULL
metadata            JSONB NULL
actor_id            UUID FK -> users.id NULL
created_at          TIMESTAMPTZ NOT NULL
```

Every status change or important analyst action should be optionally represented in the timeline.

---

## 11.11 analyst_feedback

```
id                  UUID PK
detection_id        UUID FK -> detections.id NOT NULL
analyst_id          UUID FK -> users.id NOT NULL
verdict             VARCHAR(30) NOT NULL
comment             TEXT NULL
created_at          TIMESTAMPTZ NOT NULL
```

Example verdicts:

```
TRUE_POSITIVE
FALSE_POSITIVE
UNCERTAIN
```

---

## 11.12 audit_logs

```
id                  UUID PK
user_id             UUID FK -> users.id NULL
action              VARCHAR(100) NOT NULL
resource_type       VARCHAR(50) NULL
resource_id         UUID NULL
ip_address          INET NULL
user_agent          TEXT NULL
metadata            JSONB NULL
created_at          TIMESTAMPTZ NOT NULL
```

Never put passwords, API keys, JWTs, refresh tokens, or authorization headers into metadata.

---

## 11.13 reports

```
id                  UUID PK
generated_by        UUID FK -> users.id NOT NULL
incident_id         UUID FK -> incidents.id NULL
period_start        TIMESTAMPTZ NOT NULL
period_end          TIMESTAMPTZ NOT NULL
format              VARCHAR(10) NOT NULL
file_path            TEXT NULL
status              VARCHAR(20) NOT NULL
created_at          TIMESTAMPTZ NOT NULL
```

Allowed formats:

```
PDF
CSV
JSON
```

Allowed status:

```
QUEUED
PROCESSING
COMPLETED
FAILED
```

---

# 12. REQUIRED DATABASE RELATIONSHIPS

```
roles 1 ---- N users

users 1 ---- N data_sources

data_sources 1 ---- N network_flows

network_flows 1 ---- N detections

model_versions 1 ---- N detections

detections 1 ---- N threat_intel_enrichments

incidents N ---- N detections
   through incident_detections

incidents 1 ---- N incident_events

users 1 ---- N analyst_feedback

detections 1 ---- N analyst_feedback

users 1 ---- N audit_logs

users 1 ---- N reports

incidents 1 ---- N reports
```

---

# 13. REQUIRED DATABASE INDEXES

Create indexes for frequent queries:

```
network_flows(timestamp)
network_flows(source_ip)
network_flows(destination_ip)

detections(detected_at)
detections(severity)
detections(attack_type)
detections(risk_score)

incidents(status)
incidents(severity)
incidents(assigned_to)

threat_intel_enrichments(indicator_value)
```

Create additional indexes only when justified by query patterns.

Do not index every column automatically.

---

# 14. API CONTRACT

Base path:

```
/api/v1
```

Use JSON for normal request/response bodies.

Use a consistent response envelope.

## Success

```
{
  "data": {},
  "meta": {
    "request_id": "..."
  }
}
```

## Collection

```
{
  "data": [],
  "meta": {
    "page": 1,
    "page_size": 20,
    "total": 134
  }
}
```

## Error

```
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Safe human-readable message",
    "request_id": "..."
  }
}
```

Never expose stack traces or internal infrastructure information to clients.

---

# 15. AUTHENTICATION API

## POST /api/v1/auth/login

Request:

```
{
  "email": "analyst@example.com",
  "password": "..."
}
```

Response:

```
{
  "data": {
    "access_token": "...",
    "token_type": "bearer",
    "expires_in": 900,
    "user": {
      "id": "...",
      "name": "Security Analyst",
      "role": "ANALYST"
    }
  }
}
```

Requirements:

* rate limit aggressively
* prevent brute force
* never log password
* never log token
* return generic authentication failure messages

---

## POST /api/v1/auth/refresh

Refresh the authenticated session using the approved refresh-token/session mechanism.

---

## POST /api/v1/auth/logout

Invalidate/revoke the corresponding refresh session.

---

## GET /api/v1/auth/me

Return the authenticated user's identity and effective role.

---

# 16. DASHBOARD API

## GET /api/v1/dashboard/summary

Return:

```
{
  "data": {
    "active_threats": 0,
    "critical_threats": 0,
    "open_incidents": 0,
    "traffic_volume": 0,
    "security_score": 0
  }
}
```

---

## GET /api/v1/dashboard/trends

Query parameters:

```
from
to
interval
```

Use bounded date ranges and validate all timestamps.

---

## GET /api/v1/dashboard/attack-distribution

Return grouped attack counts.

---

## GET /api/v1/dashboard/top-sources

Return top suspicious sources.

Do not expose unnecessary sensitive data.

---

# 17. INGESTION API

## POST /api/v1/ingestion/flows/batch

Request concept:

```
{
  "source_id": "uuid",
  "flows": [
    {
      "timestamp": "...",
      "source_ip": "...",
      "source_port": 52134,
      "destination_ip": "...",
      "destination_port": 22,
      "protocol": "TCP",
      "packets": 43,
      "bytes": 8234,
      "duration_ms": 842,
      "features": {}
    }
  ]
}
```

Limits:

* bounded request body
* bounded flow count
* strict field schema
* reject malformed rows
* reject invalid IPs/ports
* reject negative numerical values

Response:

```
{
  "data": {
    "accepted": 1,
    "rejected": 0,
    "job_id": "uuid"
  }
}
```

---

## POST /api/v1/ingestion/upload

Supported input:

* CSV
* JSON

Validation order:

```
authentication
    ->
authorization
    ->
content-size limit
    ->
extension allowlist
    ->
MIME/content validation
    ->
generated server filename
    ->
quarantine storage
    ->
schema validation
    ->
processing
```

Never execute uploaded content.

Never trust the client-provided filename as a filesystem path.

---

# 18. DETECTION API

## POST /api/v1/detections/analyze

Request:

```
{
  "flow_id": "uuid"
}
```

Response:

```
{
  "data": {
    "detection_id": "uuid",
    "attack_type": "Brute Force",
    "confidence": 0.968,
    "anomaly_score": 0.91,
    "risk_score": 88,
    "severity": "HIGH"
  }
}
```

---

## GET /api/v1/detections

Supported filters:

```
page
page_size
severity
attack_type
from
to
```

Pagination must enforce a server-side maximum.

---

## GET /api/v1/detections/{detection_id}

Return:

* detection
* network flow
* model version
* ML explanation
* threat intelligence
* related incidents
* analyst feedback where permitted

---

## POST /api/v1/detections/{detection_id}/feedback

Request:

```
{
  "verdict": "FALSE_POSITIVE",
  "comment": "Known internal scanner."
}
```

Authorization:

* ADMIN
* ANALYST

Do not allow VIEWER users to write analyst feedback.

---

# 19. INCIDENT API

## GET /api/v1/incidents

Filters:

```
status
severity
assigned_to
from
to
page
page_size
```

---

## POST /api/v1/incidents

Request:

```
{
  "title": "...",
  "description": "...",
  "severity": "HIGH",
  "detection_ids": [
    "uuid"
  ]
}
```

Validate that every referenced detection exists and that the current user is authorized to associate it.

---

## GET /api/v1/incidents/{incident_id}

Return:

* incident information
* status
* severity
* assignee
* linked detections
* incident events
* threat intelligence
* ML explanations

---

## PATCH /api/v1/incidents/{incident_id}

Request may contain:

```
{
  "status": "INVESTIGATING",
  "assigned_to": "uuid"
}
```

Every modification should produce an audit event.

---

## POST /api/v1/incidents/{incident_id}/events

Request:

```
{
  "event_type": "ANALYST_NOTE",
  "message": "..."
}
```

Treat message as plain text.

---

# 20. THREAT INTELLIGENCE API

## GET /api/v1/threat-intel/ip/{ip}

Validate the IP using a strict parser before invoking any provider.

---

## POST /api/v1/threat-intel/enrich

Request:

```
{
  "indicator_type": "ip",
  "indicator_value": "203.0.113.10"
}
```

Only supported indicator types are allowed.

Never permit a client to specify an arbitrary provider URL.

---

# 21. ML MODEL API

## GET /api/v1/models

Return registered models visible to the authenticated role.

---

## GET /api/v1/models/{model_id}

Return:

* name
* version
* algorithm
* feature schema
* metrics
* status
* trained time
* checksum

Do not return private storage credentials or internal secret paths.

---

## POST /api/v1/models/{model_id}/activate

ADMIN only.

Activation workflow:

```
TRAINED
    ->
EVALUATED
    ->
APPROVED
    ->
ACTIVE
```

Never automatically promote a newly trained model to active production use.

Record the activating user in the audit log.

---

# 22. REPORT API

## POST /api/v1/reports

Request:

```
{
  "report_type": "SECURITY_SUMMARY",
  "period_start": "...",
  "period_end": "...",
  "format": "PDF"
}
```

Create an asynchronous report-generation job.

Do not generate large reports synchronously inside the HTTP request.

---

## GET /api/v1/reports/{report_id}

Return report status.

---

## GET /api/v1/reports/{report_id}/download

Authorize access before returning the report.

Never construct download filesystem paths directly from user input.

---

# 23. REAL-TIME WEBSOCKET API

Endpoint:

```
WS /api/v1/ws/dashboard
```

Events may include:

```
NEW_DETECTION
INCIDENT_CREATED
INCIDENT_UPDATED
THREAT_INTEL_UPDATED
MODEL_STATUS_CHANGED
```

Example:

```
{
  "event": "NEW_DETECTION",
  "data": {
    "detection_id": "uuid",
    "attack_type": "DDoS",
    "severity": "CRITICAL",
    "risk_score": 94
  }
}
```

Do not put secrets or excessive sensitive data into WebSocket events.

Authenticate the WebSocket connection.

---

# 24. SECURITY REQUIREMENTS

## 24.1 Authentication

Implement:

* Argon2id password hashing
* short-lived access tokens (JWT, 15-minute expiry by default)
* secure refresh mechanism (separate refresh token, longer-lived)
* brute-force/rate-limit protection on all login endpoints
* token validation (signature, expiry, issuer)
* secure logout/session invalidation

Never:

* store plaintext passwords
* store passwords in frontend state
* put tokens in URLs
* log authentication tokens

---

## 24.2 Token Management

Access tokens:

* short-lived (default 15 minutes)
* signed with `JWT_SECRET`
* must include: `sub` (user ID), `role`, `exp`, `iat`, `jti`
* stored in memory only on the client — never in `localStorage`

Refresh tokens:

* longer-lived (default 7 days)
* signed with `JWT_REFRESH_SECRET`
* stored in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie
* invalidated on logout
* rotated on each successful refresh
* stored/tracked server-side to support revocation

Never:

* put access tokens or refresh tokens in API response bodies that persist to `localStorage`
* accept tokens that are expired, malformed, or have invalid signatures
* reuse a refresh token after it has been consumed (token rotation)

---

## 24.3 Session Invalidation

On logout:

* revoke the refresh token server-side
* clear the `HttpOnly` cookie
* the access token will naturally expire; do not rely on client-side deletion alone

On password change or privilege escalation:

* invalidate all existing refresh tokens for the user
* require re-authentication

Implement a token revocation store (Redis) to enable mid-lifetime access token invalidation for security-critical events.

---

## 24.4 Password Policy

Requirements:

* minimum 12 characters
* maximum 128 characters (never silently truncate)
* hash using Argon2id with recommended parameters
* reject passwords found in common breach lists where practical
* do not enforce overly restrictive character rules that encourage weaker passwords
* enforce policy server-side; client-side feedback is convenience only

On failed login:

* return a generic "Invalid credentials" message
* do not reveal whether the email exists
* apply rate limiting and account lockout policy

---

# 25. AUTHORIZATION

Enforce both:

1. function-level authorization
2. object-level authorization

Every protected action must follow:

```
authenticate
    ->
load resource
    ->
authorize
    ->
execute
```

Do not trust the client-supplied role.

Roles:

```
ADMIN
ANALYST
VIEWER
```

Default permissions:

```
Dashboard:
  ADMIN      YES
  ANALYST    YES
  VIEWER     YES

Investigate incidents:
  ADMIN      YES
  ANALYST    YES
  VIEWER     READ ONLY

Modify incidents:
  ADMIN      YES
  ANALYST    YES
  VIEWER     NO

Analyst feedback:
  ADMIN      YES
  ANALYST    YES
  VIEWER     NO

Activate model:
  ADMIN      YES
  ANALYST    NO
  VIEWER     NO

Manage users:
  ADMIN      YES
  ANALYST    NO
  VIEWER     NO

Audit logs:
  ADMIN      YES
  ANALYST    YES
  VIEWER     NO
```

---

# 26. SQL INJECTION DEFENSE

Use:

* SQLAlchemy ORM
* SQLAlchemy expressions
* bound parameters

Do NOT:

* concatenate user input into SQL
* interpolate SQL strings
* trust query parameters
* construct raw SQL from arbitrary filter expressions

If raw SQL is unavoidable, always bind user-provided values as parameters.

The database application account must use least privilege.

---

# 27. XSS DEFENSE

All analyst comments, incident descriptions, event messages, threat-intelligence metadata, and imported fields are untrusted.

Frontend rules:

* render data as text
* avoid raw HTML
* do not use `dangerouslySetInnerHTML` for normal application content
* sanitize any intentionally-supported rich text
* enforce a restrictive Content Security Policy

Backend rules:

* validate length
* normalize where needed
* reject unexpected content
* never assume database content is safe simply because it originated inside the application

---

# 28. COMMAND INJECTION DEFENSE

Avoid shell execution wherever possible.

Never place user input into:

* shell commands
* executable paths
* command-line arguments without validation
* dynamic scripts

Never use shell execution with arbitrary user input.

If a subprocess is absolutely required:

* invoke the executable directly
* pass arguments as an argument array
* validate each argument
* use a strict allowlist
* run with least privilege

---

# 29. PATH TRAVERSAL DEFENSE

Never use client-provided filenames directly for server filesystem operations.

Generate:

```
UUID + safe extension
```

Store user uploads outside executable/public directories.

Reject:

```
..
absolute paths
path separators where not required
unexpected file extensions
```

---

# 30. SSRF DEFENSE

Do not expose arbitrary URL-fetch functionality.

Threat-intelligence integrations must use:

* provider allowlist
* fixed approved base URLs
* HTTPS
* strict indicator validation
* controlled redirects
* connection timeouts
* response-size limits
* response schema validation

The client may submit:

```
IP
domain
hash
```

The client may NOT submit:

```
arbitrary provider URL
```

Outbound networking should be restricted at the infrastructure level where possible.

---

# 31. RATE LIMITING AND RESOURCE CONTROLS

Use Redis-backed rate limiting.

Suggested initial limits:

```
unauthenticated:
  10 requests/minute/IP

authenticated:
  120 requests/minute/user
```

Apply stricter endpoint-specific limits to:

```
/auth/login
/auth/refresh
/ingestion/upload
/ingestion/flows/batch
/detections/analyze
/threat-intel/enrich
/reports
```

These values are starting configuration, not immutable security constants.

Also enforce:

* maximum request body size
* maximum CSV size
* maximum JSON depth/size
* maximum number of flow records per batch
* maximum page size = 100
* maximum report date range
* maximum concurrent ML jobs
* job timeouts
* queue backpressure

---

# 32. FILE UPLOAD SECURITY

Supported formats:

```
CSV
JSON
```

Workflow:

```
Receive
  ->
Authenticate
  ->
Authorize
  ->
Size check
  ->
Type check
  ->
Filename discarded
  ->
UUID filename
  ->
Quarantine
  ->
Parse
  ->
Schema validation
  ->
Process
```

Never execute uploaded content.

Never assume MIME type alone is trustworthy.

---

# 33. THIRD-PARTY RESPONSE SECURITY

Treat all external API responses as untrusted.

Validate:

* HTTP status
* Content-Type
* response size
* JSON structure
* expected fields
* field types
* string sizes
* nesting/depth
* numerical ranges

Never render third-party HTML directly.

Never trust third-party verdicts as unconditional truth.

---

# 34. SECRET MANAGEMENT

## Required environment variables

Example categories:

```
DATABASE_URL
REDIS_URL

JWT_SECRET
JWT_REFRESH_SECRET

VIRUSTOTAL_API_KEY
ABUSEIPDB_API_KEY

ADMIN_BOOTSTRAP_SECRET
MODEL_SIGNING_KEY
```

## Rules

1. Never hardcode secrets.
2. Never commit real `.env` files.
3. Commit `.env.example` with placeholders only.
4. Never put secrets in frontend source code.
5. Never expose secrets in API responses.
6. Never log secrets.
7. Never put secrets into Docker images.
8. Keep development and production credentials separate.
9. Support credential rotation.
10. Prefer runtime secret injection for production.
11. Do not store provider API keys in the database unless an explicit encrypted secret-management design exists.
12. Audit administrative secret/configuration changes.
13. Immediately rotate a credential if it is accidentally committed or exposed.

---

# 35. .GITIGNORE REQUIREMENTS

Ensure the repository ignores:

```
.env
.env.*
__pycache__/
*.pyc
node_modules/
dist/
build/
.pytest_cache/
.mypy_cache/
coverage/
local database files
IDE metadata
generated reports
temporary uploads
```

If an environment-specific file is intentionally committed, explicitly allow only the safe template.

---

# 36. LOGGING RULES

Use structured JSON logs.

Every application request should have a request ID.

Useful fields:

```
timestamp
request_id
user_id
action
resource
result
source_ip
```

Never log:

```
passwords
access tokens
refresh tokens
Authorization headers
API keys
database passwords
secret environment variables
```

Use a log-redaction layer.

---

# 37. ERROR HANDLING

Client-facing errors MUST be safe.

Return:

```
code
safe message
request_id
```

Do not return:

* Python traceback
* SQL statements
* database credentials
* filesystem paths
* environment values
* provider API keys
* internal stack information

Detailed diagnostics should remain in protected server logs.

---

# 38. SECURITY HEADERS

Configure appropriate application/reverse-proxy headers, including:

```
Content-Security-Policy
X-Content-Type-Options
Referrer-Policy
Strict-Transport-Security
clickjacking protection
```

Do not blindly use a permissive Content Security Policy.

---

# 39. INPUT VALIDATION STANDARD

Every value crossing a trust boundary is untrusted.

Validation must happen before business processing.

Pipeline:

```
receive
  ->
parse
  ->
normalize
  ->
validate syntax
  ->
validate semantics
  ->
authorize
  ->
process
```

---

# 40. VALIDATION RULES

## Email

* valid email structure
* maximum length
* normalize consistently
* do not expose whether an account exists where that information is sensitive

## Password

* minimum security policy
* sensible maximum length
* never truncate silently
* hash using Argon2id
* never log

## UUID

Use strict UUID parsing.

## IP address

Use a standard IP parser.

Support IPv4/IPv6 only where explicitly intended.

## Port

```
integer
1 <= port <= 65535
```

## Protocol

Allowlist only supported protocol values.

Example:

```
TCP
UDP
ICMP
```

## Severity

Allowlist:

```
LOW
MEDIUM
HIGH
CRITICAL
```

## Incident status

Allowlist:

```
OPEN
INVESTIGATING
CONTAINED
RESOLVED
FALSE_POSITIVE
```

## Search query

* bounded length
* no direct SQL fragments
* no dynamic expression syntax
* escape/render safely

## Dates

* ISO-8601
* parse into timezone-aware UTC timestamps
* validate start <= end
* apply maximum allowed range

## Scores

Confidence:

```
0 <= confidence <= 1
```

Risk:

```
0 <= risk_score <= 100
```

Anomaly score:

```
validate against the model-specific expected range
```

## Strings

Every user-facing text field must have:

* maximum length
* appropriate minimum length where needed
* Unicode-safe handling
* no executable interpretation

Use plain text unless rich text is an explicit requirement.

---

# 41. ML SECURITY

Protect against:

* corrupted datasets
* poisoned training data
* accidental model replacement
* incompatible feature schemas
* untested model deployment

Every model must have:

```
name
semantic version
algorithm
artifact identifier
checksum
feature schema
training timestamp
evaluation metrics
status
creator
activation record
```

Model lifecycle:

```
TRAINED
   ->
EVALUATED
   ->
APPROVED
   ->
ACTIVE
   ->
RETIRED
```

> Note: The lifecycle does NOT include a separate REGISTERED stage.
> A model moves directly from APPROVED to ACTIVE upon manual admin activation.

Do not automatically activate newly trained models.

---

# 42. RISK ENGINE

Keep risk scoring separate from the ML model.

Inputs may include:

```
ML confidence
anomaly score
attack severity
threat-intelligence context
historical context
```

Output:

```
risk_score = 0..100
```

Then map risk to:

```
LOW
MEDIUM
HIGH
CRITICAL
```

The calculation must be:

* deterministic
* documented
* unit-tested
* configurable
* auditable

Do not distribute hard-coded weighting logic across unrelated files.

---

# 43. INCIDENT CORRELATION

A detection does not necessarily equal an incident.

Conceptual workflow:

```
detection
   |
   v
correlation/rules
   |
   +---- existing related incident --> attach detection
   |
   +---- no matching incident ------> create incident
```

The implementation should avoid producing excessive duplicate incidents for the same underlying activity.

---

# 44. FRONTEND UI REQUIREMENTS

The frontend should present SENTINEL-X as a SOC-style security platform.

Primary pages:

```
/login
/dashboard
/live-monitoring
/threats
/threats/:id
/incidents
/incidents/:id
/network
/ai-analysis
/threat-intelligence
/models
/reports
/audit-logs
/settings
```

## Dashboard must contain

* overall security score
* active threats
* critical incidents
* traffic volume
* attack distribution
* threat timeline
* suspicious source list
* recent incidents
* live status

## Incident page must contain

* severity
* status
* assignee
* incident description
* attack timeline
* source/target visualization
* linked detections
* ML prediction
* confidence
* explainability
* threat intelligence
* analyst notes
* action history

## 44.1 Theme & Color Palette Specification (Strict)

The frontend MUST implement a custom dark-mode SOC theme using Tailwind CSS with the following exact color tokens:

- **Primary Background (Jet Black):** `#0A0A0A` (main app background, layout canvas, chart backgrounds)
- **Card / Surface Background:** `#121216` with `1px solid #1E293B` subtle borders
- **Primary Brand & Telemetry Accent (Cerulean Blue):** `#007BA7` (primary interactive buttons, active navigation state, normal network traffic charts, healthy status indicators, clean network nodes)
- **Critical Threat & Anomaly Accent (Neon Rose):** `#FF2D95` (CRITICAL/HIGH severity badges, live WebSocket threat alerts, anomaly detection spikes, malicious source-to-target edges in React Flow, top contributing SHAP feature bars)
- **Typography:** `#F8FAFC` for primary headings/data and `#94A3B8` for muted labels

Rules for UI Generation:
1. Never use light-mode backgrounds.
2. Configure these exact hex values in `tailwind.config.ts` (or CSS theme variables) under `colors.soc`:
   - `soc-black: '#0A0A0A'`
   - `soc-surface: '#121216'`
   - `soc-cerulean: '#007BA7'`
   - `soc-rose: '#FF2D95'`
3. Use `#007BA7` and `#FF2D95` directly inside Recharts (`stroke`/`fill`) and React Flow node/edge styles for visual consistency.

---

# 45. IMPLEMENTATION MILESTONES

Implementation MUST happen sequentially.

Do not begin advanced frontend work before the backend foundation and schema are stable.

---

# MILESTONE 1 — BACKEND SETUP

## Objective

Create the backend foundation and development environment.

### Tasks

1. Initialize Python project.
2. Configure FastAPI.
3. Configure Pydantic settings.
4. Configure SQLAlchemy.
5. Configure Alembic.
6. Configure PostgreSQL connection.
7. Configure Redis connection.
8. Configure Celery.
9. Add structured logging.
10. Add request ID middleware.
11. Add centralized exception handling.
12. Add CORS configuration.
13. Add security headers.
14. Add basic health endpoints.
15. Create `.env.example`.
16. Create Docker development setup.
17. Establish backend linting/type-check/test tooling.

### Acceptance criteria

```
GET /health/live
GET /health/ready
```

must work.

Application must fail safely when required configuration is missing.

No secrets committed.

---

# MILESTONE 2 — DATABASE MIGRATION

## Objective

Implement the complete relational schema.

### Tasks

1. Create SQLAlchemy models.
2. Create relationships.
3. Add constraints.
4. Add indexes.
5. Generate Alembic migration.
6. Run migration against clean PostgreSQL database.
7. Add seed roles.
8. Add safe admin bootstrap script.
9. Test migration from empty database.
10. Test rollback where appropriate.

### Acceptance criteria

The database can be created from zero using migrations only.

All tables and foreign-key relationships exist correctly.

No application code depends on manually created tables.

---

# MILESTONE 3 — CORE LOGIC

## Objective

Implement business and security logic before exposing the majority of the API.

### Tasks

1. Implement authentication service.
2. Implement password hashing.
3. Implement token/session handling.
4. Implement authorization policy.
5. Implement rate limiting.
6. Implement validation utilities.
7. Implement ingestion service.
8. Implement ML inference abstraction.
9. Implement feature-processing pipeline.
10. Implement classifier integration.
11. Implement anomaly detector integration.
12. Implement risk engine.
13. Implement SHAP explanation layer.
14. Implement incident correlation.
15. Implement threat-intelligence provider abstraction.
16. Implement provider response validation.
17. Implement audit-log service.
18. Implement report service abstraction.

### Acceptance criteria

Core services can be tested without HTTP.

Authorization decisions are unit-tested.

Invalid input is rejected.

Risk calculations are deterministic and tested.

ML prediction can be mocked for service tests.

Threat-intelligence provider failure does not break detection.

---

# MILESTONE 4 — API LAYER

## Objective

Expose stable, documented REST/WebSocket interfaces.

### Tasks

1. Implement auth routes.
2. Implement dashboard routes.
3. Implement ingestion routes.
4. Implement detection routes.
5. Implement incident routes.
6. Implement threat-intelligence routes.
7. Implement model routes.
8. Implement report routes.
9. Implement user/admin routes.
10. Implement WebSocket dashboard.
11. Add request validation.
12. Add authentication dependencies.
13. Add authorization dependencies.
14. Add endpoint-specific rate limits.
15. Add safe error responses.
16. Add OpenAPI documentation.
17. Add consistent pagination.

### Acceptance criteria

Every protected endpoint rejects unauthorized access.

Every restricted operation performs server-side authorization.

Invalid request bodies receive validation errors.

Rate limits work.

OpenAPI schema accurately reflects implemented endpoints.

No endpoint leaks secrets or internal exceptions.

---

# MILESTONE 5 — FRONTEND UI

## Objective

Build a professional SOC dashboard on top of the stable API.

### Tasks

1. Initialize React + TypeScript + Vite.
2. Configure Tailwind.
3. Create global design system.
4. Implement authentication screen.
5. Implement route guards.
6. Implement dashboard layout.
7. Implement sidebar navigation.
8. Implement KPI cards.
9. Implement threat charts.
10. Implement live monitoring.
11. Implement threat table.
12. Implement threat-detail page.
13. Implement incident list.
14. Implement incident investigation page.
15. Implement source-to-target visualization.
16. Implement ML explanation visualization.
17. Implement threat-intelligence panel.
18. Implement model registry page.
19. Implement report page.
20. Implement audit-log page.
21. Implement settings page.
22. Integrate WebSocket events.
23. Add loading/error/empty states.
24. Add responsive behavior.

### UI security requirements

* do not store secrets in frontend source
* do not render untrusted HTML
* do not trust frontend role checks as authorization
* use API authorization as the authoritative control
* do not put sensitive tokens in URLs
* do not expose backend internal errors directly

### Acceptance criteria

A user can authenticate.

Dashboard displays real backend data.

Live detection events update the dashboard.

Incident investigation displays related information.

Unauthorized UI actions are hidden where appropriate, but backend authorization remains mandatory.

---

# MILESTONE 6 — INTEGRATION TESTS

## Objective

Verify the entire platform as a working secure system.

### Test layers

```
Unit tests
    +
API integration tests
    +
Database integration tests
    +
Security tests
    +
End-to-end tests
```

---

# 46. REQUIRED SECURITY TESTS

## Authentication tests

Verify:

* invalid credentials rejected
* brute-force controls activate
* expired tokens rejected
* malformed tokens rejected
* refresh/session invalidation works
* logout invalidates the appropriate session

## Authorization tests

Verify:

* VIEWER cannot activate models
* VIEWER cannot modify incidents
* ANALYST cannot manage users
* unauthorized object access is blocked
* admin-only routes are protected

## Injection tests

Verify:

* SQL injection payloads are treated as data
* HTML/script payloads are rendered safely
* command-like strings never become executable
* path traversal payloads are rejected

## SSRF tests

Verify:

* arbitrary URLs cannot be submitted
* provider allowlist works
* only approved destinations are contacted
* invalid indicators are rejected
* provider failures are handled safely

## Rate-limit tests

Verify:

* repeated login attempts are limited
* ingestion abuse is limited
* threat-intelligence abuse is limited
* report-generation abuse is limited

## File-upload tests

Test:

* oversized file
* unsupported extension
* malformed CSV
* malformed JSON
* invalid schema
* path traversal filename
* executable content
* empty file
* huge row/column count

## Secret-leak tests

Verify:

* secrets do not appear in API responses
* secrets do not appear in logs
* `.env` is not committed
* frontend bundle does not contain backend credentials
* Docker image does not contain runtime secrets

---

# 47. END-TO-END DEMONSTRATION FLOW

The final system should support this complete demonstration:

```
1.  Analyst logs in
      |
2.  Opens SOC Dashboard
      |
3.  Uploads controlled network-flow dataset
      |
4.  System validates and queues ingestion
      |
5.  ML worker processes flows
      |
6.  Classification + anomaly detection execute
      |
7.  Risk engine calculates scores
      |
8.  SHAP explanation is generated
      |
9.  Suspicious indicators are enriched
      |
10. Detection appears on dashboard
      |
11. Correlation creates/updates incident
      |
12. WebSocket pushes live alert
      |
13. Analyst opens incident
      |
14. Analyst reviews:
      - attack type
      - confidence
      - risk
      - explanation
      - source/target
      - threat intelligence
      - timeline
      |
15. Analyst marks verdict/updates incident
      |
16. Audit log records action
      |
17. Analyst generates security report
```

This flow should work using controlled/simulated project data and must not require attacking real external systems.

---

# 48. PRODUCTION-QUALITY DEFINITION OF DONE

A feature is NOT complete merely because it works in a browser.

A feature is complete only when:

```
code exists
  +
validation exists
  +
authorization exists
  +
error handling exists
  +
logging exists
  +
audit behavior exists where relevant
  +
tests exist
  +
documentation is updated
```

---

# 49. CODING AGENT RULES

The autonomous coding agent MUST:

1. Read this file before modifying the project.
2. Preserve the architecture unless a change is explicitly justified.
3. Prefer the simplest implementation satisfying the requirement.
4. Avoid speculative dependencies.
5. Avoid introducing a new library when an existing dependency can solve the problem cleanly.
6. Keep secrets out of source control.
7. Write tests alongside security-sensitive functionality.
8. Never disable authentication/authorization merely to make a test pass.
9. Never bypass validation for convenience.
10. Never expose stack traces in normal API responses.
11. Never use arbitrary URL fetching for threat intelligence.
12. Never use shell execution with user-controlled input.
13. Never use dynamic SQL with string interpolation.
14. Never render untrusted HTML.
15. Use migrations for schema changes.
16. Preserve backward compatibility of API contracts when feasible.
17. Update documentation when architecture changes.
18. Record TODOs for deliberately deferred functionality.
19. Prefer typed interfaces across frontend/backend boundaries.
20. Never silently weaken a security control to solve a functional issue.

---

# 50. IMPLEMENTATION ORDER

The agent MUST follow this order:

```
PHASE 1
Backend Setup
    ->
PHASE 2
Database Migration
    ->
PHASE 3
Core Logic
    ->
PHASE 4
API Layer
    ->
PHASE 5
Frontend UI
    ->
PHASE 6
Integration Tests
    ->
PHASE 7
Security Hardening
    ->
PHASE 8
Final Demo/Documentation
```

Do not skip directly from project initialization to frontend implementation.

---

# 51. FINAL ARCHITECTURE

```
Browser
   |
   | HTTPS
   v
Nginx / Reverse Proxy
   |
   v
React + TypeScript
   |
   | REST / WebSocket
   v
FastAPI
   |
   +-------------------+
   |                   |
   v                   v
Services            Auth/RBAC
   |
   +------------------+-------------------+
   |                  |                   |
   v                  v                   v
PostgreSQL          Redis             ML Layer
   |                  |                   |
   |                  v                   v
   |               Celery             Predictor
   |                                     |
   |                                     +-- Classifier
   |                                     +-- Anomaly Detector
   |                                     +-- SHAP
   |
   +-----------------------------------------+
                     |
                     v
              Threat Intelligence
                /            \
               v              v
          VirusTotal      AbuseIPDB
```

The application must remain functional when the external threat-intelligence providers are unavailable.

---

# 52. PRIMARY ENGINEERING GOAL

The final product should behave as a coherent security platform rather than a collection of disconnected demonstrations.

The architectural chain is:

```
Secure Input
    ->
Authentication
    ->
Authorization
    ->
Rate Limiting
    ->
Data Ingestion
    ->
Feature Engineering
    ->
ML Detection
    ->
Anomaly Detection
    ->
Risk Scoring
    ->
Explainable AI
    ->
Threat Intelligence
    ->
Incident Correlation
    ->
Real-Time SOC Dashboard
    ->
Analyst Investigation
    ->
Audit Trail
    ->
Security Reporting
```

Every layer must be independently testable, observable, and replaceable where practical.
