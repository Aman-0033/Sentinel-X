# Sentinel-X REST & Real-Time API Specification

## 1. Overview & Protocol Architecture

Sentinel-X exposes an enterprise-grade RESTful API alongside WebSocket streams for real-time telemetry and threat alerts. The API is powered by **FastAPI** (Python 3.12) and conforms to OpenAPI 3.1.0 specifications.

### Key Conventions
- **Base URL**: `/api/v1`
- **Transport**: HTTPS (TLS 1.3/1.2) enforced via Nginx reverse proxy
- **Content-Type**: `application/json` (except file uploads which use `multipart/form-data`)
- **Authentication**: Stateless Bearer tokens (JWT) in `Authorization: Bearer <token>`
- **Session Refresh**: Secure `HttpOnly`, `SameSite=Strict`, `Secure` cookie named `refresh_token`
- **Correlation ID**: Every request produces or accepts `X-Request-ID` (UUID4) propagated in response headers and log context.

---

## 2. Standard Response Envelope

All API endpoints return a deterministic JSON envelope adhering to the following structure:

### Success Response (`200 OK`, `201 Created`, `202 Accepted`)
```json
{
  "status": "success",
  "data": { ... },
  "meta": {
    "timestamp": "2026-10-31T05:00:00.000Z",
    "request_id": "c748db1a-ad20-4547-a8fb-ff48c78ac2eb",
    "pagination": {
      "page": 1,
      "page_size": 25,
      "total_items": 1420,
      "total_pages": 57
    }
  }
}
```

### Error Response (`400`, `401`, `403`, `404`, `422`, `429`, `500`)
```json
{
  "status": "error",
  "data": null,
  "error": {
    "code": "AUTHORIZATION_DENIED",
    "message": "User role VIEWER does not possess required privilege: incident:modify",
    "details": {
      "required_roles": ["ADMIN", "ANALYST"],
      "user_role": "VIEWER"
    }
  },
  "meta": {
    "timestamp": "2026-10-31T05:00:00.000Z",
    "request_id": "c748db1a-ad20-4547-a8fb-ff48c78ac2eb"
  }
}
```

---

## 3. Standard Error Code Taxonomy

| Error Code | HTTP Status | Description |
|:---|:---:|:---|
| `UNAUTHENTICATED` | 401 | Missing, malformed, expired, or revoked Bearer token. |
| `INVALID_CREDENTIALS` | 401 | Email not found or Argon2id password hash verification failed. |
| `TOKEN_EXPIRED` | 401 | Access token `exp` timestamp in the past; trigger token refresh. |
| `AUTHORIZATION_DENIED` | 403 | Authenticated user lacks RBAC role permissions for operation. |
| `RESOURCE_NOT_FOUND` | 404 | Targeted entity ID does not exist in PostgreSQL. |
| `VALIDATION_ERROR` | 422 | Pydantic schema validation failure or invalid payload format. |
| `RATE_LIMIT_EXCEEDED` | 429 | Redis sliding window token bucket threshold exceeded. |
| `SSRF_BLOCKED` | 400 | Inbound or outbound network address is reserved, private, or loopback. |
| `MALICIOUS_PAYLOAD` | 400 | File upload contains executable magic bytes or forbidden structure. |
| `INTERNAL_SERVER_ERROR`| 500 | Unhandled server exception (masked details; logged securely). |

---

## 4. Endpoints Specification

### 4.1 Authentication Service (`/api/v1/auth`)

#### `POST /api/v1/auth/login`
Authenticates user credentials, sets refresh cookie, and returns short-lived access token.
- **Rate Limit**: 5 attempts per 60s per client IP.
- **Request Body**:
  ```json
  {
    "email": "analyst@sentinel.internal",
    "password": "SentinelAnalyst2026!"
  }
  ```
- **Response Headers**: `Set-Cookie: refresh_token=...; HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth`
- **Response Data (`200 OK`)**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "bearer",
    "expires_in": 900,
    "user": {
      "id": "u-a1b2c3d4-e5f6-7890",
      "email": "analyst@sentinel.internal",
      "full_name": "Senior SOC Analyst",
      "role": "ANALYST",
      "is_active": true
    }
  }
  ```

#### `POST /api/v1/auth/refresh`
Exchanges rotating `refresh_token` cookie for a fresh access token and newly rotated refresh cookie.
- **Replay Protection**: If a previously consumed refresh token is presented, all refresh tokens for that user session are invalidated immediately.
- **Response Data (`200 OK`)**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "bearer",
    "expires_in": 900
  }
  ```

#### `POST /api/v1/auth/logout`
Blacklists active access token in Redis cache and revokes refresh token session.
- **Auth**: Bearer token required.
- **Response Data (`200 OK`)**:
  ```json
  {
    "message": "Successfully logged out"
  }
  ```

#### `GET /api/v1/auth/me`
Retrieves currently authenticated user profile and permissions.
- **Auth**: Bearer token required.
- **Response Data (`200 OK`)**:
  ```json
  {
    "id": "u-a1b2c3d4-e5f6-7890",
    "email": "analyst@sentinel.internal",
    "full_name": "Senior SOC Analyst",
    "role": "ANALYST",
    "last_login_at": "2026-10-31T04:45:12.000Z"
  }
  ```

---

### 4.2 Ingestion Service (`/api/v1/ingestion`)

#### `POST /api/v1/ingestion/upload`
Uploads raw network packet captures (PCAP) or tabular flow records (CSV/JSON) for validation and asynchronous ML scoring.
- **Auth**: Roles `[ADMIN, ANALYST]`
- **Content-Type**: `multipart/form-data`
- **Form Fields**:
  - `file`: Binary file content (max 100MB).
  - `source_name`: String identifier (e.g. `perimeter-tap-01`).
- **Security Validations**:
  - Magic byte rejection: Rejects `MZ` (PE), `\x7fELF` (ELF), `\xca\xfe\xba\xbe` (Java Mach-O), `#!/bin/` (Scripts).
  - Column count limit: Maximum 100 columns to mitigate CSV bomb DoS.
- **Response Data (`202 Accepted`)**:
  ```json
  {
    "batch_id": "batch-88e2-4521-9fa1",
    "filename": "perimeter_capture_20261031.csv",
    "status": "QUEUED",
    "record_count": 5000,
    "celery_task_id": "task-7b3c4d5e"
  }
  ```

---

### 4.3 Detections & AI Explainability (`/api/v1/detections`)

#### `GET /api/v1/detections`
Lists detected threat events with filtering, sorting, and pagination.
- **Auth**: Roles `[ADMIN, ANALYST, VIEWER]`
- **Query Parameters**:
  - `page` (default: 1), `page_size` (default: 25, max: 100)
  - `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`)
  - `classification` (`DDoS`, `PortScan`, `BruteForce`, `Botnet`, `Benign`)
  - `start_date`, `end_date` (ISO-8601 strings)
- **Response Data (`200 OK`)**: Array of detection records with model confidence, anomaly scores, and risk ratings.

#### `GET /api/v1/detections/{id}/shap`
Retrieves local feature attribution values generated by TreeSHAP for this specific detection.
- **Auth**: Roles `[ADMIN, ANALYST, VIEWER]`
- **Response Data (`200 OK`)**:
  ```json
  {
    "detection_id": "det-99321",
    "base_value": 0.042,
    "prediction_score": 0.984,
    "top_features": [
      { "feature": "flow_packets_per_second", "value": 48210.5, "shap_value": +0.412 },
      { "feature": "syn_flag_ratio", "value": 0.998, "shap_value": +0.320 },
      { "feature": "avg_packet_size", "value": 40.0, "shap_value": +0.185 }
    ]
  }
  ```

#### `POST /api/v1/detections/{id}/feedback`
Allows analysts to submit ground-truth feedback (False Positive / True Positive) to trigger ML active learning drift queues.
- **Auth**: Roles `[ADMIN, ANALYST]`
- **Request Body**:
  ```json
  {
    "feedback_type": "FALSE_POSITIVE",
    "corrected_label": "Benign",
    "comment": "Scheduled vulnerability scanner scan from internal IP 10.0.50.25"
  }
  ```
- **Response Data (`200 OK`)**:
  ```json
  {
    "feedback_id": "fb-4412",
    "status": "RECORDED",
    "detection_id": "det-99321"
  }
  ```

---

### 4.4 Incident Management (`/api/v1/incidents`)

#### `GET /api/v1/incidents`
Lists correlated multi-stage security incidents.
- **Auth**: Roles `[ADMIN, ANALYST, VIEWER]`
- **Query Parameters**: `status` (`OPEN`, `INVESTIGATING`, `CONTAINED`, `CLOSED`), `severity`, `page`, `page_size`

#### `PATCH /api/v1/incidents/{id}/status`
Transitions an incident across lifecycle stages and triggers an immutable audit log entry.
- **Auth**: Roles `[ADMIN, ANALYST]`
- **Request Body**:
  ```json
  {
    "status": "CONTAINED",
    "comment": "Firewall block rule deployed on border gateway for IP 185.220.101.5"
  }
  ```
- **Response Data (`200 OK`)**: Updated incident entity with lifecycle timeline.

---

### 4.5 Threat Intelligence Service (`/api/v1/threat-intel`)

#### `POST /api/v1/threat-intel/lookup`
Performs threat intelligence enrichment for an indicator of compromise (IP, domain, hash).
- **Auth**: Roles `[ADMIN, ANALYST, VIEWER]`
- **SSRF Defense**: Strictly rejects private, reserved, loopback, or cloud-metadata IPs.
- **Request Body**:
  ```json
  {
    "indicator": "185.220.101.5",
    "indicator_type": "IP"
  }
  ```
- **Response Data (`200 OK`)**:
  ```json
  {
    "indicator": "185.220.101.5",
    "reputation_score": 95,
    "verdict": "MALICIOUS",
    "threat_actor": "Tor Exit Node / Scanner",
    "last_seen": "2026-10-31T03:12:00.000Z"
  }
  ```

---

### 4.6 Reporting Service (`/api/v1/reports`)

#### `POST /api/v1/reports/generate`
Queues asynchronous generation of PDF/JSON executive or compliance security reports.
- **Auth**: Roles `[ADMIN, ANALYST]`
- **Rate Limit**: 10 report requests per minute per IP.
- **Request Body**:
  ```json
  {
    "report_type": "SECURITY_SUMMARY",
    "format": "JSON",
    "period_start": "2026-10-01T00:00:00Z",
    "period_end": "2026-10-31T23:59:59Z"
  }
  ```
- **Response Data (`200 OK` or `202 Accepted`)**:
  ```json
  {
    "report_id": "rep-2026-10-31-01",
    "title": "Security Summary Report",
    "status": "COMPLETED",
    "download_url": "/api/v1/reports/rep-2026-10-31-01/download"
  }
  ```

---

### 4.7 Audit Logging Service (`/api/v1/audit-logs`)

#### `GET /api/v1/audit-logs`
Provides queryable access to tamper-evident system audit records.
- **Auth**: Strict RBAC `[ADMIN, ANALYST]` (Forbidden to `VIEWER`).
- **Query Parameters**: `user_id`, `action`, `status`, `page`, `page_size`
- **Response Data (`200 OK`)**:
  ```json
  {
    "items": [
      {
        "id": "aud-9012",
        "user_id": "u-a1b2c3d4-e5f6-7890",
        "user_email": "analyst@sentinel.internal",
        "action": "INCIDENT_STATUS_CHANGE",
        "resource_type": "incident",
        "resource_id": "inc-104",
        "status": "SUCCESS",
        "ip_address": "127.0.0.1",
        "timestamp": "2026-10-31T05:01:22.000Z"
      }
    ]
  }
  ```

---

### 4.8 Real-Time Alert WebSocket (`/api/v1/ws/alerts`)

- **Protocol**: `wss://` (or `ws://` in development)
- **Authentication**: JWT token passed via subprotocol or query parameter `?token=<access_token>`.
- **Payload Schema**:
  ```json
  {
    "type": "NEW_CRITICAL_DETECTION",
    "timestamp": "2026-10-31T05:02:10.120Z",
    "payload": {
      "detection_id": "det-99322",
      "severity": "CRITICAL",
      "classification": "DDoS",
      "risk_score": 98.5,
      "source_ip": "185.220.101.5",
      "destination_ip": "10.0.0.4",
      "packet_count": 850000
    }
  }
  ```

