# Sentinel-X Security: Security Requirements Specification

## 1. Guiding Principles & Standards

Sentinel-X is designed and constructed according to industry-standard cybersecurity engineering principles:
1. **Defense-in-Depth**: Layered security controls across Network (Nginx/WAF), Application (FastAPI/Pydantic), Broker (Redis ACLs), and Persistence (PostgreSQL RBAC).
2. **Principle of Least Privilege (PoLP)**: Users, database connections, and worker containers run with the minimum capabilities required for operational function.
3. **Fail-Secure Architecture**: When an exception, parse error, or validation failure occurs, the system defaults to an explicit denial state rather than permissive continuation.
4. **Zero-Secret Exposure**: No credentials, tokens, or encryption keys are committed to source control or exposed in API payloads/logs.

---

## 2. Authentication Requirements (REQ-AUTH)

- **REQ-AUTH-01 (Password Complexity)**: Passwords must be at least 12 characters in length, containing at least one uppercase letter, one lowercase letter, one digit, and one special character (`!@#$%^&*()_+-=`).
- **REQ-AUTH-02 (Password Hashing)**: Passwords must be hashed using the **Argon2id** algorithm (`time_cost=3`, `memory_cost=64MB`, `parallelism=4`). MD5, SHA-1, and plain SHA-256 are strictly prohibited.
- **REQ-AUTH-03 (Token Lifespan)**: Access tokens must be signed JWTs (HS256) with a maximum lifetime of 15 minutes (`900 seconds`).
- **REQ-AUTH-04 (Refresh Token Security)**: Refresh tokens must be stored in HTTP cookies configured with `HttpOnly=True`, `Secure=True`, and `SameSite=Strict`. Refresh tokens expire in 7 days.
- **REQ-AUTH-05 (Refresh Rotation & Replay Revocation)**: Every refresh request generates a new refresh token and invalidates the previous one. Replay of an invalidated refresh token triggers automatic termination of all active sessions for that account.
- **REQ-AUTH-06 (Brute Force Protection)**: Authentication attempts are rate-limited to 5 failures per 60 seconds per IP address. Continued failures trigger exponential backoff.
- **REQ-AUTH-07 (Immediate Revocation)**: On `/auth/logout`, the active JWT token ID (`jti`) is added to the Redis blacklist cache with an expiration matching the token's remaining TTL.

---

## 3. Authorization & Access Control Requirements (REQ-AUTHZ)

- **REQ-AUTHZ-01 (Role Hierarchy)**: The platform enforces three distinct RBAC tiers:
  1. `ADMIN`: Full administrative control, user provisioning, model promotion, global audit log access.
  2. `ANALYST`: Telemetry upload, threat investigation, incident status modification, feedback submission, report generation.
  3. `VIEWER`: Read-only visibility into dashboards, alerts, metrics, and incident listings.
- **REQ-AUTHZ-02 (Server-Side Enforcement)**: Frontend navigation gates are purely cosmetic; all authorizations must be verified cryptographically on every API invocation via backend dependency injection (`RoleChecker`).
- **REQ-AUTHZ-03 (Audit Access Restriction)**: The `/api/v1/audit-logs` endpoint must strictly forbid access to users with role `VIEWER`, returning HTTP 403 `AUTHORIZATION_DENIED`.

---

## 4. Input Validation & Data Sanitization Requirements (REQ-INP)

- **REQ-INP-01 (Schema Validation)**: 100% of incoming JSON payloads must be validated against strict Pydantic schemas with `extra="forbid"`.
- **REQ-INP-02 (Path Traversal Prevention)**: Uploaded filenames must be sanitized to strip relative directory sequences (`../`, `..\\`) and replaced with server-side UUIDv4 identifiers before persistence.
- **REQ-INP-03 (Magic Byte Inspection)**: File ingestion must inspect the first 16 bytes (magic numbers) of uploaded binaries. Executable headers (`MZ`, `\x7fELF`, `\xca\xfe\xba\xbe`, `#!/bin/`) must be rejected with HTTP 400.
- **REQ-INP-04 (CSV Injection Neutralization)**: Any formula control prefix (`=`, `+`, `-`, `@`) in ingested CSV text fields must be sanitized by prepending a single quote (`'`).
- **REQ-INP-05 (SSRF Protection)**: All network enrichment lookups must validate target IP addresses using Python's `ipaddress` library, explicitly blocking private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and reserved documentation subnets (`198.51.100.0/24`).

---

## 5. Transport & Network Security Requirements (REQ-NET)

- **REQ-NET-01 (TLS Enforcement)**: All client-to-server traffic must be encrypted via TLS 1.3 or TLS 1.2 with strong cipher suites (`ECDHE-ECDSA-AES256-GCM-SHA384`).
- **REQ-NET-02 (Security Headers)**: Nginx reverse proxy and FastAPI middleware must emit the following HTTP response headers:
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- **REQ-NET-03 (Cross-Origin Resource Sharing)**: CORS must be explicitly restricted to the designated frontend origin; wildcard `*` origins are strictly forbidden in authenticated routes.

---

## 6. Audit & Logging Requirements (REQ-AUD)

- **REQ-AUD-01 (Immutable Audit Logging)**: All security-sensitive operations (login, logout, user creation, incident triage, feedback submission, model promotion) must produce an append-only entry in `audit_logs`.
- **REQ-AUD-02 (Secret Redaction)**: Structured logging formatters must scrub bearer tokens, passwords, API keys, and sensitive financial tokens from log statements using regex substitution (`redact_data()`).
- **REQ-AUD-03 (Traceability)**: Every HTTP request must be assigned a unique `X-Request-ID` (UUIDv4) that is logged across all application and worker logs for forensic correlation.
