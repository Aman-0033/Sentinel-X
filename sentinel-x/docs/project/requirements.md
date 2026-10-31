# Sentinel-X: System Requirements Specification (SRS)

## 1. Project Background & Purpose

**Sentinel-X** is an AI-powered Security Operations Center (SOC) and Network Threat Intelligence Platform developed as a Bachelor of Computer Applications (BCA) Minor Project. The system bridges the gap between traditional rule-based Intrusion Detection Systems (IDS) and modern AI/ML-driven autonomous security analytics.

### Core Objectives
1. Ingest raw network packet captures and tabular NetFlow telemetry at scale.
2. Provide multi-stage threat detection utilizing both supervised machine learning (XGBoost) and unsupervised anomaly detection (Isolation Forest).
3. Deliver human-interpretable model decisions through Explainable AI (TreeSHAP) to eliminate "black-box" machine learning concerns in security operations.
4. Provide an enterprise-grade reactive analyst user interface adhering to cyber defense ergonomics and strict security boundaries.

---

## 2. Functional Requirements (FR)

| Req ID | Requirement Description | Implementation Details |
|:---|:---|:---|
| **FR-01** | **Multi-Format Telemetry Ingestion** | Support batch upload of PCAP, CSV, and JSON network records up to 100MB with automated file sanitization and magic byte validation. |
| **FR-02** | **Supervised Threat Classification** | Classify network flows into attack categories (`Benign`, `DDoS`, `PortScan`, `BruteForce`, `Botnet`) with confidence scores $> 0.95$. |
| **FR-03** | **Unsupervised Anomaly Detection** | Detect novel zero-day behavioral anomalies using Isolation Forests, outputting continuous anomaly scores $[-1.0, 1.0]$. |
| **FR-04** | **Explainable AI (TreeSHAP)** | Compute local feature importance for every alert, detailing exact statistical factors driving the AI classification. |
| **FR-05** | **Compound Risk Scoring** | Calculate normalized risk scores $[0, 100]$ using confidence, anomaly score, asset criticality, and threat severity. |
| **FR-06** | **Incident Correlation & Lifecycle** | Correlate individual detection events into unified incident dossiers, tracking states: `OPEN` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `CONTAINED` $\rightarrow$ `CLOSED`. |
| **FR-07** | **Threat Intelligence Enrichment** | Query external reputation indicators (AlienVault OTX / AbuseIPDB) with strict SSRF filtering on target IPs. |
| **FR-08** | **Real-Time SOC Alerting** | Deliver instantaneous threat notifications to connected analyst clients via secure WebSockets (`/api/v1/ws/alerts`). |
| **FR-09** | **Analyst Ground-Truth Feedback** | Permit authorized operators to submit feedback (True/False Positive) to detect model drift and trigger retraining. |
| **FR-10** | **Executive & Technical Reporting** | Compile PDF, JSON, and CSV executive summaries and forensic incident reports on demand. |

---

## 3. Non-Functional Requirements (NFR)

### 3.1 Performance (NFR-PERF)
- **NFR-PERF-01**: Average API latency for cached dashboard metrics and alert queries must remain below 100ms.
- **NFR-PERF-02**: Machine learning inference engine must process incoming feature batches with latency $< 50\mu\text{s}$ per flow record.
- **NFR-PERF-03**: Ingestion engine must sustain a throughput of at least 5,000 flows per second via Celery worker pools.

### 3.2 Security (NFR-SEC)
- **NFR-SEC-01**: Zero plaintext credentials stored anywhere in the database; Argon2id hashing enforced for all accounts.
- **NFR-SEC-02**: Stateless session authentication utilizing 15-minute HS256 JWT access tokens paired with rotating HttpOnly 7-day refresh cookies.
- **NFR-SEC-03**: Enforce Least Privilege Role-Based Access Control (RBAC) across `ADMIN`, `ANALYST`, and `VIEWER` tiers.
- **NFR-SEC-04**: 100% of state-mutating actions must generate an immutable, tamper-evident record in `audit_logs`.
- **NFR-SEC-05**: Strict defense against OWASP Top 10 vulnerabilities (SQLi, XSS, CSRF, SSRF, Path Traversal, Insecure Deserialization).

### 3.3 Reliability & Availability (NFR-REL)
- **NFR-REL-01**: Celery worker architecture ensures ingestion spikes do not starve the interactive REST API event loop.
- **NFR-REL-02**: Database integrity guaranteed via PostgreSQL ACID transactions and foreign key cascading.

### 3.4 Usability & Ergonomics (NFR-USE)
- **NFR-USE-01**: Professional SOC dark-mode aesthetic utilizing deep obsidian background (`#0A0A0A`), electric cyan (`#007BA7`), and hot pink alert accents (`#FF2D95`).
- **NFR-USE-02**: Fully responsive layout adapting seamlessly from 1080p desktop monitors to laptop screens.

