# Sentinel-X: BCA Minor Project Defense & Viva Voce Guide

## 1. Project Elevator Pitch (The 60-Second Overview)

> "Examiners, **Sentinel-X** is an enterprise-grade AI-powered Security Operations Center (SOC) and Network Threat Intelligence platform. Traditional Intrusion Detection Systems rely heavily on static signature matching, which fails against zero-day threats and polymorphic malware. 
> 
> Sentinel-X solves this by combining **supervised machine learning (XGBoost)** for known attack classification with **unsupervised anomaly detection (Isolation Forests)** for novel zero-day discovery. Crucially, to solve the 'black-box' problem of AI in cybersecurity, Sentinel-X integrates **Explainable AI (TreeSHAP)** to provide analysts with real-time, mathematical feature attributions explaining *why* an alert was triggered. The platform is built as a hardened modular monolith using FastAPI, PostgreSQL 16, Redis, Celery, and a modern React TypeScript frontend, protected by rigorous defense-in-depth controls including Argon2id password hashing, refresh token rotation, and SSRF prevention."

---

## 2. Core Architectural & Technology Decisions

### Q: Why FastAPI instead of Django or Flask?
- **Asynchronous Concurrency**: Built on Starlette and `asyncio`, FastAPI handles high-concurrency I/O (such as WebSocket streaming and database pooling) with near-Go/Node.js throughput.
- **Type Safety & Data Validation**: Native Pydantic integration enforces strict schema validation at compile and runtime, drastically reducing injection attack surfaces.
- **Automatic OpenAPI 3.1 Documentation**: FastAPI natively compiles Swagger and OpenAPI specs directly from Python type hints, ensuring API contracts are always synchronized.

### Q: Why PostgreSQL 16 instead of MongoDB / NoSQL?
- **Relational Integrity**: Security operations require strict relational links between Users, Roles, Network Flows, Detections, Incidents, and Audit Logs. Foreign key cascading and check constraints prevent orphaned data.
- **ACID Compliance**: Audit trails and incident status transitions require strict transaction isolation (Read Committed / Serializable).
- **Hybrid Storage with JSONB**: PostgreSQL allows unstructured telemetry and TreeSHAP feature attributions to be stored as indexed `JSONB` without sacrificing relational rigor.

### Q: Why Celery and Redis for background processing?
- Network packet ingestion and machine learning inference are computationally expensive. Running them synchronously in the HTTP request loop would cause thread starvation and high latency.
- Celery distributes heavy ML pipelines across background worker pools, while Redis acts as a high-speed message broker, keeping REST API response times below 50ms.

---

## 3. Machine Learning & Explainable AI (XAI) Deep-Dive

### Q: What is the difference between Supervised and Unsupervised detection in Sentinel-X?
- **Supervised Classification (XGBoost)**: Trained on labeled attack data (e.g. CIC-IDS2017) to classify known threats: `DDoS`, `PortScan`, `BruteForce`, and `Botnet`. It outputs class probabilities and high confidence metrics ($> 95\%$).
- **Unsupervised Anomaly Detection (Isolation Forest)**: Assumes no prior knowledge of attack signatures. It isolates anomalies by randomly partitioning feature space. Points that isolate in fewer splits are flagged as anomalous, enabling the detection of **zero-day attacks**.

### Q: Why XGBoost over Deep Learning (e.g. CNNs or RNNs)?
- Tabular network telemetry (packet rates, byte sizes, flag ratios) performs statistically better on gradient-boosted decision trees (GBDT) than on deep neural networks.
- XGBoost has vastly lower inference latency ($< 50\mu\text{s}$ per record), lower RAM consumption, and natively supports TreeSHAP for exact feature attribution.

### Q: What is TreeSHAP and why is it essential for SOC analysts?
- **SHAP (SHapley Additive exPlanations)** is grounded in cooperative game theory. It calculates the optimal marginal contribution of each input feature to the model's final prediction score.
- **TreeSHAP** is an optimized algorithm for tree ensembles that computes exact Shapley values in polynomial time rather than exponential time.
- **SOC Value**: Instead of an opaque "DDoS detected (98%)" alert, Sentinel-X provides a waterfall chart:
  - `flow_packets_per_sec (+0.412)`
  - `syn_flag_ratio (+0.320)`
  - `avg_packet_size (-0.05)`
  This transparency allows analysts to verify threats instantly and prevents alert fatigue.

---

## 4. Cybersecurity Hardening & Defense-in-Depth

### Q: How is password storage secured?
- Plaintext, MD5, SHA-1, and basic SHA-256 are completely rejected.
- We utilize **Argon2id** (`time_cost=3`, `memory_cost=64MB`, `parallelism=4`). Argon2id provides memory hardness to defeat GPU/ASIC brute-force clusters and protects against side-channel cache attacks.

### Q: What is Refresh Token Rotation and how does it stop replay attacks?
- When a client refreshes their access token using the `refresh_token` cookie, the backend invalidates that refresh token immediately and issues a new pair.
- If an adversary intercepts a previously used refresh token and attempts to replay it, Sentinel-X detects token reuse, immediately invalidates all active sessions for that user account, and alerts the SOC.

### Q: What is Server-Side Request Forgery (SSRF) and how did you prevent it?
- SSRF occurs when an attacker tricks the server into making HTTP requests to internal, non-routable infrastructure (e.g. cloud metadata `169.254.169.254` or internal microservices `10.0.0.1`).
- In `/threat-intel/lookup`, our system parses target IP addresses using Python's `ipaddress` module and strictly checks:
  ```python
  if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
      raise AppValidationError("Target IP belongs to a forbidden private or non-routable subnet")
  ```

### Q: How does Sentinel-X prevent file upload attacks?
1. **Size Limits**: Capped at 100MB to prevent disk exhaustion.
2. **Decompression / Column Limits**: Max 100 columns on CSV files.
3. **Magic Byte Verification**: Inspects file headers to ensure executables (`MZ`, `\x7fELF`, `\xca\xfe\xba\xbe`, `#!/bin/`) disguised as `.pcap` or `.csv` are rejected.
4. **Path Traversal Sanitization**: Filenames are stripped of path separators and stored under generated UUIDs.
5. **CSV Formula Injection**: Leading `=`, `+`, `-`, `@` characters are escaped with `'`.

---

## 5. Rapid-Fire Viva Voce Questions & High-Scoring Answers

### 1. What role does Docker and Nginx play in deployment?
> "Docker containers isolate our services (FastAPI app, Celery worker, PostgreSQL, Redis, React frontend). Nginx acts as our reverse proxy, TLS terminator, and first line of defense, enforcing HTTP security headers (HSTS, CSP, X-Frame-Options) and rate-limiting ingress connections before they touch the application layer."

### 2. What is the database schema structure?
> "The database comprises 13 normalized tables using UUID primary keys and UTC timestamps. Key entities include `users`, `roles`, `network_flows`, `detections`, `incidents`, `analyst_feedback`, and an append-only `audit_logs` table that tracks every administrative and analyst action."

### 3. How do you prevent SQL Injection if you have dynamic queries?
> "We use SQLAlchemy 2.0 ORM with 100% parameterized queries. Parameter values are sent separately from the SQL statement template over the binary protocol, making it mathematically impossible for user input to be interpreted as executable SQL syntax."

### 4. What happens when an analyst marks a detection as a False Positive?
> "The feedback is stored in the `analyst_feedback` table and linked to the detection event. An audit entry is recorded, and the misclassified sample is automatically queued for active learning to retrain and fine-tune future model versions."

### 5. Why do you use WebSockets instead of polling?
> "Polling creates unnecessary HTTP request overhead and server load. WebSockets provide a persistent, full-duplex TCP channel, allowing the backend to push critical threat detections to the analyst dashboard in real time with sub-millisecond latency."

---

## 6. Live Demonstration Flow (17 Steps to Present to Examiners)

1. **Login & Session Establishment**: Demonstrate authentication using seeded analyst credentials; inspect response headers showing the secure `HttpOnly` refresh cookie.
2. **System Health Verification**: View `/health` showing green status across Database, Redis, and ML pipeline.
3. **Telemetry Ingestion**: Upload a network capture containing malicious flows (`DDoS` and `PortScan`).
4. **Background Scoring**: Highlight Celery worker processing in the background without blocking the UI.
5. **Real-Time Alert Feed**: Show the alert appearing instantly via WebSocket.
6. **AI Explanation (TreeSHAP)**: Click into the detection to show the TreeSHAP waterfall chart explaining feature importance.
7. **Threat Intel Enrichment**: Perform an IP reputation query on the malicious actor IP.
8. **Incident Creation**: Correlate the detection into a formal security incident dossier.
9. **Status Transition**: Transition incident status to `INVESTIGATING`.
10. **Analyst Feedback**: Submit ground-truth feedback to demonstrate active learning integration.
11. **Containment**: Transition incident status to `CONTAINED`.
12. **Incident Closure**: Close incident with remediation notes.
13. **Executive Report Generation**: Queue generation of an automated security summary report.
14. **Report Download**: Download and view the compiled security report.
15. **Admin Login**: Switch to Administrator account (`admin@sentinel.internal`).
16. **Audit Trail Inspection**: Open `/audit-logs` to show the complete, immutable record of every action performed during the demo.
17. **Secure Logout**: Log out and show that access tokens are blacklisted in Redis and refresh cookies revoked.

