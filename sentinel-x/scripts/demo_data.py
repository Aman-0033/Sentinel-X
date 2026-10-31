"""Populate the Sentinel-X database with realistic SOC demo telemetry (Section 47)."""

import argparse
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Ensure backend root is in sys.path
backend_dir = Path(__file__).resolve().parents[1] / "backend"
if not backend_dir.exists():
    backend_dir = Path(__file__).resolve().parents[0] / "sentinel-x" / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.security import get_password_hash
from app.db.models.analyst_feedback import AnalystFeedback
from app.db.models.data_source import DataSource
from app.db.models.detection import Detection
from app.db.models.incident import Incident
from app.db.models.incident_detection import IncidentDetection
from app.db.models.incident_event import IncidentEvent
from app.db.models.model_version import ModelVersion
from app.db.models.network_flow import NetworkFlow
from app.db.models.role import Role
from app.db.models.threat_intel import ThreatIntelEnrichment
from app.db.models.user import User
from app.ml.feature_engineering.features import FEATURE_NAMES
from app.services.risk_service import calculate_risk_score
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker


def seed_demo_data(db_url: str | None = None, session: Session | None = None) -> None:
    """Populate database with complete end-to-end SOC security telemetry."""
    close_db = False
    if session is not None:
        db = session
    else:
        if not db_url:
            try:
                from app.core.config import get_settings

                db_url = get_settings().DATABASE_URL
            except Exception:  # noqa: BLE001
                db_url = "sqlite:///sentinel_dev.db"

        print(f"Connecting to database: {db_url}")
        engine = create_engine(db_url)
        session_factory = sessionmaker(bind=engine)
        db = session_factory()
        close_db = True

    try:
        now = datetime.now(UTC)

        # 1. Seed Roles
        roles = {}
        for role_name in ["ADMIN", "ANALYST", "VIEWER"]:
            role = db.query(Role).filter(Role.name == role_name).first()
            if not role:
                role = Role(
                    id=str(uuid.uuid4()),
                    name=role_name,
                    description=f"{role_name} role",
                )
                db.add(role)
                db.flush()
            roles[role_name] = role

        # 2. Seed Users
        demo_users = [
            (
                "admin@sentinel.internal",
                "SentinelAdmin2026!",
                "Chief SOC Officer",
                "ADMIN",
            ),
            (
                "analyst@sentinel.internal",
                "SentinelAnalyst2026!",
                "Tier 2 Threat Analyst",
                "ANALYST",
            ),
            (
                "viewer@sentinel.internal",
                "SentinelViewer2026!",
                "Compliance Auditor",
                "VIEWER",
            ),
            (
                "admin@sentinel.local",
                "SentinelAdmin2026!",
                "Chief SOC Officer",
                "ADMIN",
            ),
            (
                "analyst@sentinel.local",
                "SentinelAnalyst2026!",
                "Tier 2 Threat Analyst",
                "ANALYST",
            ),
        ]
        users = {}
        for email, pwd, name, r_name in demo_users:
            user = db.query(User).filter(User.email == email).first()
            if not user:
                user = User(
                    id=str(uuid.uuid4()),
                    email=email,
                    password_hash=get_password_hash(pwd),
                    full_name=name,
                    role_id=roles[r_name].id,
                    is_active=True,
                )
                db.add(user)
                db.flush()
            users[r_name] = user

        # 3. Seed Data Sources
        source = db.query(DataSource).first()
        if not source:
            source = DataSource(
                id=str(uuid.uuid4()),
                name="Perimeter Core Gateway",
                source_type="LIVE_COLLECTOR",
                description="Perimeter Core Gateway simulator",
                configuration={"ip_address": "10.0.0.1"},
                created_by=users["ADMIN"].id,
            )
            db.add(source)
            db.flush()

        # 4. Seed Active Model Version
        active_model = (
            db.query(ModelVersion).filter(ModelVersion.status == "ACTIVE").first()
        )
        if not active_model:
            active_model = ModelVersion(
                id=str(uuid.uuid4()),
                name="SENTINEL-XGBoost",
                version="1.0.0",
                algorithm="XGBoost + IsolationForest",
                artifact_uri="models/sentinel_xgb_v1.joblib",
                checksum="dc3919fab54b38e5f1b8a3294194b88502f562cb30bb621775b8df5f2fbc254a",
                feature_schema={"feature_names": FEATURE_NAMES},
                metrics={"precision": 1.0, "recall": 1.0, "f1_score": 1.0},
                status="ACTIVE",
                trained_at=now,
                created_by=users["ADMIN"].id,
                created_at=now,
            )
            db.add(active_model)
            db.flush()

        # 5. Check if demo flows are already populated for idempotency
        if db.query(NetworkFlow).first():
            db.commit()
            print("Demo telemetry already present.")
            return

        # 6. Seed Telemetry Flows & Detections
        attacks = [
            (
                "203.0.113.45",
                "10.0.0.25",
                48921,
                22,
                "TCP",
                180,
                24000,
                "Brute Force",
                0.96,
                "HIGH",
            ),
            (
                "198.51.100.22",
                "10.0.0.80",
                52140,
                80,
                "TCP",
                25000,
                15000000,
                "DDoS",
                0.99,
                "CRITICAL",
            ),
            (
                "192.0.2.14",
                "10.0.0.50",
                41234,
                4444,
                "TCP",
                12,
                1800,
                "Malware C2",
                0.88,
                "HIGH",
            ),
            (
                "203.0.113.99",
                "10.0.0.10",
                33100,
                8080,
                "TCP",
                4,
                160,
                "Port Scan",
                0.91,
                "MEDIUM",
            ),
            (
                "192.168.1.55",
                "10.0.0.80",
                50123,
                443,
                "TCP",
                30,
                4500,
                "Benign",
                0.99,
                "LOW",
            ),
            (
                "192.168.1.101",
                "10.0.0.80",
                54321,
                443,
                "TCP",
                22,
                3800,
                "Benign",
                0.98,
                "LOW",
            ),
            (
                "192.168.1.102",
                "10.0.0.53",
                49152,
                53,
                "UDP",
                4,
                256,
                "Benign",
                0.97,
                "LOW",
            ),
            (
                "198.51.100.77",
                "10.0.0.25",
                60123,
                22,
                "TCP",
                350,
                48000,
                "Brute Force",
                0.94,
                "HIGH",
            ),
            (
                "192.0.2.88",
                "10.0.0.100",
                38920,
                80,
                "TCP",
                18000,
                11000000,
                "DDoS",
                0.98,
                "CRITICAL",
            ),
            (
                "192.168.1.200",
                "10.0.0.80",
                58120,
                443,
                "TCP",
                45,
                6200,
                "Benign",
                0.99,
                "LOW",
            ),
        ]

        detections = []
        for (
            src_ip,
            dst_ip,
            s_port,
            d_port,
            proto,
            pkts,
            bytes_cnt,
            atk,
            conf,
            sev,
        ) in attacks:
            flow_time = now - timedelta(minutes=15)
            flow = NetworkFlow(
                id=str(uuid.uuid4()),
                source_id=source.id,
                timestamp=flow_time,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=s_port,
                destination_port=d_port,
                protocol=proto,
                packets=pkts,
                bytes=bytes_cnt,
                duration_ms=1200.0,
                direction="INBOUND",
            )
            db.add(flow)
            db.flush()

            # Calculate deterministic risk score
            risk_eval = calculate_risk_score(
                atk, confidence=conf, is_anomaly=(atk != "Benign")
            )

            det = Detection(
                id=str(uuid.uuid4()),
                flow_id=flow.id,
                model_version_id=active_model.id,
                attack_type=atk,
                confidence=conf,
                anomaly_score=0.85 if atk != "Benign" else 0.10,
                risk_score=risk_eval.risk_score,
                severity=risk_eval.severity,
                is_anomaly=(atk != "Benign"),
                explanation={
                    "prediction": atk,
                    "method": "SHAP-TreeExplainer",
                    "important_factors": [
                        {
                            "feature": "failed_connection_ratio",
                            "value": 0.85,
                            "importance": 0.35,
                            "direction": "positive",
                        },
                        {
                            "feature": "request_frequency",
                            "value": 45.0,
                            "importance": 0.28,
                            "direction": "positive",
                        },
                    ],
                },
                detected_at=flow_time,
            )
            db.add(det)
            db.flush()
            detections.append((det, src_ip, atk))

            # Add threat intel for external IPs
            if not src_ip.startswith("192.168."):
                enrich = ThreatIntelEnrichment(
                    id=str(uuid.uuid4()),
                    detection_id=det.id,
                    indicator_type="ip",
                    indicator_value=src_ip,
                    provider="virustotal",
                    reputation_score=85.0 if atk != "Benign" else 0.0,
                    verdict="MALICIOUS" if atk != "Benign" else "CLEAN",
                    country="US",
                    asn=15169,
                    checked_at=now,
                )
                db.add(enrich)

        # 6. Seed Incidents with linked detections and timeline events
        # Incident 1: Brute Force
        inc1 = Incident(
            id=str(uuid.uuid4()),
            title="Brute Force activity detected from 203.0.113.45",
            description="Repeated SSH authentication failures and abnormal connection velocity.",
            severity="HIGH",
            status="INVESTIGATING",
            assigned_to=users["ANALYST"].id,
            created_by=users["ADMIN"].id,
            created_at=now - timedelta(hours=1),
            updated_at=now - timedelta(minutes=10),
        )
        db.add(inc1)
        db.flush()

        # Link Brute Force detection
        db.add(
            IncidentDetection(
                incident_id=inc1.id, detection_id=detections[0][0].id, linked_at=now
            )
        )
        db.add(
            IncidentEvent(
                id=str(uuid.uuid4()),
                incident_id=inc1.id,
                event_type="INCIDENT_CREATED",
                message="Incident created via automated correlation engine.",
                created_at=now - timedelta(hours=1),
            )
        )
        db.add(
            IncidentEvent(
                id=str(uuid.uuid4()),
                incident_id=inc1.id,
                event_type="ANALYST_ASSIGNED",
                message=f"Assigned to {users['ANALYST'].full_name}.",
                actor_id=users["ADMIN"].id,
                created_at=now - timedelta(minutes=45),
            )
        )

        # Incident 2: DDoS
        inc2 = Incident(
            id=str(uuid.uuid4()),
            title="DDoS volumetric flood from 198.51.100.22",
            description="Massive packet volume targeting port 80 perimeter ingress.",
            severity="CRITICAL",
            status="OPEN",
            created_by=users["ADMIN"].id,
            created_at=now - timedelta(minutes=20),
            updated_at=now - timedelta(minutes=20),
        )
        db.add(inc2)
        db.flush()

        db.add(
            IncidentDetection(
                incident_id=inc2.id, detection_id=detections[1][0].id, linked_at=now
            )
        )
        db.add(
            IncidentEvent(
                id=str(uuid.uuid4()),
                incident_id=inc2.id,
                event_type="INCIDENT_CREATED",
                message="Incident created via automated correlation engine. Severity CRITICAL.",
                created_at=now - timedelta(minutes=20),
            )
        )

        # 7. Seed Analyst Feedback
        feedback = AnalystFeedback(
            id=str(uuid.uuid4()),
            detection_id=detections[0][0].id,
            analyst_id=users["ANALYST"].id,
            verdict="TRUE_POSITIVE",
            comment="Confirmed SSH password spraying from external proxy node.",
            created_at=now - timedelta(minutes=30),
        )
        db.add(feedback)

        db.commit()
        print("Demo data seeded successfully!")
        print("Demo Credentials:")
        print("  Admin:   admin@sentinel.internal   / SentinelAdmin2026!")
        print("  Analyst: analyst@sentinel.internal / SentinelAnalyst2026!")
        print("  Viewer:  viewer@sentinel.internal  / SentinelViewer2026!")

    finally:
        if close_db:
            db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed Sentinel-X demo database")
    parser.add_argument("--db-url", type=str, default=None)
    args = parser.parse_args()
    seed_demo_data(args.db_url)
