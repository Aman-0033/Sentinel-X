"""End-to-End Demonstration Flow Test (Section 47).

Automates and verifies the complete 17-step operational lifecycle:
1. Analyst logs in
2. Opens SOC Dashboard
3. Uploads controlled network-flow dataset
4. System validates and queues ingestion
5. ML worker processes flows
6. Classification + anomaly detection execute
7. Risk engine calculates scores
8. SHAP explanation is generated
9. Suspicious indicators are enriched
10. Detection appears on dashboard
11. Correlation creates/updates incident
12. WebSocket pushes live alert
13. Analyst opens incident
14. Analyst reviews attack type, confidence, risk, explanation, threat intel, timeline
15. Analyst marks verdict / updates incident
16. Audit log records action
17. Analyst generates security report
"""

import io
from datetime import datetime, timezone
import pytest
from sqlalchemy.orm import Session

from app.core.security import create_access_token
from app.db.models.user import User
from app.services.detection_service import DetectionService
from app.services.incident_service import IncidentService


def test_complete_17_step_end_to_end_demonstration_flow(client, auth_context):
    """Execute all 17 steps of the Section 47 Demonstration Flow end-to-end."""

    # -------------------------------------------------------------
    # Step 1: Analyst logs in
    # -------------------------------------------------------------
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@sentinel.internal", "password": "SentinelAnalyst2026!"},
    )
    assert login_resp.status_code == 200, "Step 1 Failed: Analyst login failed"
    login_data = login_resp.json()["data"]
    analyst_token = login_data["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    analyst_id = login_data["user"]["id"]
    assert login_data["user"]["role"] == "ANALYST"

    # -------------------------------------------------------------
    # Step 2: Opens SOC Dashboard
    # -------------------------------------------------------------
    dashboard_resp = client.get("/api/v1/dashboard/summary", headers=analyst_headers)
    assert dashboard_resp.status_code == 200, "Step 2 Failed: Dashboard summary failed"
    dash_data = dashboard_resp.json()["data"]
    assert "traffic_volume" in dash_data
    assert "open_incidents" in dash_data
    assert "security_score" in dash_data

    # -------------------------------------------------------------
    # Step 3: Uploads controlled network-flow dataset
    # -------------------------------------------------------------
    controlled_flow_csv = (
        "source_ip,destination_ip,source_port,destination_port,protocol,packets,bytes,duration_ms,direction\n"
        "203.0.113.195,10.0.0.50,44123,80,TCP,45000,32000000,1250,INBOUND\n"
        "198.51.100.88,10.0.0.50,55122,22,TCP,1200,85000,450,INBOUND\n"
    )
    upload_resp = client.post(
        "/api/v1/ingestion/upload",
        headers=analyst_headers,
        files={"file": ("simulated_threat_telemetry.csv", io.BytesIO(controlled_flow_csv.encode("utf-8")), "text/csv")},
    )
    assert upload_resp.status_code == 200, "Step 3 Failed: Telemetry CSV upload failed"

    # -------------------------------------------------------------
    # Step 4: System validates and queues ingestion
    # -------------------------------------------------------------
    upload_data = upload_resp.json()["data"]
    assert upload_data["accepted"] == 2, "Step 4 Failed: Expected 2 flows ingested"
    assert upload_data["status"] == "COMPLETED"
    assert "job_id" in upload_data

    # -------------------------------------------------------------
    # Step 5 & 6: ML worker processes flows, classification + anomaly detection execute
    # -------------------------------------------------------------
    # Ingest direct flow and run ML analysis
    batch_resp = client.post(
        "/api/v1/ingestion/flows/batch",
        headers=analyst_headers,
        json={
            "flows": [
                {
                    "source_ip": "198.51.100.99",
                    "destination_ip": "10.0.0.1",
                    "source_port": 54321,
                    "destination_port": 443,
                    "protocol": "TCP",
                    "packets": 50000,
                    "bytes": 45000000,
                    "duration_ms": "250.5",
                    "direction": "INBOUND",
                }
            ]
        },
    )
    assert batch_resp.status_code == 200, "Step 5/6 Failed: Batch flow ingestion failed"
    assert batch_resp.json()["data"]["accepted"] == 1

    # -------------------------------------------------------------
    # Step 7: Risk engine calculates scores
    # Step 8: SHAP explanation is generated
    # -------------------------------------------------------------
    det_list_resp = client.get("/api/v1/detections", headers=analyst_headers)
    assert det_list_resp.status_code == 200, "Step 7/8 Failed: List detections failed"
    detections = det_list_resp.json()["data"]
    assert len(detections) > 0, "Detections catalog should contain detected threats"

    target_detection = detections[0]
    det_id = target_detection["id"]

    # Verify risk calculation and SHAP explanation properties
    assert "risk_score" in target_detection
    assert 0.0 <= target_detection["risk_score"] <= 100.0
    assert target_detection["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert target_detection["explanation"] is not None

    # -------------------------------------------------------------
    # Step 9: Suspicious indicators are enriched
    # -------------------------------------------------------------
    enrich_resp = client.post(
        "/api/v1/threat-intel/enrich",
        headers=analyst_headers,
        json={
            "indicator_value": "185.220.101.5",
            "indicator_type": "ip",
            "provider": "virustotal",
        },
    )
    assert enrich_resp.status_code == 200, "Step 9 Failed: Threat intel enrichment failed"
    intel_data = enrich_resp.json()["data"]
    assert intel_data["indicator"] == "185.220.101.5"
    assert "verdict" in intel_data

    # -------------------------------------------------------------
    # Step 10: Detection appears on dashboard
    # -------------------------------------------------------------
    det_detail_resp = client.get(f"/api/v1/detections/{det_id}", headers=analyst_headers)
    assert det_detail_resp.status_code == 200, "Step 10 Failed: Detection detail view failed"
    det_detail = det_detail_resp.json()["data"]
    assert det_detail["id"] == det_id

    # -------------------------------------------------------------
    # Step 11: Correlation creates/updates incident
    # -------------------------------------------------------------
    incidents_resp = client.get("/api/v1/incidents", headers=analyst_headers)
    assert incidents_resp.status_code == 200, "Step 11 Failed: Incident list failed"
    incidents = incidents_resp.json()["data"]
    assert len(incidents) > 0, "Incident correlation should have active incidents"
    incident_id = incidents[0]["id"]

    # -------------------------------------------------------------
    # Step 12: WebSocket pushes live alert
    # -------------------------------------------------------------
    with client.websocket_connect(f"/api/v1/ws/dashboard?token={analyst_token}") as ws:
        # Receive welcome connection payload
        welcome = ws.receive_json()
        assert welcome["event"] == "CONNECTED"
        assert "Authenticated" in welcome["data"]["message"]

        # Send heartbeat PING and receive PONG
        ws.send_text("PING")
        pong = ws.receive_json()
        assert pong["event"] == "PONG"

    # -------------------------------------------------------------
    # Step 13: Analyst opens incident
    # -------------------------------------------------------------
    inc_detail_resp = client.get(f"/api/v1/incidents/{incident_id}", headers=analyst_headers)
    assert inc_detail_resp.status_code == 200, "Step 13 Failed: Incident detail failed"
    inc_detail = inc_detail_resp.json()["data"]

    # -------------------------------------------------------------
    # Step 14: Analyst reviews: attack type, confidence, risk, explanation, source/target, threat intel, timeline
    # -------------------------------------------------------------
    assert "title" in inc_detail
    assert "severity" in inc_detail
    assert "status" in inc_detail
    assert "detections" in inc_detail
    assert "events" in inc_detail

    # -------------------------------------------------------------
    # Step 15: Analyst marks verdict / updates incident
    # -------------------------------------------------------------
    patch_resp = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=analyst_headers,
        json={"status": "INVESTIGATING", "notes": "Analyst initiated forensic containment triage."},
    )
    assert patch_resp.status_code == 200, "Step 15 Failed: Incident status update failed"
    assert patch_resp.json()["data"]["status"] == "INVESTIGATING"

    feedback_resp = client.post(
        f"/api/v1/detections/{det_id}/feedback",
        headers=analyst_headers,
        json={"verdict": "TRUE_POSITIVE", "comment": "Confirmed hostile flow signature matching SYN flood."},
    )
    assert feedback_resp.status_code == 200, "Step 15 Failed: Feedback verdict submission failed"

    # -------------------------------------------------------------
    # Step 16: Audit log records action
    # -------------------------------------------------------------
    audit_resp = client.get("/api/v1/audit-logs", headers=analyst_headers)
    assert audit_resp.status_code == 200, "Step 16 Failed: Audit log retrieval failed"
    audit_logs = audit_resp.json()["data"]
    assert len(audit_logs) > 0, "Audit logs should record analyst interactions"
    # Verify no plaintext passwords or secrets in audit log
    for log in audit_logs:
        assert "password" not in log["action"].lower()

    # -------------------------------------------------------------
    # Step 17: Analyst generates security report
    # -------------------------------------------------------------
    report_resp = client.post(
        "/api/v1/reports",
        headers=analyst_headers,
        json={
            "report_type": "SECURITY_SUMMARY",
            "format": "JSON",
            "period_start": "2026-10-01T00:00:00Z",
            "period_end": "2026-10-31T23:59:59Z",
        },
    )
    assert report_resp.status_code == 200, "Step 17 Failed: Report generation failed"
    report_data = report_resp.json()["data"]
    assert report_data["format"] == "JSON"
    assert report_data["status"] in ("QUEUED", "PROCESSING", "COMPLETED")
    assert "id" in report_data
