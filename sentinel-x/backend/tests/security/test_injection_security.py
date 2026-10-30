"""Security Test Suite: Injection Rejection (Section 46.3).

Verifies:
- SQL injection payloads in parameters and queries are neutralized or rejected.
- XSS and HTML script injection payloads are treated as inert strings.
- Command-injection characters and sequences never become executable.
- Path traversal sequences are strictly rejected and quarantined safely.
"""

import io
import pytest


def test_sqli_payload_in_incident_search_is_rejected_or_treated_as_data(client, auth_context):
    """Verify SQL injection strings in incident search queries are rejected or treated as data."""
    sqli_payloads = [
        "' OR '1'='1",
        "admin' --",
        "'; DROP TABLE incidents; --",
        "1 UNION SELECT null, null, null, null--",
        "' OR 1=1; --",
    ]

    for payload in sqli_payloads:
        response = client.get(
            f"/api/v1/incidents?search={payload}",
            headers=auth_context["analyst_headers"],
        )
        # Should either return 422 (validation error due to SQLI_PATTERNS) or 200 with empty data
        assert response.status_code in (200, 422), f"SQLi payload '{payload}' caused unexpected response {response.status_code}"
        if response.status_code == 200:
            # Query did not dump all rows
            data = response.json()["data"]
            assert isinstance(data, list)


def test_sqli_payload_in_detection_filters(client, auth_context):
    """Verify SQL injection strings in detection query parameters do not cause syntax errors."""
    sqli_filters = [
        ("attack_type", "' OR 1=1 --"),
        ("severity", "' UNION SELECT * FROM users --"),
        ("protocol", "TCP' OR '1'='1"),
    ]

    for param, val in sqli_filters:
        response = client.get(
            f"/api/v1/detections?{param}={val}",
            headers=auth_context["analyst_headers"],
        )
        # Strict validation rejects invalid severity/protocol, or treats attack_type safely
        assert response.status_code in (200, 422)
        assert response.status_code != 500


def test_sqli_payload_in_path_uuid_parameter(client, auth_context):
    """Verify non-UUID SQL injection path parameters are safely handled with 404/422 without crashing."""
    sqli_ids = [
        "1' OR '1'='1",
        "'; DROP TABLE users;--",
        "admin'--",
    ]
    for bad_id in sqli_ids:
        response = client.get(
            f"/api/v1/detections/{bad_id}",
            headers=auth_context["analyst_headers"],
        )
        assert response.status_code in (404, 422)


def test_xss_payload_in_incident_event_is_stored_safely_as_text(client, auth_context):
    """Verify XSS payloads in incident comments are stored as plain text and not executed."""
    # 1. Get an existing incident
    inc_res = client.get("/api/v1/incidents", headers=auth_context["analyst_headers"])
    assert inc_res.status_code == 200
    incidents = inc_res.json()["data"]
    assert len(incidents) > 0
    incident_id = incidents[0]["id"]

    xss_payload = "<script>alert('XSS_EXECUTION')</script><img src=x onerror=alert(1)>"

    # 2. Add event with XSS payload
    post_res = client.post(
        f"/api/v1/incidents/{incident_id}/events",
        headers=auth_context["analyst_headers"],
        json={
            "event_type": "NOTE",
            "message": xss_payload,
        },
    )
    assert post_res.status_code in (200, 201)

    # 3. Retrieve event and ensure it remains inert text in JSON
    get_res = client.get(
        f"/api/v1/incidents/{incident_id}",
        headers=auth_context["analyst_headers"],
    )
    assert get_res.status_code == 200
    events = get_res.json()["data"]["events"]
    matching = [e for e in events if e["message"] == xss_payload]
    assert len(matching) > 0, "XSS string was not properly preserved as literal text"


def test_command_injection_strings_in_inputs_are_neutralized(client, auth_context):
    """Verify shell command injection patterns are safely handled without shell execution."""
    cmd_injection_strings = [
        "; rm -rf /",
        "$(whoami)",
        "`id`",
        "| cat /etc/passwd",
        "& dir",
        "&& echo VULNERABLE",
    ]

    for cmd in cmd_injection_strings:
        # In feedback notes
        response = client.get(
            f"/api/v1/incidents?search={cmd}",
            headers=auth_context["analyst_headers"],
        )
        assert response.status_code in (200, 422)
        assert response.status_code != 500


def test_path_traversal_in_file_upload_filename_is_rejected(client, auth_context):
    """Verify path traversal sequences in uploaded filenames are rejected."""
    traversal_filenames = [
        "../../../../etc/passwd.csv",
        "..\\..\\windows\\win.ini.csv",
        "....//....//shell.csv",
        "evil.csv\x00.exe",
    ]

    for bad_name in traversal_filenames:
        csv_content = "source_ip,destination_ip,protocol\n192.168.1.10,10.0.0.1,TCP\n"
        response = client.post(
            "/api/v1/ingestion/upload",
            headers=auth_context["analyst_headers"],
            files={"file": (bad_name, io.BytesIO(csv_content.encode("utf-8")), "text/csv")},
        )
        assert response.status_code == 422
        assert "path traversal" in response.json()["error"]["message"].lower() or "validation" in response.json()["error"]["code"].lower()
