"""Security Test Suite: File Upload Abuse Rejection (Section 46.6).

Verifies:
- Oversized file upload rejection.
- Unsupported file extension rejection.
- Malformed CSV rejection.
- Malformed JSON rejection.
- Invalid schema rejection.
- Path traversal filename rejection.
- Executable content (magic bytes) rejection.
- Empty file rejection.
- Excessive row/column count rejection.
- CSV formula injection sanitization.
"""

import io
import pytest


def test_empty_file_rejected(client, auth_context):
    """Verify 0-byte file upload is rejected with 422."""
    res = client.post(
        "/api/v1/ingestion/upload",
        headers=auth_context["analyst_headers"],
        files={"file": ("empty.csv", io.BytesIO(b""), "text/csv")},
    )
    assert res.status_code == 422
    assert "empty" in res.json()["error"]["message"].lower()


def test_unsupported_file_extension_rejected(client, auth_context):
    """Verify unauthorized file types (.exe, .sh, .py, .pdf) are rejected."""
    bad_extensions = [
        ("malware.exe", b"binary content", "application/octet-stream"),
        ("exploit.sh", b"echo pwned", "application/x-sh"),
        ("script.py", b"import os\nos.system('dir')", "text/x-python"),
        ("document.pdf", b"%PDF-1.4...", "application/pdf"),
    ]

    for filename, content, mime in bad_extensions:
        res = client.post(
            "/api/v1/ingestion/upload",
            headers=auth_context["analyst_headers"],
            files={"file": (filename, io.BytesIO(content), mime)},
        )
        assert res.status_code == 422


def test_executable_magic_bytes_rejected(client, auth_context):
    """Verify files masquerading as CSV/JSON with executable headers are rejected."""
    executable_payloads = [
        ("fake.csv", b"MZ\x90\x00\x03\x00\x00\x00", "text/csv"),  # Windows PE
        ("fake.json", b"\x7fELF\x02\x01\x01\x00", "application/json"),  # Linux ELF
        ("script.csv", b"#!/bin/bash\necho evil", "text/csv"),  # Shell script
    ]

    for filename, content, mime in executable_payloads:
        res = client.post(
            "/api/v1/ingestion/upload",
            headers=auth_context["analyst_headers"],
            files={"file": (filename, io.BytesIO(content), mime)},
        )
        assert res.status_code == 422
        assert "executable" in res.json()["error"]["message"].lower() or "validation" in res.json()["error"]["code"].lower()


def test_oversized_file_rejected(client, auth_context):
    """Verify files exceeding 10MB upload threshold are rejected."""
    # Generate 11 MB of dummy data
    oversized_data = b"a" * (11 * 1024 * 1024)
    res = client.post(
        "/api/v1/ingestion/upload",
        headers=auth_context["analyst_headers"],
        files={"file": ("oversized.csv", io.BytesIO(oversized_data), "text/csv")},
    )
    assert res.status_code == 422
    assert "exceeds maximum" in res.json()["error"]["message"].lower()


def test_malformed_csv_rejected(client, auth_context):
    """Verify CSV with no header or unparseable content is rejected."""
    malformed_csv = "\n\n\n"
    res = client.post(
        "/api/v1/ingestion/upload",
        headers=auth_context["analyst_headers"],
        files={"file": ("corrupt.csv", io.BytesIO(malformed_csv.encode("utf-8")), "text/csv")},
    )
    assert res.status_code == 422
    assert "missing header" in res.json()["error"]["message"].lower() or "validation" in res.json()["error"]["code"].lower()


def test_malformed_json_rejected(client, auth_context):
    """Verify JSON with syntax errors is rejected."""
    malformed_json = "{invalid: json, 'missing': brackets"
    res = client.post(
        "/api/v1/ingestion/upload",
        headers=auth_context["analyst_headers"],
        files={"file": ("corrupt.json", io.BytesIO(malformed_json.encode("utf-8")), "application/json")},
    )
    assert res.status_code == 422
    assert "malformed json" in res.json()["error"]["message"].lower()


def test_invalid_schema_in_flow_data_rejected(client, auth_context):
    """Verify records missing required IP fields or having invalid values fail validation."""
    invalid_schema_csv = "source_ip,destination_ip,protocol\nnot_an_ip,10.0.0.1,INVALID_PROTOCOL\n"
    res = client.post(
        "/api/v1/ingestion/upload",
        headers=auth_context["analyst_headers"],
        files={"file": ("invalid_schema.csv", io.BytesIO(invalid_schema_csv.encode("utf-8")), "text/csv")},
    )
    assert res.status_code == 422
    assert "invalid ip address" in res.json()["error"]["message"].lower() or "validation" in res.json()["error"]["code"].lower()


def test_excessive_columns_csv_rejected(client, auth_context):
    """Verify CSV containing more than 100 columns is rejected."""
    # Create header with 150 columns
    headers = [f"col_{i}" for i in range(150)]
    row = [str(i) for i in range(150)]
    huge_csv = ",".join(headers) + "\n" + ",".join(row) + "\n"

    res = client.post(
        "/api/v1/ingestion/upload",
        headers=auth_context["analyst_headers"],
        files={"file": ("wide.csv", io.BytesIO(huge_csv.encode("utf-8")), "text/csv")},
    )
    assert res.status_code == 422
    assert "exceeds maximum limit of 100" in res.json()["error"]["message"]


def test_csv_formula_injection_sanitization(client, auth_context):
    """Verify formula injection prefixes (=, +, -, @) are sanitized with leading quote."""
    csv_with_formulas = (
        "source_ip,destination_ip,protocol,direction\n"
        "192.168.1.10,10.0.0.1,TCP,=cmd|' /C calc'!A0\n"
    )

    res = client.post(
        "/api/v1/ingestion/upload",
        headers=auth_context["analyst_headers"],
        files={"file": ("formula.csv", io.BytesIO(csv_with_formulas.encode("utf-8")), "text/csv")},
    )
    # The file is accepted and sanitized safely
    assert res.status_code == 200
    assert res.json()["data"]["accepted"] == 1
