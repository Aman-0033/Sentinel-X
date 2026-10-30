"""Unit tests for RequestIdMiddleware."""


def test_request_id_generated_when_omitted(client):
    """Verify an X-Request-ID header is generated and returned when not provided."""
    response = client.get("/health/live")
    assert response.status_code == 200
    assert "x-request-id" in response.headers
    request_id = response.headers["x-request-id"]
    assert len(request_id) >= 16


def test_request_id_propagated_when_valid(client):
    """Verify a valid client-supplied X-Request-ID is retained and echoed."""
    custom_id = "soc-incident-audit-req-001"
    response = client.get("/health/live", headers={"X-Request-ID": custom_id})
    assert response.status_code == 200
    assert response.headers["x-request-id"] == custom_id
    data = response.json()
    assert data["meta"]["request_id"] == custom_id


def test_request_id_replaced_when_malformed(client):
    """Verify an invalid or malicious X-Request-ID (e.g. CRLF injection attempt) is replaced."""
    malicious_id = "invalid\r\nHeader-Injection: true"
    response = client.get("/health/live", headers={"X-Request-ID": malicious_id})
    assert response.status_code == 200
    returned_id = response.headers["x-request-id"]
    assert returned_id != malicious_id
    assert "\r" not in returned_id
    assert "\n" not in returned_id
