"""Integration tests for health endpoints.

Verifies Milestone 1 Acceptance Criteria:
- GET /health/live works and returns 200 OK.
- GET /health/ready works and checks database and Redis readiness.
- Fail-safe response behavior when dependencies are unreachable.
"""

from unittest.mock import patch


def test_get_health_live(client):
    """Verify GET /health/live returns 200 OK with valid Section 14 envelope."""
    response = client.get("/health/live")
    assert response.status_code == 200

    payload = response.json()
    assert payload["status"] == "healthy"
    assert payload["data"]["status"] == "live"
    assert payload["data"]["service"] == "Sentinel-X"
    assert "version" in payload["data"]
    assert "timestamp" in payload["data"]
    assert "meta" in payload
    assert "request_id" in payload["meta"]


def test_get_api_v1_health_live(client):
    """Verify GET /api/v1/health/live is also accessible and operational."""
    response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "healthy"
    assert payload["data"]["status"] == "live"


def test_get_health_ready_when_healthy(client):
    """Verify GET /health/ready returns 200 OK when DB and Redis are operational."""
    with (
        patch("app.api.v1.health.check_db_connection", return_value=True),
        patch("app.api.v1.health.check_redis_connection", return_value=True),
    ):
        response = client.get("/health/ready")
        assert response.status_code == 200

        payload = response.json()
        assert payload["status"] == "ready"
        assert payload["data"]["status"] == "ready"
        assert payload["data"]["dependencies"]["database"] == "connected"
        assert payload["data"]["dependencies"]["redis"] == "connected"
        assert "request_id" in payload["meta"]


def test_get_health_ready_when_database_down(client):
    """Verify GET /health/ready returns 503 with safe envelope when database is down."""
    with (
        patch("app.api.v1.health.check_db_connection", return_value=False),
        patch("app.api.v1.health.check_redis_connection", return_value=True),
    ):
        response = client.get("/health/ready")
        assert response.status_code == 503

        payload = response.json()
        assert payload["status"] == "not_ready"
        assert payload["data"]["dependencies"]["database"] == "disconnected"
        assert payload["data"]["dependencies"]["redis"] == "connected"
        assert "error" in payload
        assert payload["error"]["code"] == "SERVICE_UNAVAILABLE"
        assert "request_id" in payload["error"]


def test_get_health_ready_when_redis_down(client):
    """Verify GET /health/ready returns 503 with safe envelope when Redis is down."""
    with (
        patch("app.api.v1.health.check_db_connection", return_value=True),
        patch("app.api.v1.health.check_redis_connection", return_value=False),
    ):
        response = client.get("/health/ready")
        assert response.status_code == 503

        payload = response.json()
        assert payload["status"] == "not_ready"
        assert payload["data"]["dependencies"]["database"] == "connected"
        assert payload["data"]["dependencies"]["redis"] == "disconnected"
        assert "error" in payload
        assert payload["error"]["code"] == "SERVICE_UNAVAILABLE"
