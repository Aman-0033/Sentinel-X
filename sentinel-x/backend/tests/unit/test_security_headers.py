"""Unit tests for SecurityHeadersMiddleware."""


def test_security_headers_present_on_responses(client):
    """Verify all mandatory defensive headers from Section 38 are present."""
    response = client.get("/health/live")
    assert response.status_code == 200

    headers = response.headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in headers["content-security-policy"]
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert "max-age=31536000" in headers["strict-transport-security"]
    assert "geolocation=()" in headers["permissions-policy"]
    assert headers["x-xss-protection"] == "0"
