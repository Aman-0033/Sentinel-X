"""Unit tests for centralized exception handling and safe error envelopes."""

from fastapi import APIRouter, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field

from app.core.exceptions import (
    AppValidationError,
    AuthenticationError,
    ConfigurationError,
    ConflictError,
    NotFoundError,
    RateLimitError,
    ServiceUnavailableError,
)


class SampleModel(BaseModel):
    name: str = Field(..., min_length=3)
    score: int = Field(..., ge=0, le=100)


def test_custom_exception_returns_section14_envelope(app, client):
    """Verify domain SentinelException generates the exact Section 14 error format."""
    router = APIRouter()

    @router.get("/test-auth-fail")
    def trigger_auth_error():
        raise AuthenticationError("Custom authentication failed.")

    @router.get("/test-not-found")
    def trigger_not_found():
        raise NotFoundError(resource="Incident", identifier="INC-404")

    @router.get("/test-conflict")
    def trigger_conflict():
        raise ConflictError("Rule already exists.")

    @router.get("/test-rate-limit")
    def trigger_rate_limit():
        raise RateLimitError("Too many attempts.")

    @router.get("/test-service-unavailable")
    def trigger_service_unavailable():
        raise ServiceUnavailableError("Worker offline.")

    @router.get("/test-validation-error")
    def trigger_validation_error():
        raise AppValidationError("Validation failed for IP format.")

    @router.get("/test-configuration-error")
    def trigger_config_error():
        raise ConfigurationError("Missing key.")

    @router.get("/test-http-error")
    def trigger_http_error():
        raise HTTPException(status_code=400, detail="Malformed parameter.")

    @router.post("/test-pydantic-validation")
    def trigger_pydantic_validation(body: SampleModel):
        return {"name": body.name}

    app.include_router(router)

    # 1. Test Authentication Error (401)
    res1 = client.get("/test-auth-fail")
    assert res1.status_code == 401
    assert res1.json()["error"]["code"] == "AUTHENTICATION_FAILED"

    # 2. Test Not Found Error (404)
    res2 = client.get("/test-not-found")
    assert res2.status_code == 404
    assert res2.json()["error"]["code"] == "NOT_FOUND"

    # 3. Test Conflict Error (409)
    res3 = client.get("/test-conflict")
    assert res3.status_code == 409
    assert res3.json()["error"]["code"] == "CONFLICT"

    # 4. Test Rate Limit Error (429)
    res4 = client.get("/test-rate-limit")
    assert res4.status_code == 429
    assert res4.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    # 5. Test Service Unavailable (503)
    res5 = client.get("/test-service-unavailable")
    assert res5.status_code == 503
    assert res5.json()["error"]["code"] == "SERVICE_UNAVAILABLE"

    # 6. Test AppValidationError (422)
    res6 = client.get("/test-validation-error")
    assert res6.status_code == 422
    assert res6.json()["error"]["code"] == "VALIDATION_ERROR"

    # 7. Test ConfigurationError (500)
    res7 = client.get("/test-configuration-error")
    assert res7.status_code == 500
    assert res7.json()["error"]["code"] == "CONFIGURATION_ERROR"

    # 8. Test HTTPException (400)
    res8 = client.get("/test-http-error")
    assert res8.status_code == 400
    assert res8.json()["error"]["code"] == "BAD_REQUEST"
    assert res8.json()["error"]["message"] == "Malformed parameter."

    # 9. Test RequestValidationError (422) with details
    res9 = client.post("/test-pydantic-validation", json={"name": "a", "score": 200})
    assert res9.status_code == 422
    data9 = res9.json()
    assert data9["error"]["code"] == "VALIDATION_ERROR"
    assert "details" in data9["error"]
    assert len(data9["error"]["details"]) > 0


def test_unhandled_exception_returns_safe_500_without_traceback(app):
    """Verify unhandled exceptions never expose internal Python tracebacks or paths."""
    router = APIRouter()

    @router.get("/test-crash")
    def trigger_crash():
        raise ZeroDivisionError("division by zero in database calculation")

    app.include_router(router)

    with TestClient(app, raise_server_exceptions=False) as client_no_raise:
        res = client_no_raise.get("/test-crash")
        assert res.status_code == 500
        data = res.json()

        assert "error" in data
        assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"
        assert "ZeroDivisionError" not in data["error"]["message"]
        assert "traceback" not in str(data)
        assert "Traceback" not in str(data)
        assert "division by zero" not in data["error"]["message"]
        assert "request_id" in data["error"]
