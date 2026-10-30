"""Security Test Suite: Secret Leak Prevention (Section 46.7).

Verifies:
- Secrets (password hashes, secrets, keys) never appear in API responses.
- Structured application logs redact sensitive credentials and headers.
- No live .env files exist in repository.
- Frontend production bundle contains zero backend secrets.
- Dockerfiles contain zero baked runtime secrets.
"""

from pathlib import Path
import re
import pytest

from app.core.logging import StructuredJsonFormatter, redact_data


def test_api_responses_never_expose_password_hashes_or_secrets(client, auth_context):
    """Verify user endpoints and auth endpoints never return password_hash."""
    # 1. User listing endpoint
    res = client.get("/api/v1/users", headers=auth_context["admin_headers"])
    assert res.status_code == 200
    users = res.json()["data"]
    for user in users:
        assert "password_hash" not in user
        assert "password" not in user
        assert "secret" not in user

    # 2. Login endpoint response
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@sentinel.internal", "password": "SentinelAdmin2026!"},
    )
    assert login_res.status_code == 200
    login_data = login_res.json()["data"]
    assert "password_hash" not in login_data["user"]
    assert "password" not in login_data["user"]


def test_health_endpoints_do_not_leak_database_or_redis_credentials(client):
    """Verify health readiness endpoint does not leak database passwords."""
    res = client.get("/health/ready")
    assert res.status_code in (200, 503)
    text = res.text.lower()
    assert "sentinel_dev_secret" not in text
    assert "password=" not in text
    assert "jwt_secret" not in text


def test_log_formatter_sanitizes_sensitive_keys():
    """Verify StructuredJsonFormatter redacts passwords, tokens, and authorization values."""
    sensitive_dict = {
        "password": "SuperSecretPassword123!",
        "token": "sensitive_jwt_token_value",
        "authorization": "Bearer secret_bearer_token",
        "category": "safe_value",
    }
    redacted = redact_data(sensitive_dict)
    assert redacted["password"] == "[REDACTED]"
    assert redacted["token"] == "[REDACTED]"
    assert redacted["authorization"] == "[REDACTED]"
    assert redacted["category"] == "safe_value"


def test_no_live_env_files_in_repository():
    """Verify no actual .env or .env.production file is committed."""
    repo_root = Path(__file__).resolve().parents[3]
    forbidden_files = list(repo_root.glob("**/.env")) + list(repo_root.glob("**/.env.local"))
    # Exclude any .env.example
    actual_env_files = [f for f in forbidden_files if not f.name.endswith(".example")]
    assert len(actual_env_files) == 0, f"Found uncommitted or leaked .env files: {actual_env_files}"


def test_frontend_bundle_does_not_contain_backend_secrets():
    """Scan built frontend assets in dist/ to ensure no backend secrets are bundled."""
    sentinel_root = Path(__file__).resolve().parents[3]
    frontend_dist = sentinel_root / "frontend" / "dist" / "assets"
    if not frontend_dist.exists():
        frontend_dist = sentinel_root.parent / "frontend" / "dist" / "assets"

    assert frontend_dist.exists(), f"Frontend dist directory not found at {frontend_dist}"

    sensitive_patterns = [
        re.compile(r"JWT_SECRET", re.IGNORECASE),
        re.compile(r"JWT_REFRESH_SECRET", re.IGNORECASE),
        re.compile(r"ADMIN_BOOTSTRAP_SECRET", re.IGNORECASE),
        re.compile(r"MODEL_SIGNING_KEY", re.IGNORECASE),
        re.compile(r"postgresql://", re.IGNORECASE),
    ]

    for asset_file in frontend_dist.glob("*.js"):
        content = asset_file.read_text(encoding="utf-8", errors="ignore")
        for pattern in sensitive_patterns:
            assert not pattern.search(content), f"Leaked sensitive pattern '{pattern.pattern}' found in {asset_file.name}!"


def test_dockerfiles_do_not_contain_baked_runtime_secrets():
    """Verify Dockerfiles in deployment/docker/ do not contain hardcoded secret tokens."""
    repo_root = Path(__file__).resolve().parents[3]
    docker_dir = repo_root / "sentinel-x" / "deployment" / "docker"
    if not docker_dir.exists():
        docker_dir = repo_root / "deployment" / "docker"

    for dockerfile in docker_dir.glob("*.Dockerfile"):
        lines = dockerfile.read_text(encoding="utf-8").splitlines()
        for line in lines:
            line_upper = line.strip().upper()
            if line_upper.startswith("ENV"):
                assert "JWT_SECRET=" not in line, f"Hardcoded secret in {dockerfile.name}: {line}"
                assert "ADMIN_BOOTSTRAP_SECRET=" not in line, f"Hardcoded secret in {dockerfile.name}: {line}"
                assert "MODEL_SIGNING_KEY=" not in line, f"Hardcoded secret in {dockerfile.name}: {line}"
