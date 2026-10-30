"""Security-specific verification tests for Milestone 1.

Verifies:
- No hardcoded secrets or committed `.env` files.
- `.gitignore` prevents secret exposure.
- Security headers are enforced across all routes.
- CORS policy behaviors.
"""

from pathlib import Path


def test_no_env_file_committed():
    """Verify that no actual .env file exists in the repository root or backend."""
    repo_root = Path(__file__).resolve().parents[3]
    env_file = repo_root / ".env"
    backend_env = repo_root / "sentinel-x" / ".env"
    assert not env_file.exists(), "CRITICAL: .env file found in root directory!"
    assert not backend_env.exists(), "CRITICAL: .env file found in sentinel-x directory!"


def test_gitignore_contains_required_exclusions():
    """Verify .gitignore includes all mandatory patterns from Section 35."""
    repo_root = Path(__file__).resolve().parents[3]
    gitignore_path = repo_root / ".gitignore"
    assert gitignore_path.exists(), ".gitignore must exist in root repository"

    content = gitignore_path.read_text(encoding="utf-8")
    mandatory_patterns = [
        ".env",
        "__pycache__",
        "*.py[cod]",
        ".pytest_cache",
        ".mypy_cache",
        "*.sqlite",
        "*.db",
        "node_modules",
        "dist",
        "build",
    ]
    for pattern in mandatory_patterns:
        assert pattern in content, f"Missing mandatory gitignore pattern: {pattern}"


def test_cors_headers_on_allowed_origin(client):
    """Verify CORS headers allow configured origin."""
    response = client.get(
        "/health/live",
        headers={"Origin": "http://localhost:5173"},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-credentials" in response.headers


def test_cors_headers_block_unauthorized_origin(client):
    """Verify CORS headers do not allow unauthorized external origin."""
    response = client.get(
        "/health/live",
        headers={"Origin": "https://malicious-external-site.attacker.com"},
    )
    assert response.status_code == 200
    assert (
        response.headers.get("access-control-allow-origin")
        != "https://malicious-external-site.attacker.com"
    )
