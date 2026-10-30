"""Unit tests for database session and connection check."""

from unittest.mock import patch

from app.db.session import check_db_connection, get_db


def test_database_connection_check_success():
    """Verify check_db_connection returns True on active database."""
    assert check_db_connection() is True


def test_database_connection_check_failure_handled_safely():
    """Verify check_db_connection returns False when database is down, without crashing."""
    with patch("app.db.session.engine.connect", side_effect=Exception("Connection refused")):
        assert check_db_connection() is False


def test_get_db_session_lifecycle():
    """Verify get_db generator yields active session and closes it."""
    gen = get_db()
    session = next(gen)
    assert session is not None
    assert session.is_active is True
    # Complete generator
    try:
        next(gen)
    except StopIteration:
        pass
