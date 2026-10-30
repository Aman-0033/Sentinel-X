"""Integration tests verifying Alembic migrations can build database from zero."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_alembic_migrations_clean_build_and_rollback(tmp_path: Path):
    """Verify Alembic migration 0001_initial_schema creates all 13 tables from scratch and rolls back."""
    test_db_path = tmp_path / "migration_test.db"
    test_db_url = f"sqlite:///{test_db_path.as_posix()}"

    backend_dir = Path(__file__).resolve().parents[2]
    alembic_ini = backend_dir / "alembic.ini"

    # Setup Alembic Config object
    alembic_cfg = Config(str(alembic_ini))
    alembic_cfg.set_main_option("sqlalchemy.url", test_db_url)
    alembic_cfg.set_main_option("script_location", str(backend_dir / "migrations"))

    # 1. Run upgrade to head from clean empty database
    command.upgrade(alembic_cfg, "head")

    engine = create_engine(test_db_url)
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())

    expected_tables = {
        "roles",
        "users",
        "data_sources",
        "network_flows",
        "model_versions",
        "detections",
        "threat_intel_enrichments",
        "incidents",
        "incident_detections",
        "incident_events",
        "analyst_feedback",
        "audit_logs",
        "reports",
        "alembic_version",
    }

    assert expected_tables.issubset(table_names), f"Missing tables: {expected_tables - table_names}"

    # 2. Test rollback (downgrade to base)
    command.downgrade(alembic_cfg, "base")
    inspector_after_downgrade = inspect(engine)
    remaining_tables = set(inspector_after_downgrade.get_table_names()) - {"alembic_version"}
    assert len(remaining_tables) == 0, f"Tables still exist after downgrade: {remaining_tables}"

    # 3. Test re-upgrade to head builds successfully again
    command.upgrade(alembic_cfg, "head")
    inspector_reupgraded = inspect(engine)
    reupgraded_tables = set(inspector_reupgraded.get_table_names())
    assert expected_tables.issubset(reupgraded_tables)

    engine.dispose()
