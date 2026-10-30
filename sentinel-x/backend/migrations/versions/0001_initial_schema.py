"""Initial database schema with 13 core tables, constraints, and indexes.

Revision ID: 0001_initial_schema
Revises: None
Create Date: 2026-10-30 18:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Cross-dialect type helpers
inet_type = sa.String(45).with_variant(postgresql.INET, "postgresql")
jsonb_type = sa.JSON().with_variant(postgresql.JSONB, "postgresql")


def upgrade() -> None:
    # 1. roles
    op.create_table(
        "roles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(30), unique=True, nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_roles_name", "roles", ["name"])

    # 2. users
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "role_id", sa.String(36), sa.ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("full_name", sa.String(120), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_role_id", "users", ["role_id"])

    # 3. data_sources
    op.create_table(
        "data_sources",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("source_type", sa.String(30), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("configuration", jsonb_type, nullable=True),
        sa.Column(
            "created_by",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "source_type IN ('DATASET', 'CSV_UPLOAD', 'JSON_UPLOAD', 'SIMULATOR', 'LIVE_COLLECTOR')",
            name="ck_data_sources_source_type",
        ),
    )
    op.create_index("ix_data_sources_source_type", "data_sources", ["source_type"])

    # 4. network_flows
    op.create_table(
        "network_flows",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "source_id",
            sa.String(36),
            sa.ForeignKey("data_sources.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", inet_type, nullable=False),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_ip", inet_type, nullable=False),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(20), nullable=True),
        sa.Column("packets", sa.BigInteger(), nullable=True),
        sa.Column("bytes", sa.BigInteger(), nullable=True),
        sa.Column("duration_ms", sa.Numeric(12, 3), nullable=True),
        sa.Column("direction", sa.String(20), nullable=True),
        sa.Column("raw_features", jsonb_type, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "source_port IS NULL OR (source_port >= 1 AND source_port <= 65535)",
            name="ck_network_flows_source_port",
        ),
        sa.CheckConstraint(
            "destination_port IS NULL OR (destination_port >= 1 AND destination_port <= 65535)",
            name="ck_network_flows_destination_port",
        ),
        sa.CheckConstraint("packets IS NULL OR packets >= 0", name="ck_network_flows_packets"),
        sa.CheckConstraint("bytes IS NULL OR bytes >= 0", name="ck_network_flows_bytes"),
        sa.CheckConstraint(
            "duration_ms IS NULL OR duration_ms >= 0", name="ck_network_flows_duration_ms"
        ),
    )
    op.create_index("ix_network_flows_timestamp", "network_flows", ["timestamp"])
    op.create_index("ix_network_flows_source_ip", "network_flows", ["source_ip"])
    op.create_index("ix_network_flows_destination_ip", "network_flows", ["destination_ip"])
    op.create_index("ix_network_flows_source_id", "network_flows", ["source_id"])

    # 5. model_versions
    op.create_table(
        "model_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("version", sa.String(50), nullable=False),
        sa.Column("algorithm", sa.String(50), nullable=False),
        sa.Column("artifact_uri", sa.Text(), nullable=False),
        sa.Column("feature_schema", jsonb_type, nullable=False),
        sa.Column("metrics", jsonb_type, nullable=False),
        sa.Column("checksum", sa.String(128), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("trained_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_by",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('TRAINED', 'EVALUATED', 'APPROVED', 'ACTIVE', 'RETIRED')",
            name="ck_model_versions_status",
        ),
        sa.UniqueConstraint("name", "version", name="uq_model_versions_name_version"),
    )
    op.create_index("ix_model_versions_name", "model_versions", ["name"])
    op.create_index("ix_model_versions_status", "model_versions", ["status"])

    # 6. detections
    op.create_table(
        "detections",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "flow_id",
            sa.String(36),
            sa.ForeignKey("network_flows.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "model_version_id",
            sa.String(36),
            sa.ForeignKey("model_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("attack_type", sa.String(100), nullable=False),
        sa.Column("confidence", sa.Numeric(5, 4), nullable=False),
        sa.Column("anomaly_score", sa.Numeric(8, 5), nullable=True),
        sa.Column("risk_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("is_anomaly", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("explanation", jsonb_type, nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_detections_confidence"),
        sa.CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100", name="ck_detections_risk_score"
        ),
        sa.CheckConstraint(
            "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="ck_detections_severity"
        ),
    )
    op.create_index("ix_detections_detected_at", "detections", ["detected_at"])
    op.create_index("ix_detections_severity", "detections", ["severity"])
    op.create_index("ix_detections_attack_type", "detections", ["attack_type"])
    op.create_index("ix_detections_risk_score", "detections", ["risk_score"])
    op.create_index("ix_detections_flow_id", "detections", ["flow_id"])
    op.create_index("ix_detections_model_version_id", "detections", ["model_version_id"])

    # 7. threat_intel_enrichments
    op.create_table(
        "threat_intel_enrichments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "detection_id",
            sa.String(36),
            sa.ForeignKey("detections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("indicator_type", sa.String(20), nullable=False),
        sa.Column("indicator_value", sa.String(255), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("reputation_score", sa.Numeric(6, 2), nullable=True),
        sa.Column("verdict", sa.String(50), nullable=True),
        sa.Column("country", sa.String(5), nullable=True),
        sa.Column("asn", sa.BigInteger(), nullable=True),
        sa.Column("response_data", jsonb_type, nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_threat_intel_enrichments_indicator_value",
        "threat_intel_enrichments",
        ["indicator_value"],
    )
    op.create_index(
        "ix_threat_intel_enrichments_detection_id", "threat_intel_enrichments", ["detection_id"]
    )

    # 8. incidents
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="OPEN"),
        sa.Column(
            "assigned_to",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_by",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE')",
            name="ck_incidents_status",
        ),
        sa.CheckConstraint(
            "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="ck_incidents_severity"
        ),
    )
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_assigned_to", "incidents", ["assigned_to"])

    # 9. incident_detections
    op.create_table(
        "incident_detections",
        sa.Column(
            "incident_id",
            sa.String(36),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "detection_id",
            sa.String(36),
            sa.ForeignKey("detections.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 10. incident_events
    op.create_table(
        "incident_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(36),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("metadata", jsonb_type, nullable=True),
        sa.Column(
            "actor_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incident_events_incident_id", "incident_events", ["incident_id"])

    # 11. analyst_feedback
    op.create_table(
        "analyst_feedback",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "detection_id",
            sa.String(36),
            sa.ForeignKey("detections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "analyst_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("verdict", sa.String(30), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "verdict IN ('TRUE_POSITIVE', 'FALSE_POSITIVE', 'UNCERTAIN')",
            name="ck_analyst_feedback_verdict",
        ),
    )
    op.create_index("ix_analyst_feedback_detection_id", "analyst_feedback", ["detection_id"])
    op.create_index("ix_analyst_feedback_analyst_id", "analyst_feedback", ["analyst_id"])

    # 12. audit_logs
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", sa.String(36), nullable=True),
        sa.Column("ip_address", inet_type, nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("metadata", jsonb_type, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    # 13. reports
    op.create_table(
        "reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "generated_by",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "incident_id",
            sa.String(36),
            sa.ForeignKey("incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("format", sa.String(10), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="QUEUED"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("format IN ('PDF', 'CSV', 'JSON')", name="ck_reports_format"),
        sa.CheckConstraint(
            "status IN ('QUEUED', 'PROCESSING', 'COMPLETED', 'FAILED')", name="ck_reports_status"
        ),
    )
    op.create_index("ix_reports_generated_by", "reports", ["generated_by"])
    op.create_index("ix_reports_incident_id", "reports", ["incident_id"])


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_table("audit_logs")
    op.drop_table("analyst_feedback")
    op.drop_table("incident_events")
    op.drop_table("incident_detections")
    op.drop_table("incidents")
    op.drop_table("threat_intel_enrichments")
    op.drop_table("detections")
    op.drop_table("model_versions")
    op.drop_table("network_flows")
    op.drop_table("data_sources")
    op.drop_table("users")
    op.drop_table("roles")
