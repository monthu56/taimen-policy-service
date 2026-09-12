"""policy foundation: stores, catalogs, models, roles, bindings, projection, decisions, outbox

Revision ID: 0001_policy_foundation
Revises:
Create Date: 2026-09-12
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_policy_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant_stores",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True),
        sa.Column("fga_store_id", sa.String(64), nullable=False),
        sa.Column("model_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("fga_model_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "catalogs",
        sa.Column("service", sa.String(64), primary_key=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "model_versions",
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("catalogs_hash", sa.String(64), nullable=False),
        sa.Column("fga_model", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False, index=True),
        sa.Column("key", sa.String(128), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False, server_default="tenant"),
        sa.Column("name", sa.String(256), nullable=False, server_default=""),
        sa.Column("actions", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "key", name="uq_roles_tenant_key"),
    )
    op.create_table(
        "bindings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False, index=True),
        sa.Column("subject_type", sa.String(32), nullable=False),
        sa.Column("subject_id", sa.String(128), nullable=False),
        sa.Column("role_key", sa.String(128), nullable=False),
        sa.Column("scope_type", sa.String(32), nullable=False),
        sa.Column("scope_id", sa.String(128), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("source", sa.String(16), nullable=False, server_default="admin"),
        sa.Column("delegator_id", sa.Uuid()),
        sa.Column("created_by", sa.String(128), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoke_reason", sa.String(256), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_bindings_tenant_subject", "bindings", ["tenant_id", "subject_type", "subject_id"]
    )
    op.create_index("ix_bindings_tenant_scope", "bindings", ["tenant_id", "scope_type", "scope_id"])
    op.create_table(
        "relation_tuples",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False, index=True),
        sa.Column("object", sa.String(320), nullable=False),
        sa.Column("relation", sa.String(64), nullable=False),
        sa.Column("subject", sa.String(320), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("source_event_id", sa.String(128), nullable=False, server_default=""),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "object", "relation", "subject", name="uq_relation_tuples_key"
        ),
    )
    op.create_table(
        "projection_cursors",
        sa.Column("source", sa.String(32), primary_key=True),
        sa.Column("cursor", sa.String(256), nullable=False, server_default=""),
        sa.Column("events_applied", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "decision_log",
        sa.Column("decision_id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("principal_id", sa.String(128), nullable=False),
        sa.Column("caller_id", sa.String(128), nullable=False, server_default=""),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("resource", sa.String(320), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("model_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("consistency", sa.String(16), nullable=False, server_default="default"),
        sa.Column("correlation_id", sa.String(128), nullable=False, server_default=""),
        sa.Column("latency_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_decision_log_tenant_time", "decision_log", ["tenant_id", "evaluated_at"])
    op.create_table(
        "outbox_events",
        sa.Column(
            "sequence", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True
        ),
        sa.Column("id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("aggregate_type", sa.String(64), nullable=False),
        sa.Column("aggregate_id", sa.String(128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    for table in (
        "outbox_events",
        "decision_log",
        "projection_cursors",
        "relation_tuples",
        "bindings",
        "roles",
        "model_versions",
        "catalogs",
        "tenant_stores",
    ):
        op.drop_table(table)
