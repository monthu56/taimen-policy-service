"""Схема данных policy-service (дизайн v0, раздел 6).

Bindings, roles и delegations — источник истины здесь; engine получает их
проекцией в tuples. Структурные отношения (`relation_tuples`) — проекция
журналов resource servers, редактируются только воркером проекции.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class TenantStore(Base):
    __tablename__ = "tenant_stores"

    tenant_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    fga_store_id: Mapped[str] = mapped_column(String(64), nullable=False)
    model_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fga_model_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Catalog(Base):
    __tablename__ = "catalogs"

    service: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ModelVersion(Base):
    __tablename__ = "model_versions"

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    catalogs_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    fga_model: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Role(Base):
    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("tenant_id", "key", name="uq_roles_tenant_key"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="tenant")
    name: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Binding(Base):
    __tablename__ = "bindings"
    __table_args__ = (
        Index("ix_bindings_tenant_subject", "tenant_id", "subject_type", "subject_id"),
        Index("ix_bindings_tenant_scope", "tenant_id", "scope_type", "scope_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)  # principal | group
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    role_key: Mapped[str] = mapped_column(String(128), nullable=False)
    scope_type: Mapped[str] = mapped_column(String(32), nullable=False)  # tenant | workspace
    scope_id: Mapped[str] = mapped_column(String(128), nullable=False)
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="admin")
    delegator_id: Mapped[uuid.UUID | None] = mapped_column()
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str] = mapped_column(String(256), nullable=False, default="")


class RelationTuple(Base):
    """Проекция структурного отношения из журнала resource server."""

    __tablename__ = "relation_tuples"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "object", "relation", "subject", name="uq_relation_tuples_key"
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    object: Mapped[str] = mapped_column(String(320), nullable=False)
    relation: Mapped[str] = mapped_column(String(64), nullable=False)
    subject: Mapped[str] = mapped_column(String(320), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    source_event_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProjectionCursor(Base):
    __tablename__ = "projection_cursors"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    cursor: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    events_applied: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class DecisionLog(Base):
    __tablename__ = "decision_log"
    __table_args__ = (Index("ix_decision_log_tenant_time", "tenant_id", "evaluated_at"),)

    decision_id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    principal_id: Mapped[str] = mapped_column(String(128), nullable=False)
    caller_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource: Mapped[str] = mapped_column(String(320), nullable=False)
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    model_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    consistency: Mapped[str] = mapped_column(String(16), nullable=False, default="default")
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OutboxEvent(Base):
    __tablename__ = "outbox_events"

    sequence: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    id: Mapped[uuid.UUID] = mapped_column(nullable=False, unique=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column()
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(64), nullable=False)
    aggregate_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
