"""Схемы HTTP API (дизайн v0, раздел 7). Ключи JSON — camelCase."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class ApiModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, from_attributes=True, extra="forbid"
    )


Consistency = Literal["default", "strong"]


class ResourceRefIn(ApiModel):
    type: str = Field(min_length=1, max_length=64)
    id: str = Field(min_length=1, max_length=256)

    @property
    def key(self) -> str:
        return f"{self.type}:{self.id}"


class ContextualTupleIn(ApiModel):
    object: str = Field(min_length=3, max_length=320)
    relation: str = Field(min_length=1, max_length=64)
    subject: str = Field(min_length=3, max_length=320)


class DecisionContextIn(ApiModel):
    principal_type: str = ""
    contextual_tuples: list[ContextualTupleIn] = Field(default_factory=list, max_length=50)
    as_of: datetime | None = None


class CheckIn(ApiModel):
    principal_id: str | None = None
    action: str = Field(min_length=3, max_length=128)
    resource: ResourceRefIn
    context: DecisionContextIn = Field(default_factory=DecisionContextIn)
    consistency: Consistency = "default"


class DecisionOut(ApiModel):
    allowed: bool
    reason_code: str
    decision_id: uuid.UUID
    policy_version: str
    model_version: str
    evaluated_at: datetime
    consistency_token: str | None = None
    action: str = ""
    resource: str = ""


class BatchCheckIn(ApiModel):
    items: list[CheckIn] = Field(min_length=1, max_length=100)


class BatchCheckOut(ApiModel):
    items: list[DecisionOut]


class ListObjectsIn(ApiModel):
    principal_id: str | None = None
    action: str = Field(min_length=3, max_length=128)
    resource_type: str = Field(min_length=1, max_length=64)
    context: DecisionContextIn = Field(default_factory=DecisionContextIn)
    consistency: Consistency = "default"
    cursor: str | None = None
    limit: int = Field(default=1000, ge=1, le=1000)


class ListObjectsOut(ApiModel):
    objects: list[str]
    cursor: str | None = None
    model_version: str
    evaluated_at: datetime


class ListSubjectsIn(ApiModel):
    action: str = Field(min_length=3, max_length=128)
    resource: ResourceRefIn
    consistency: Consistency = "default"


class ListSubjectsOut(ApiModel):
    principals: list[str]
    model_version: str


class ExplainOut(ApiModel):
    decision_id: uuid.UUID
    allowed: bool
    reason_code: str
    action: str
    resource: str
    principal_id: str
    model_version: str
    evaluated_at: datetime
    path: list[dict[str, Any]]
    binding_ids: list[uuid.UUID]


# --- admin ---


class CatalogRegisterOut(ApiModel):
    service: str
    version: int
    content_hash: str
    changed: bool
    actions: list[str]


class ModelPublishOut(ApiModel):
    version: int
    catalogs_hash: str
    tenants_published: int
    created: bool


class RoleIn(ApiModel):
    key: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9_.:-]*$")
    name: str = Field(default="", max_length=256)
    kind: Literal["system", "tenant", "generated"] = "tenant"
    actions: list[str] = Field(default_factory=list, max_length=200)


class RoleOut(ApiModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    key: str
    name: str
    kind: str
    actions: list[str]
    version: int
    created_at: datetime
    updated_at: datetime


class SubjectIn(ApiModel):
    type: Literal["principal", "group"]
    id: str = Field(min_length=1, max_length=128)


class ScopeIn(ApiModel):
    type: Literal["tenant", "workspace"]
    id: str = Field(min_length=1, max_length=128)


class BindingIn(ApiModel):
    subject: SubjectIn
    role_key: str = Field(min_length=1, max_length=128)
    scope: ScopeIn
    starts_at: datetime | None = None
    expires_at: datetime | None = None


class DelegationIn(ApiModel):
    delegator_id: str = Field(min_length=1, max_length=128)
    delegate_id: str = Field(min_length=1, max_length=128)
    role_key: str = Field(min_length=1, max_length=128)
    scope: ScopeIn
    starts_at: datetime | None = None
    expires_at: datetime


class BindingOut(ApiModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    subject_type: str
    subject_id: str
    role_key: str
    scope_type: str
    scope_id: str
    starts_at: datetime | None
    expires_at: datetime | None
    status: str
    source: str
    delegator_id: uuid.UUID | None
    created_by: str
    created_at: datetime
    revoked_at: datetime | None
    revoke_reason: str


class RevokeIn(ApiModel):
    reason: str = Field(default="", max_length=256)


class SimulateIn(ApiModel):
    principal_id: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=3, max_length=128)
    resource: ResourceRefIn
    context: DecisionContextIn = Field(default_factory=DecisionContextIn)
    # Гипотетические bindings, которых ещё нет: проверка «что если».
    extra_bindings: list[BindingIn] = Field(default_factory=list, max_length=20)


class TenantStoreOut(ApiModel):
    tenant_id: uuid.UUID
    fga_store_id: str
    model_version: int
    published_at: datetime | None


class EventOut(ApiModel):
    sequence: int
    id: uuid.UUID
    tenant_id: uuid.UUID | None
    type: str
    aggregate_type: str
    aggregate_id: str
    payload: dict[str, Any]
    occurred_at: datetime


class EventPageOut(ApiModel):
    items: list[EventOut]
    next_after: int | None


class ProjectionStatusOut(ApiModel):
    source: str
    cursor: str
    events_applied: int
    last_error: str
    updated_at: datetime


class AccessReviewOut(ApiModel):
    tenant_id: uuid.UUID
    generated_at: datetime
    roles: list[RoleOut]
    bindings: list[BindingOut]
