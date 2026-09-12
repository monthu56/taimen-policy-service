"""Ядро policy-service: модель, stores, роли, bindings, решения, проекция.

Границы (ADR-0025 §7): grants (roles, bindings, delegations) — источник истины
здесь, engine получает их tuples; структурные отношения — проекция журналов
resource servers (`apply_relations`), редактируется только воркером.

Порядок записи при отзыве: сначала tuples в engine, потом строка `revoked`,
потом outbox — удаление никогда не расширяет allow при сбое посередине.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from time import perf_counter
from typing import Any, Literal

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from policy_service.catalog import (
    SCOPE_TYPES,
    ActionDef,
    Catalog,
    CatalogError,
    ResourceType,
    content_hash_of,
    parse_catalog,
    relation_name,
)
from policy_service.config import Settings
from policy_service.fga import CheckItem, FgaClient, FgaError, Tuple
from policy_service.model_builder import ACTIVE_WINDOW, build_model
from policy_service.models import (
    Binding,
    DecisionLog,
    ModelVersion,
    OutboxEvent,
    ProjectionCursor,
    RelationTuple,
    Role,
    TenantStore,
    utcnow,
)
from policy_service.models import (
    Catalog as CatalogRow,
)

Consistency = Literal["default", "strong"]
FAR_FUTURE = "9999-12-31T00:00:00+00:00"
WILDCARD_PRINCIPAL = "principal:*"

REASON_ALLOWED = "allowed"
REASON_DENIED = "denied_no_binding"
REASON_UNKNOWN_ACTION = "unknown_action"
REASON_UNKNOWN_RESOURCE = "unknown_resource_type"
REASON_NOT_APPLICABLE = "action_not_applicable"
REASON_TENANT_UNKNOWN = "tenant_unknown"
REASON_UNAVAILABLE = "unavailable"


class PolicyError(Exception):
    def __init__(self, code: str, status: int = 400, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.status = status
        self.detail = detail or code


class PolicyUnavailable(PolicyError):
    def __init__(self, code: str = "policy_unavailable", detail: str = "") -> None:
        super().__init__(code, 503, detail)


@dataclass(frozen=True)
class StoreRef:
    tenant_id: uuid.UUID
    store_id: str
    model_id: str
    model_version: int


@dataclass(frozen=True)
class DecisionResult:
    allowed: bool
    reason_code: str
    decision_id: uuid.UUID
    model_version: int
    evaluated_at: datetime
    action: str
    resource: str
    consistency: str


@dataclass(frozen=True)
class RelationChange:
    object: str
    relation: str
    subject: str


@dataclass
class ModelInfo:
    """Проверки запросов против зарегистрированных каталогов (без engine)."""

    catalogs: list[Catalog]
    types: dict[str, ResourceType] = field(default_factory=dict)
    actions: dict[str, ActionDef] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for catalog in self.catalogs:
            self.types.update(catalog.resource_types)
            self.actions.update(catalog.actions)

    @property
    def known_types(self) -> set[str]:
        return set(self.types) | set(SCOPE_TYPES)

    def validate_target(self, action: str, resource_type: str) -> str | None:
        if action not in self.actions:
            return REASON_UNKNOWN_ACTION
        if resource_type not in self.known_types:
            return REASON_UNKNOWN_RESOURCE
        if resource_type in SCOPE_TYPES:
            return None
        if resource_type not in self.actions[action].resources:
            return REASON_NOT_APPLICABLE
        return None

    def contextual_allowed(self, object_type: str, relation: str) -> bool:
        rtype = self.types.get(object_type)
        return rtype is not None and relation in rtype.relations


class PolicyCore:
    def __init__(self, settings: Settings, fga: FgaClient) -> None:
        self._settings = settings
        self._fga = fga
        self._model: ModelInfo | None = None
        self._model_version = 0
        self._model_json: dict[str, Any] | None = None
        self._stores: dict[uuid.UUID, StoreRef] = {}

    # --- загрузка состояния ---------------------------------------------------

    @property
    def model(self) -> ModelInfo | None:
        return self._model

    @property
    def model_version(self) -> int:
        return self._model_version

    async def load(self, session: AsyncSession) -> None:
        rows = list(await session.scalars(select(CatalogRow).order_by(CatalogRow.service)))
        catalogs = [parse_catalog(row.content) for row in rows]
        self._model = ModelInfo(catalogs) if catalogs else None
        latest = await session.scalar(
            select(ModelVersion).order_by(ModelVersion.version.desc()).limit(1)
        )
        self._model_version = latest.version if latest else 0
        self._model_json = latest.fga_model if latest else None
        self._stores = {}
        for store in await session.scalars(select(TenantStore)):
            self._stores[store.tenant_id] = StoreRef(
                store.tenant_id, store.fga_store_id, store.fga_model_id, store.model_version
            )

    async def engine_healthy(self) -> bool:
        return await self._fga.healthy()

    # --- каталоги и модель ----------------------------------------------------

    async def register_catalog(
        self, session: AsyncSession, data: dict[str, Any]
    ) -> tuple[Catalog, bool]:
        catalog = parse_catalog(data)
        row = await session.get(CatalogRow, catalog.service)
        changed = row is None or row.content_hash != catalog.content_hash
        if row is None:
            session.add(
                CatalogRow(
                    service=catalog.service,
                    version=catalog.version,
                    content_hash=catalog.content_hash,
                    content=catalog.content,
                )
            )
        elif changed:
            row.version = catalog.version
            row.content_hash = catalog.content_hash
            row.content = catalog.content
            row.registered_at = utcnow()
        await session.flush()
        # Пересобрать ModelInfo: build_model проверит коллизии типов между сервисами.
        rows = list(await session.scalars(select(CatalogRow).order_by(CatalogRow.service)))
        catalogs = [parse_catalog(r.content) for r in rows]
        build_model(catalogs)
        self._model = ModelInfo(catalogs)
        return catalog, changed

    async def publish_model(self, session: AsyncSession) -> tuple[ModelVersion, bool, int]:
        rows = list(await session.scalars(select(CatalogRow).order_by(CatalogRow.service)))
        if not rows:
            raise PolicyError("no_catalogs", 409, "нет зарегистрированных каталогов")
        catalogs = [parse_catalog(r.content) for r in rows]
        model_json = build_model(catalogs)
        catalogs_hash = content_hash_of({r.service: r.content_hash for r in rows})
        latest = await session.scalar(
            select(ModelVersion).order_by(ModelVersion.version.desc()).limit(1)
        )
        created = latest is None or latest.catalogs_hash != catalogs_hash
        if created:
            version = ModelVersion(
                version=(latest.version + 1) if latest else 1,
                catalogs_hash=catalogs_hash,
                fga_model=model_json,
            )
            session.add(version)
            await session.flush()
        else:
            assert latest is not None
            version = latest
        self._model = ModelInfo(catalogs)
        self._model_version = version.version
        self._model_json = version.fga_model

        published = 0
        for store in await session.scalars(select(TenantStore)):
            if store.model_version == version.version and store.fga_model_id:
                continue
            model_id = await self._write_model(store.fga_store_id, version.fga_model)
            store.fga_model_id = model_id
            store.model_version = version.version
            store.published_at = utcnow()
            self._stores[store.tenant_id] = StoreRef(
                store.tenant_id, store.fga_store_id, model_id, version.version
            )
            published += 1
        await self._emit(
            session,
            None,
            "model.published",
            "model",
            str(version.version),
            {"version": version.version, "catalogsHash": catalogs_hash},
        )
        return version, created, published

    async def _write_model(self, store_id: str, model_json: dict[str, Any]) -> str:
        try:
            return await self._fga.write_model(store_id, model_json)
        except FgaError as exc:
            raise PolicyUnavailable("engine_write_model_failed", exc.message) from exc

    # --- tenants и stores -----------------------------------------------------

    async def ensure_tenant(self, session: AsyncSession, tenant_id: uuid.UUID) -> StoreRef:
        cached = self._stores.get(tenant_id)
        if cached is not None and cached.model_id:
            return cached
        row = await session.get(TenantStore, tenant_id)
        if row is None:
            try:
                store_id = await self._fga.create_store(
                    f"{self._settings.fga_store_prefix}-{tenant_id}"
                )
            except FgaError as exc:
                raise PolicyUnavailable("engine_create_store_failed", exc.message) from exc
            row = TenantStore(tenant_id=tenant_id, fga_store_id=store_id)
            session.add(row)
            await session.flush()
        if self._model_json is not None and (
            not row.fga_model_id or row.model_version != self._model_version
        ):
            row.fga_model_id = await self._write_model(row.fga_store_id, self._model_json)
            row.model_version = self._model_version
            row.published_at = utcnow()
            await session.flush()
        if not row.fga_model_id:
            raise PolicyUnavailable("model_not_published", "модель ещё не опубликована")
        ref = StoreRef(tenant_id, row.fga_store_id, row.fga_model_id, row.model_version)
        self._stores[tenant_id] = ref
        return ref

    async def get_store(self, session: AsyncSession, tenant_id: uuid.UUID) -> StoreRef | None:
        cached = self._stores.get(tenant_id)
        if cached is not None and cached.model_id:
            return cached
        row = await session.get(TenantStore, tenant_id)
        if row is None or not row.fga_model_id:
            return None
        ref = StoreRef(tenant_id, row.fga_store_id, row.fga_model_id, row.model_version)
        self._stores[tenant_id] = ref
        return ref

    async def list_stores(self, session: AsyncSession) -> list[TenantStore]:
        return list(await session.scalars(select(TenantStore).order_by(TenantStore.created_at)))

    # --- роли -----------------------------------------------------------------

    def _require_model(self) -> ModelInfo:
        if self._model is None:
            raise PolicyUnavailable("model_not_loaded", "каталоги не зарегистрированы")
        return self._model

    async def upsert_role(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        *,
        key: str,
        actions: Sequence[str],
        name: str = "",
        kind: str = "tenant",
    ) -> Role:
        model = self._require_model()
        unknown = sorted(set(actions) - set(model.actions))
        if unknown:
            raise PolicyError("unknown_action", 422, f"неизвестные действия: {unknown}")
        store = await self.ensure_tenant(session, tenant_id)
        role = await session.scalar(
            select(Role).where(Role.tenant_id == tenant_id, Role.key == key)
        )
        new_actions = sorted(set(actions))
        old_actions: list[str] = []
        if role is None:
            role = Role(tenant_id=tenant_id, key=key, kind=kind, name=name, actions=new_actions)
            session.add(role)
        else:
            old_actions = list(role.actions)
            if role.kind == "system" and kind != "system":
                raise PolicyError("system_role_immutable", 409)
            role.actions = new_actions
            role.name = name or role.name
            role.version += 1
        await session.flush()
        obj = f"role:{key}"
        writes = [
            Tuple(obj, relation_name(a), WILDCARD_PRINCIPAL)
            for a in new_actions
            if a not in old_actions
        ]
        deletes = [
            Tuple(obj, relation_name(a), WILDCARD_PRINCIPAL)
            for a in old_actions
            if a not in new_actions
        ]
        await self._engine_write(store, writes=writes, deletes=deletes)
        await self._emit(
            session,
            tenant_id,
            "role.updated",
            "role",
            key,
            {"key": key, "actions": new_actions, "version": role.version},
        )
        return role

    async def get_role(self, session: AsyncSession, tenant_id: uuid.UUID, key: str) -> Role | None:
        return await session.scalar(
            select(Role).where(Role.tenant_id == tenant_id, Role.key == key)
        )

    async def list_roles(self, session: AsyncSession, tenant_id: uuid.UUID) -> list[Role]:
        return list(
            await session.scalars(
                select(Role).where(Role.tenant_id == tenant_id).order_by(Role.key)
            )
        )

    # --- bindings и delegations -----------------------------------------------

    async def create_binding(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        *,
        subject_type: str,
        subject_id: str,
        role_key: str,
        scope_type: str,
        scope_id: str,
        starts_at: datetime | None = None,
        expires_at: datetime | None = None,
        source: str = "admin",
        delegator_id: uuid.UUID | None = None,
        created_by: str = "",
    ) -> Binding:
        store = await self.ensure_tenant(session, tenant_id)
        role = await self.get_role(session, tenant_id, role_key)
        if role is None:
            raise PolicyError("role_not_found", 404)
        if scope_type not in SCOPE_TYPES:
            raise PolicyError("scope_type_not_allowed", 422)
        if scope_type == "tenant" and scope_id != str(tenant_id):
            raise PolicyError("tenant_mismatch", 422, "scope tenant должен совпадать с tenant")
        if expires_at is not None and starts_at is not None and expires_at <= starts_at:
            raise PolicyError("window_invalid", 422)
        binding = Binding(
            tenant_id=tenant_id,
            subject_type=subject_type,
            subject_id=subject_id,
            role_key=role_key,
            scope_type=scope_type,
            scope_id=scope_id,
            starts_at=starts_at,
            expires_at=expires_at,
            source=source,
            delegator_id=delegator_id,
            created_by=created_by,
        )
        session.add(binding)
        await session.flush()
        await self._engine_write(store, writes=self._binding_tuples(binding))
        await self._emit(
            session,
            tenant_id,
            "binding.created",
            "binding",
            str(binding.id),
            _binding_payload(binding),
        )
        return binding

    async def create_delegation(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        *,
        delegator_id: str,
        delegate_id: str,
        role_key: str,
        scope_type: str,
        scope_id: str,
        starts_at: datetime | None,
        expires_at: datetime,
        created_by: str = "",
    ) -> Binding:
        """Делегат получает роль на scope на окно; роль не шире прав делегатора."""
        role = await self.get_role(session, tenant_id, role_key)
        if role is None:
            raise PolicyError("role_not_found", 404)
        store = await self.ensure_tenant(session, tenant_id)
        now = utcnow()
        if expires_at <= (starts_at or now):
            raise PolicyError("window_invalid", 422)
        scope_obj = f"{scope_type}:{scope_id}"
        items = [
            CheckItem(
                f"principal:{delegator_id}",
                relation_name(action),
                scope_obj,
                context={"current_time": now.isoformat()},
            )
            for action in role.actions
        ]
        try:
            results = await self._fga.batch_check(
                store.store_id, items, model_id=store.model_id, consistency="strong"
            )
        except FgaError as exc:
            raise PolicyUnavailable("engine_unavailable", exc.message) from exc
        missing = [a for a, ok in zip(role.actions, results, strict=True) if not ok]
        if missing:
            raise PolicyError("delegation_exceeds_delegator", 422, f"делегатор не имеет: {missing}")
        return await self.create_binding(
            session,
            tenant_id,
            subject_type="principal",
            subject_id=delegate_id,
            role_key=role_key,
            scope_type=scope_type,
            scope_id=scope_id,
            starts_at=starts_at or now,
            expires_at=expires_at,
            source="delegation",
            delegator_id=uuid.UUID(delegator_id),
            created_by=created_by,
        )

    async def revoke_binding(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        binding_id: uuid.UUID,
        *,
        reason: str = "",
    ) -> Binding:
        binding = await session.get(Binding, binding_id)
        if binding is None or binding.tenant_id != tenant_id:
            raise PolicyError("binding_not_found", 404)
        if binding.status == "revoked":
            return binding
        store = await self.ensure_tenant(session, tenant_id)
        await self._engine_write(store, deletes=self._binding_tuples(binding))
        binding.status = "revoked"
        binding.revoked_at = utcnow()
        binding.revoke_reason = reason
        await session.flush()
        await self._emit(
            session,
            tenant_id,
            "binding.revoked",
            "binding",
            str(binding.id),
            {**_binding_payload(binding), "reason": reason},
        )
        return binding

    async def revoke_subject_bindings(
        self, session: AsyncSession, tenant_id: uuid.UUID, *, subject_id: str, reason: str
    ) -> int:
        rows = await session.scalars(
            select(Binding).where(
                Binding.tenant_id == tenant_id,
                Binding.status == "active",
                (Binding.subject_id == subject_id)
                | (Binding.delegator_id == _uuid_or_none(subject_id)),
            )
        )
        count = 0
        for binding in rows:
            await self.revoke_binding(session, tenant_id, binding.id, reason=reason)
            count += 1
        return count

    async def list_bindings(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        *,
        subject_id: str | None = None,
        scope_id: str | None = None,
        include_revoked: bool = False,
    ) -> list[Binding]:
        stmt = select(Binding).where(Binding.tenant_id == tenant_id)
        if subject_id:
            stmt = stmt.where(Binding.subject_id == subject_id)
        if scope_id:
            stmt = stmt.where(Binding.scope_id == scope_id)
        if not include_revoked:
            stmt = stmt.where(Binding.status == "active")
        return list(await session.scalars(stmt.order_by(Binding.created_at)))

    def _binding_tuples(self, binding: Binding) -> list[Tuple]:
        obj = f"binding:{binding.id}"
        subject = (
            f"principal:{binding.subject_id}"
            if binding.subject_type == "principal"
            else f"group:{binding.subject_id}#member"
        )
        condition: dict[str, Any] | None = None
        if binding.starts_at is not None or binding.expires_at is not None:
            condition = {
                "name": ACTIVE_WINDOW,
                "context": {
                    "starts_at": (binding.starts_at or binding.created_at or utcnow()).isoformat(),
                    "expires_at": binding.expires_at.isoformat()
                    if binding.expires_at
                    else FAR_FUTURE,
                },
            }
        return [
            Tuple(obj, "subject", subject, condition=condition),
            Tuple(obj, "role", f"role:{binding.role_key}"),
            Tuple(f"{binding.scope_type}:{binding.scope_id}", "binding", obj),
        ]

    async def _engine_write(
        self, store: StoreRef, *, writes: Iterable[Tuple] = (), deletes: Iterable[Tuple] = ()
    ) -> None:
        try:
            await self._fga.write_idempotent(
                store.store_id, writes=writes, deletes=deletes, model_id=store.model_id
            )
        except FgaError as exc:
            if exc.retriable:
                raise PolicyUnavailable("engine_unavailable", exc.message) from exc
            raise PolicyError("engine_rejected_write", 422, exc.message) from exc

    # --- решения --------------------------------------------------------------

    async def check(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        *,
        principal_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        contextual: Sequence[RelationChange] = (),
        as_of: datetime | None = None,
        consistency: Consistency = "default",
        caller_id: str = "",
        correlation_id: str = "",
        log: bool = True,
    ) -> DecisionResult:
        results = await self.batch_check(
            session,
            tenant_id,
            items=[(principal_id, action, resource_type, resource_id, tuple(contextual), as_of)],
            consistency=consistency,
            caller_id=caller_id,
            correlation_id=correlation_id,
            log=log,
        )
        return results[0]

    async def batch_check(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        *,
        items: Sequence[tuple[str, str, str, str, tuple[RelationChange, ...], datetime | None]],
        consistency: Consistency = "default",
        caller_id: str = "",
        correlation_id: str = "",
        log: bool = True,
    ) -> list[DecisionResult]:
        model = self._require_model()
        started = perf_counter()
        now = utcnow()
        store = await self.get_store(session, tenant_id)
        prepared: list[tuple[int, CheckItem]] = []
        results: list[DecisionResult | None] = [None] * len(items)
        for index, (principal_id, action, rtype, rid, contextual, as_of) in enumerate(items):
            reason = model.validate_target(action, rtype)
            if reason is None and store is None:
                reason = REASON_TENANT_UNKNOWN
            if reason is not None:
                results[index] = DecisionResult(
                    False,
                    reason,
                    uuid.uuid4(),
                    self._model_version,
                    now,
                    action,
                    f"{rtype}:{rid}",
                    consistency,
                )
                continue
            tuples = [self._contextual_tuple(model, c) for c in contextual]
            prepared.append(
                (
                    index,
                    CheckItem(
                        f"principal:{principal_id}",
                        relation_name(action),
                        f"{rtype}:{rid}",
                        contextual=tuple(tuples),
                        context={"current_time": (as_of or now).isoformat()},
                        correlation_id=f"c{index}",
                    ),
                )
            )
        if prepared:
            assert store is not None
            try:
                answers = await self._fga.batch_check(
                    store.store_id,
                    [item for _, item in prepared],
                    model_id=store.model_id,
                    consistency=consistency,
                )
            except FgaError as exc:
                raise PolicyUnavailable("engine_unavailable", exc.message) from exc
            for (index, _), allowed in zip(prepared, answers, strict=True):
                principal_id, action, rtype, rid, _, _ = items[index]
                results[index] = DecisionResult(
                    allowed,
                    REASON_ALLOWED if allowed else REASON_DENIED,
                    uuid.uuid4(),
                    store.model_version,
                    now,
                    action,
                    f"{rtype}:{rid}",
                    consistency,
                )
        latency = (perf_counter() - started) * 1000 / max(1, len(items))
        final = [r for r in results if r is not None]
        if log:
            for (principal_id, *_), result in zip(items, final, strict=True):
                session.add(
                    DecisionLog(
                        decision_id=result.decision_id,
                        tenant_id=tenant_id,
                        principal_id=principal_id,
                        caller_id=caller_id,
                        action=result.action,
                        resource=result.resource,
                        allowed=result.allowed,
                        reason_code=result.reason_code,
                        model_version=result.model_version,
                        consistency=consistency,
                        correlation_id=correlation_id,
                        latency_ms=latency,
                        evaluated_at=now,
                    )
                )
        return final

    def _contextual_tuple(self, model: ModelInfo, change: RelationChange) -> Tuple:
        obj_type = change.object.partition(":")[0]
        if not model.contextual_allowed(obj_type, change.relation):
            raise PolicyError(
                "contextual_tuple_not_allowed",
                400,
                f"{change.object}#{change.relation} нельзя задать контекстно",
            )
        if not change.subject.startswith("principal:"):
            raise PolicyError("contextual_tuple_not_allowed", 400, "subject должен быть principal")
        return Tuple(change.object, change.relation, change.subject)

    async def list_objects(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        *,
        principal_id: str,
        action: str,
        resource_type: str,
        contextual: Sequence[RelationChange] = (),
        as_of: datetime | None = None,
        consistency: Consistency = "default",
    ) -> tuple[list[str], int]:
        model = self._require_model()
        reason = model.validate_target(action, resource_type)
        if reason is not None:
            raise PolicyError(reason, 400)
        store = await self.get_store(session, tenant_id)
        if store is None:
            return [], self._model_version
        tuples = [self._contextual_tuple(model, c) for c in contextual]
        try:
            objects = await self._fga.list_objects(
                store.store_id,
                subject=f"principal:{principal_id}",
                relation=relation_name(action),
                object_type=resource_type,
                contextual=tuples,
                context={"current_time": (as_of or utcnow()).isoformat()},
                model_id=store.model_id,
                consistency=consistency,
            )
        except FgaError as exc:
            raise PolicyUnavailable("engine_unavailable", exc.message) from exc
        prefix = f"{resource_type}:"
        return sorted(
            o[len(prefix) :] for o in objects if o.startswith(prefix)
        ), store.model_version

    async def list_subjects(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        *,
        action: str,
        resource_type: str,
        resource_id: str,
        consistency: Consistency = "default",
    ) -> tuple[list[str], int]:
        model = self._require_model()
        reason = model.validate_target(action, resource_type)
        if reason is not None:
            raise PolicyError(reason, 400)
        store = await self.get_store(session, tenant_id)
        if store is None:
            return [], self._model_version
        try:
            users = await self._fga.list_users(
                store.store_id,
                object=f"{resource_type}:{resource_id}",
                relation=relation_name(action),
                context={"current_time": utcnow().isoformat()},
                model_id=store.model_id,
                consistency=consistency,
            )
        except FgaError as exc:
            raise PolicyUnavailable("engine_unavailable", exc.message) from exc
        return sorted(u.removeprefix("principal:") for u in users), store.model_version

    async def simulate(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        *,
        principal_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        extra_bindings: Sequence[dict[str, Any]],
        contextual: Sequence[RelationChange] = (),
        as_of: datetime | None = None,
    ) -> DecisionResult:
        """What-if: гипотетические bindings подаются как contextual tuples."""
        model = self._require_model()
        reason = model.validate_target(action, resource_type)
        store = await self.get_store(session, tenant_id)
        now = utcnow()
        if reason is None and store is None:
            reason = REASON_TENANT_UNKNOWN
        if reason is not None:
            return DecisionResult(
                False,
                reason,
                uuid.uuid4(),
                self._model_version,
                now,
                action,
                f"{resource_type}:{resource_id}",
                "strong",
            )
        assert store is not None
        tuples = [self._contextual_tuple(model, c) for c in contextual]
        for index, spec in enumerate(extra_bindings):
            obj = f"binding:sim-{index}"
            subject = spec["subject"]
            subj = (
                f"principal:{subject['id']}"
                if subject["type"] == "principal"
                else f"group:{subject['id']}#member"
            )
            tuples.append(Tuple(obj, "subject", subj))
            tuples.append(Tuple(obj, "role", f"role:{spec['role_key']}"))
            tuples.append(Tuple(f"{spec['scope']['type']}:{spec['scope']['id']}", "binding", obj))
        try:
            allowed = await self._fga.check(
                store.store_id,
                CheckItem(
                    f"principal:{principal_id}",
                    relation_name(action),
                    f"{resource_type}:{resource_id}",
                    contextual=tuple(tuples),
                    context={"current_time": (as_of or now).isoformat()},
                ),
                model_id=store.model_id,
                consistency="strong",
            )
        except FgaError as exc:
            raise PolicyUnavailable("engine_unavailable", exc.message) from exc
        return DecisionResult(
            allowed,
            REASON_ALLOWED if allowed else REASON_DENIED,
            uuid.uuid4(),
            store.model_version,
            now,
            action,
            f"{resource_type}:{resource_id}",
            "strong",
        )

    async def explain(
        self, session: AsyncSession, tenant_id: uuid.UUID, decision_id: uuid.UUID
    ) -> tuple[DecisionLog, list[dict[str, Any]], list[uuid.UUID]]:
        """Путь решения: цепочка scope ресурса и bindings, дающие действие.

        v0 считает путь по собственной проекции отношений и таблице bindings,
        без обхода графа в engine: этого достаточно, чтобы ответить «какой
        binding на каком узле дерева дал allow».
        """
        record = await session.get(DecisionLog, decision_id)
        if record is None or record.tenant_id != tenant_id:
            raise PolicyError("decision_not_found", 404)
        rtype, _, rid = record.resource.partition(":")
        path: list[dict[str, Any]] = []
        chain = await self._scope_chain(session, tenant_id, rtype, rid)
        for node in chain:
            path.append({"object": node, "via": "scope/parent"})
        path.append({"object": f"tenant:{tenant_id}", "via": "tenant"})
        scope_ids = {node.partition(":")[2] for node in chain} | {str(tenant_id)}
        matching: list[uuid.UUID] = []
        bindings = await self.list_bindings(session, tenant_id, subject_id=record.principal_id)
        roles = {r.key: r for r in await self.list_roles(session, tenant_id)}
        for binding in bindings:
            role = roles.get(binding.role_key)
            if role is None or record.action not in role.actions:
                continue
            if binding.scope_id in scope_ids:
                matching.append(binding.id)
                path.append(
                    {
                        "binding": str(binding.id),
                        "role": binding.role_key,
                        "scope": f"{binding.scope_type}:{binding.scope_id}",
                        "window": [
                            binding.starts_at.isoformat() if binding.starts_at else None,
                            binding.expires_at.isoformat() if binding.expires_at else None,
                        ],
                    }
                )
        return record, path, matching

    async def _scope_chain(
        self, session: AsyncSession, tenant_id: uuid.UUID, rtype: str, rid: str
    ) -> list[str]:
        """Объект → его scope-воркспейс → предки (по проекции отношений)."""
        chain: list[str] = []
        current = f"{rtype}:{rid}"
        seen: set[str] = set()
        while current and current not in seen and len(chain) < 64:
            seen.add(current)
            chain.append(current)
            ctype = current.partition(":")[0]
            if ctype == "tenant":
                break
            relation = "parent" if ctype == "workspace" else None
            if relation is None:
                info = self._require_model().types.get(ctype)
                if info is None:
                    break
                relation = "scope" if info.scope else info.parent
            if relation is None:
                break
            row = await session.scalar(
                select(RelationTuple.subject).where(
                    RelationTuple.tenant_id == tenant_id,
                    RelationTuple.object == current,
                    RelationTuple.relation == relation,
                )
            )
            current = row or ""
        return chain

    # --- проекция структурных отношений ---------------------------------------

    async def apply_relations(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        *,
        source: str,
        event_id: str,
        writes: Sequence[RelationChange] = (),
        deletes: Sequence[RelationChange] = (),
    ) -> None:
        if not writes and not deletes:
            return
        store = await self.ensure_tenant(session, tenant_id)
        to_write: list[Tuple] = []
        for change in writes:
            exists = await session.scalar(
                select(RelationTuple.id).where(
                    RelationTuple.tenant_id == tenant_id,
                    RelationTuple.object == change.object,
                    RelationTuple.relation == change.relation,
                    RelationTuple.subject == change.subject,
                )
            )
            if exists is None:
                session.add(
                    RelationTuple(
                        tenant_id=tenant_id,
                        object=change.object,
                        relation=change.relation,
                        subject=change.subject,
                        source=source,
                        source_event_id=event_id,
                    )
                )
            to_write.append(Tuple(change.object, change.relation, change.subject))
        to_delete = [Tuple(c.object, c.relation, c.subject) for c in deletes]
        await self._engine_write(store, writes=to_write, deletes=to_delete)
        for change in deletes:
            await session.execute(
                delete(RelationTuple).where(
                    RelationTuple.tenant_id == tenant_id,
                    RelationTuple.object == change.object,
                    RelationTuple.relation == change.relation,
                    RelationTuple.subject == change.subject,
                )
            )
        await session.flush()

    async def current_subjects(
        self, session: AsyncSession, tenant_id: uuid.UUID, *, object: str, relation: str
    ) -> list[str]:
        return list(
            await session.scalars(
                select(RelationTuple.subject).where(
                    RelationTuple.tenant_id == tenant_id,
                    RelationTuple.object == object,
                    RelationTuple.relation == relation,
                )
            )
        )

    async def replace_relation(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID,
        *,
        source: str,
        event_id: str,
        object: str,
        relation: str,
        subject: str | None,
    ) -> None:
        """Отношение с единственным субъектом (scope, parent, owner): заменить."""
        existing = await self.current_subjects(session, tenant_id, object=object, relation=relation)
        deletes = [RelationChange(object, relation, s) for s in existing if s != subject]
        writes = (
            [RelationChange(object, relation, subject)]
            if subject and subject not in existing
            else []
        )
        await self.apply_relations(
            session, tenant_id, source=source, event_id=event_id, writes=writes, deletes=deletes
        )

    # --- курсоры проекции и outbox --------------------------------------------

    async def get_cursor(self, session: AsyncSession, source: str) -> ProjectionCursor:
        row = await session.get(ProjectionCursor, source)
        if row is None:
            row = ProjectionCursor(source=source)
            session.add(row)
            await session.flush()
        return row

    async def list_cursors(self, session: AsyncSession) -> list[ProjectionCursor]:
        return list(
            await session.scalars(select(ProjectionCursor).order_by(ProjectionCursor.source))
        )

    async def _emit(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID | None,
        event_type: str,
        aggregate_type: str,
        aggregate_id: str,
        payload: dict[str, Any],
    ) -> None:
        session.add(
            OutboxEvent(
                tenant_id=tenant_id,
                type=event_type,
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                payload=payload,
            )
        )

    async def list_events(
        self, session: AsyncSession, *, after: int, limit: int
    ) -> tuple[list[OutboxEvent], int | None]:
        rows = list(
            await session.scalars(
                select(OutboxEvent)
                .where(OutboxEvent.sequence > after)
                .order_by(OutboxEvent.sequence)
                .limit(limit + 1)
            )
        )
        has_more = len(rows) > limit
        items = rows[:limit]
        return items, (items[-1].sequence if has_more and items else None)

    async def decision_count(self, session: AsyncSession, tenant_id: uuid.UUID) -> int:
        return int(
            await session.scalar(
                select(func.count())
                .select_from(DecisionLog)
                .where(DecisionLog.tenant_id == tenant_id)
            )
            or 0
        )


def _binding_payload(binding: Binding) -> dict[str, Any]:
    return {
        "bindingId": str(binding.id),
        "subject": {"type": binding.subject_type, "id": binding.subject_id},
        "roleKey": binding.role_key,
        "scope": {"type": binding.scope_type, "id": binding.scope_id},
        "source": binding.source,
        "status": binding.status,
    }


def _uuid_or_none(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except (ValueError, TypeError):
        return None


__all__ = [
    "UTC",
    "CatalogError",
    "DecisionResult",
    "ModelInfo",
    "PolicyCore",
    "PolicyError",
    "PolicyUnavailable",
    "RelationChange",
    "StoreRef",
]
