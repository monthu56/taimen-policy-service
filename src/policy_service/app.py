"""HTTP API policy-service (дизайн v0, раздел 7).

Decision API — IAM-токен audience `policy-service`; principal решения — из
токена, чужой principal только со scope `policy:check-on-behalf`.
Admin API — bootstrap-заголовок или токен со scope `policy:admin` того же
tenant. Любая ошибка принятия решения — 503 `policy_unavailable`, не allow.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from policy_service import __version__
from policy_service.auth import (
    BOOTSTRAP_HEADER,
    SCOPE_CHECK,
    AuthContext,
    IamContextError,
    IamContextVerifier,
    IamVerificationUnavailable,
    bootstrap_token_matches,
)
from policy_service.catalog import CatalogError, load_catalog_file
from policy_service.config import Settings
from policy_service.core import (
    DecisionResult,
    PolicyCore,
    PolicyError,
    RelationChange,
)
from policy_service.db import Database
from policy_service.fga import FgaClient
from policy_service.models import Base
from policy_service.schemas import (
    AccessReviewOut,
    BatchCheckIn,
    BatchCheckOut,
    BindingIn,
    BindingOut,
    CatalogRegisterOut,
    CheckIn,
    ContextualTupleIn,
    DecisionOut,
    DelegationIn,
    EventOut,
    EventPageOut,
    ExplainOut,
    ListObjectsIn,
    ListObjectsOut,
    ListSubjectsIn,
    ListSubjectsOut,
    ModelPublishOut,
    ProjectionStatusOut,
    RevokeIn,
    RoleIn,
    RoleOut,
    SimulateIn,
    TenantStoreOut,
)

log = logging.getLogger("policy_service")


def create_app(
    settings: Settings | None = None,
    *,
    database: Database | None = None,
    fga: FgaClient | None = None,
) -> FastAPI:
    settings = settings or Settings()
    db = database or Database(settings)
    engine = fga or FgaClient(
        settings.fga_url,
        preshared_key=settings.fga_preshared_key,
        timeout_seconds=settings.fga_timeout_seconds,
    )
    core = PolicyCore(settings, engine)
    verifier = IamContextVerifier(
        issuer=settings.iam_issuer,
        audience=settings.iam_audience,
        public_key_pem=settings.resolved_iam_public_key(),
        jwks_url=settings.iam_jwks_url,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if settings.create_schema_on_startup:
            async with db.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        async with db.sessions() as session:
            await core.load(session)
            for path in settings.catalog_paths():
                catalog = load_catalog_file(path)
                await core.register_catalog(session, catalog.content)
            if settings.catalog_paths():
                await core.publish_model(session)
            await session.commit()
        try:
            yield
        finally:
            await engine.aclose()
            await db.close()

    app = FastAPI(title="Policy Service", version=__version__, lifespan=lifespan)
    app.state.core = core
    app.state.settings = settings
    app.state.db = db

    @app.exception_handler(PolicyError)
    async def _policy_error(_: Request, exc: PolicyError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status, content={"detail": exc.code, "message": exc.detail}
        )

    @app.exception_handler(CatalogError)
    async def _catalog_error(_: Request, exc: CatalogError) -> JSONResponse:
        return JSONResponse(
            status_code=422, content={"detail": "catalog_invalid", "message": str(exc)}
        )

    async def get_session() -> AsyncIterator[AsyncSession]:
        async for session in db.session():
            yield session

    async def require_iam(
        request: Request,
        authorization: str | None = Header(default=None),
        x_correlation_id: str | None = Header(default=None),
    ) -> AuthContext:
        token = ""
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        try:
            return await verifier.verify(token, correlation_id=x_correlation_id or "")
        except IamContextError as exc:
            raise HTTPException(status_code=401, detail="invalid_iam_context") from exc
        except IamVerificationUnavailable as exc:
            raise HTTPException(status_code=503, detail="iam_verification_unavailable") from exc

    async def require_check_scope(ctx: AuthContext = Depends(require_iam)) -> AuthContext:
        if SCOPE_CHECK not in ctx.scopes and not ctx.is_admin():
            raise HTTPException(status_code=403, detail="scope_not_allowed")
        return ctx

    async def require_admin(
        request: Request,
        tenant_id: uuid.UUID | None = None,
        authorization: str | None = Header(default=None),
    ) -> AuthContext | None:
        presented = request.headers.get(BOOTSTRAP_HEADER)
        if presented is not None:
            if bootstrap_token_matches(settings.bootstrap_token, presented):
                return None
            raise HTTPException(status_code=401, detail="unauthorized")
        ctx = await require_iam(request, authorization, None)
        if not ctx.is_admin():
            raise HTTPException(status_code=403, detail="scope_not_allowed")
        if tenant_id is not None and ctx.tenant_id != tenant_id:
            raise HTTPException(status_code=403, detail="tenant_mismatch")
        return ctx

    # --- health ----------------------------------------------------------------

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "version": __version__, "modelVersion": core.model_version}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        engine_ok = await core.engine_healthy()
        ready = engine_ok and core.model is not None
        return JSONResponse(
            status_code=200 if ready else 503,
            content={"ready": ready, "engine": engine_ok, "modelLoaded": core.model is not None},
        )

    # --- decisions -------------------------------------------------------------

    @app.post("/api/v1/decisions:check", response_model=DecisionOut)
    async def decisions_check(
        body: CheckIn,
        ctx: AuthContext = Depends(require_check_scope),
        session: AsyncSession = Depends(get_session),
    ) -> DecisionOut:
        principal = _principal(ctx, body.principal_id)
        result = await core.check(
            session,
            ctx.tenant_id,
            principal_id=principal,
            action=body.action,
            resource_type=body.resource.type,
            resource_id=body.resource.id,
            contextual=_contextual(body.context.contextual_tuples),
            as_of=body.context.as_of,
            consistency=body.consistency,
            caller_id=str(ctx.principal_id),
            correlation_id=ctx.correlation_id,
        )
        await session.commit()
        return _decision_out(result)

    @app.post("/api/v1/decisions:batch-check", response_model=BatchCheckOut)
    async def decisions_batch_check(
        body: BatchCheckIn,
        ctx: AuthContext = Depends(require_check_scope),
        session: AsyncSession = Depends(get_session),
    ) -> BatchCheckOut:
        items = [
            (
                _principal(ctx, item.principal_id),
                item.action,
                item.resource.type,
                item.resource.id,
                tuple(_contextual(item.context.contextual_tuples)),
                item.context.as_of,
            )
            for item in body.items
        ]
        consistency = "strong" if any(i.consistency == "strong" for i in body.items) else "default"
        results = await core.batch_check(
            session,
            ctx.tenant_id,
            items=items,
            consistency=consistency,
            caller_id=str(ctx.principal_id),
            correlation_id=ctx.correlation_id,
        )
        await session.commit()
        return BatchCheckOut(items=[_decision_out(r) for r in results])

    @app.post("/api/v1/decisions:list-objects", response_model=ListObjectsOut)
    async def decisions_list_objects(
        body: ListObjectsIn,
        ctx: AuthContext = Depends(require_check_scope),
        session: AsyncSession = Depends(get_session),
    ) -> ListObjectsOut:
        principal = _principal(ctx, body.principal_id)
        objects, version = await core.list_objects(
            session,
            ctx.tenant_id,
            principal_id=principal,
            action=body.action,
            resource_type=body.resource_type,
            contextual=_contextual(body.context.contextual_tuples),
            as_of=body.context.as_of,
            consistency=body.consistency,
        )
        return ListObjectsOut(
            objects=objects[: body.limit],
            cursor=None,
            model_version=str(version),
            evaluated_at=datetime.now(tz=UTC),
        )

    @app.post("/api/v1/decisions:list-subjects", response_model=ListSubjectsOut)
    async def decisions_list_subjects(
        body: ListSubjectsIn,
        ctx: AuthContext = Depends(require_check_scope),
        session: AsyncSession = Depends(get_session),
    ) -> ListSubjectsOut:
        principals, version = await core.list_subjects(
            session,
            ctx.tenant_id,
            action=body.action,
            resource_type=body.resource.type,
            resource_id=body.resource.id,
            consistency=body.consistency,
        )
        return ListSubjectsOut(principals=principals, model_version=str(version))

    @app.get("/api/v1/decisions/{decision_id}:explain", response_model=ExplainOut)
    async def decisions_explain(
        decision_id: uuid.UUID,
        ctx: AuthContext = Depends(require_check_scope),
        session: AsyncSession = Depends(get_session),
    ) -> ExplainOut:
        record, path, bindings = await core.explain(session, ctx.tenant_id, decision_id)
        return ExplainOut(
            decision_id=record.decision_id,
            allowed=record.allowed,
            reason_code=record.reason_code,
            action=record.action,
            resource=record.resource,
            principal_id=record.principal_id,
            model_version=str(record.model_version),
            evaluated_at=record.evaluated_at,
            path=path,
            binding_ids=bindings,
        )

    # --- admin: каталоги и модель -------------------------------------------------

    @app.post("/api/v1/catalogs/{service}", response_model=CatalogRegisterOut)
    async def register_catalog(
        service: str,
        body: dict[str, Any],
        _: AuthContext | None = Depends(require_admin),
        session: AsyncSession = Depends(get_session),
    ) -> CatalogRegisterOut:
        if body.get("service") != service:
            raise PolicyError("service_mismatch", 422, "service в теле не совпадает с путём")
        catalog, changed = await core.register_catalog(session, body)
        await session.commit()
        return CatalogRegisterOut(
            service=catalog.service,
            version=catalog.version,
            content_hash=catalog.content_hash,
            changed=changed,
            actions=catalog.action_names(),
        )

    @app.post("/api/v1/model-versions:publish", response_model=ModelPublishOut)
    async def publish_model(
        _: AuthContext | None = Depends(require_admin),
        session: AsyncSession = Depends(get_session),
    ) -> ModelPublishOut:
        version, created, published = await core.publish_model(session)
        await session.commit()
        return ModelPublishOut(
            version=version.version,
            catalogs_hash=version.catalogs_hash,
            tenants_published=published,
            created=created,
        )

    # --- admin: tenants ------------------------------------------------------------

    @app.post("/api/v1/tenants/{tenant_id}/stores", response_model=TenantStoreOut)
    async def ensure_tenant_store(
        tenant_id: uuid.UUID,
        _: AuthContext | None = Depends(require_admin),
        session: AsyncSession = Depends(get_session),
    ) -> TenantStoreOut:
        await core.ensure_tenant(session, tenant_id)
        await core.apply_relations(
            session,
            tenant_id,
            source="admin",
            event_id="ensure-store",
            writes=[
                RelationChange(f"memory_namespace:{tenant_id}", "tenant", f"tenant:{tenant_id}")
            ],
        )
        await session.commit()
        row = next(s for s in await core.list_stores(session) if s.tenant_id == tenant_id)
        return TenantStoreOut.model_validate(row)

    @app.get("/api/v1/tenants/{tenant_id}/stores", response_model=TenantStoreOut)
    async def get_tenant_store(
        tenant_id: uuid.UUID,
        _: AuthContext | None = Depends(require_admin),
        session: AsyncSession = Depends(get_session),
    ) -> TenantStoreOut:
        rows = [s for s in await core.list_stores(session) if s.tenant_id == tenant_id]
        if not rows:
            raise PolicyError("store_not_found", 404)
        return TenantStoreOut.model_validate(rows[0])

    # --- admin: роли ---------------------------------------------------------------

    @app.post("/api/v1/tenants/{tenant_id}/roles", response_model=RoleOut)
    async def upsert_role(
        tenant_id: uuid.UUID,
        body: RoleIn,
        _: AuthContext | None = Depends(require_admin),
        session: AsyncSession = Depends(get_session),
    ) -> RoleOut:
        role = await core.upsert_role(
            session, tenant_id, key=body.key, actions=body.actions, name=body.name, kind=body.kind
        )
        await session.commit()
        return RoleOut.model_validate(role)

    @app.get("/api/v1/tenants/{tenant_id}/roles", response_model=list[RoleOut])
    async def list_roles(
        tenant_id: uuid.UUID,
        _: AuthContext | None = Depends(require_admin),
        session: AsyncSession = Depends(get_session),
    ) -> list[RoleOut]:
        return [RoleOut.model_validate(r) for r in await core.list_roles(session, tenant_id)]

    # --- admin: bindings и delegations ---------------------------------------------

    @app.post("/api/v1/tenants/{tenant_id}/bindings", response_model=BindingOut)
    async def create_binding(
        tenant_id: uuid.UUID,
        body: BindingIn,
        ctx: AuthContext | None = Depends(require_admin),
        session: AsyncSession = Depends(get_session),
    ) -> BindingOut:
        binding = await core.create_binding(
            session,
            tenant_id,
            subject_type=body.subject.type,
            subject_id=body.subject.id,
            role_key=body.role_key,
            scope_type=body.scope.type,
            scope_id=body.scope.id,
            starts_at=body.starts_at,
            expires_at=body.expires_at,
            created_by=str(ctx.principal_id) if ctx else "bootstrap",
        )
        await session.commit()
        return BindingOut.model_validate(binding)

    @app.get("/api/v1/tenants/{tenant_id}/bindings", response_model=list[BindingOut])
    async def list_bindings(
        tenant_id: uuid.UUID,
        subject_id: str | None = Query(default=None, alias="subjectId"),
        scope_id: str | None = Query(default=None, alias="scopeId"),
        include_revoked: bool = Query(default=False, alias="includeRevoked"),
        _: AuthContext | None = Depends(require_admin),
        session: AsyncSession = Depends(get_session),
    ) -> list[BindingOut]:
        rows = await core.list_bindings(
            session,
            tenant_id,
            subject_id=subject_id,
            scope_id=scope_id,
            include_revoked=include_revoked,
        )
        return [BindingOut.model_validate(b) for b in rows]

    @app.post("/api/v1/tenants/{tenant_id}/bindings/{binding_id}:revoke", response_model=BindingOut)
    async def revoke_binding(
        tenant_id: uuid.UUID,
        binding_id: uuid.UUID,
        body: RevokeIn | None = None,
        _: AuthContext | None = Depends(require_admin),
        session: AsyncSession = Depends(get_session),
    ) -> BindingOut:
        binding = await core.revoke_binding(
            session, tenant_id, binding_id, reason=body.reason if body else ""
        )
        await session.commit()
        return BindingOut.model_validate(binding)

    @app.post("/api/v1/tenants/{tenant_id}/delegations", response_model=BindingOut)
    async def create_delegation(
        tenant_id: uuid.UUID,
        body: DelegationIn,
        ctx: AuthContext | None = Depends(require_admin),
        session: AsyncSession = Depends(get_session),
    ) -> BindingOut:
        binding = await core.create_delegation(
            session,
            tenant_id,
            delegator_id=body.delegator_id,
            delegate_id=body.delegate_id,
            role_key=body.role_key,
            scope_type=body.scope.type,
            scope_id=body.scope.id,
            starts_at=body.starts_at,
            expires_at=body.expires_at,
            created_by=str(ctx.principal_id) if ctx else "bootstrap",
        )
        await session.commit()
        return BindingOut.model_validate(binding)

    @app.post("/api/v1/tenants/{tenant_id}/decisions:simulate", response_model=DecisionOut)
    async def simulate(
        tenant_id: uuid.UUID,
        body: SimulateIn,
        _: AuthContext | None = Depends(require_admin),
        session: AsyncSession = Depends(get_session),
    ) -> DecisionOut:
        result = await core.simulate(
            session,
            tenant_id,
            principal_id=body.principal_id,
            action=body.action,
            resource_type=body.resource.type,
            resource_id=body.resource.id,
            extra_bindings=[b.model_dump() for b in body.extra_bindings],
            contextual=_contextual(body.context.contextual_tuples),
            as_of=body.context.as_of,
        )
        return _decision_out(result)

    @app.get("/api/v1/tenants/{tenant_id}/access-review", response_model=AccessReviewOut)
    async def access_review(
        tenant_id: uuid.UUID,
        _: AuthContext | None = Depends(require_admin),
        session: AsyncSession = Depends(get_session),
    ) -> AccessReviewOut:
        roles = await core.list_roles(session, tenant_id)
        bindings = await core.list_bindings(session, tenant_id, include_revoked=True)
        return AccessReviewOut(
            tenant_id=tenant_id,
            generated_at=datetime.now(tz=UTC),
            roles=[RoleOut.model_validate(r) for r in roles],
            bindings=[BindingOut.model_validate(b) for b in bindings],
        )

    # --- admin: проекция и outbox ----------------------------------------------------

    @app.get("/api/v1/projection", response_model=list[ProjectionStatusOut])
    async def projection_status(
        _: AuthContext | None = Depends(require_admin),
        session: AsyncSession = Depends(get_session),
    ) -> list[ProjectionStatusOut]:
        return [ProjectionStatusOut.model_validate(c) for c in await core.list_cursors(session)]

    @app.get("/api/v1/events", response_model=EventPageOut)
    async def list_events(
        after: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=500),
        _: AuthContext | None = Depends(require_admin),
        session: AsyncSession = Depends(get_session),
    ) -> EventPageOut:
        items, next_after = await core.list_events(session, after=after, limit=limit)
        return EventPageOut(
            items=[EventOut.model_validate(i) for i in items], next_after=next_after
        )

    return app


def _principal(ctx: AuthContext, requested: str | None) -> str:
    try:
        return ctx.resolve_principal(requested)
    except IamContextError as exc:
        raise HTTPException(status_code=403, detail="principal_not_allowed") from exc


def _contextual(items: Sequence[ContextualTupleIn]) -> list[RelationChange]:
    return [RelationChange(i.object, i.relation, i.subject) for i in items]


def _decision_out(result: DecisionResult) -> DecisionOut:
    return DecisionOut(
        allowed=result.allowed,
        reason_code=result.reason_code,
        decision_id=result.decision_id,
        policy_version=str(result.model_version),
        model_version=str(result.model_version),
        evaluated_at=result.evaluated_at,
        consistency_token=None,
        action=result.action,
        resource=result.resource,
    )


app = create_app()


def main() -> None:
    uvicorn.run("policy_service.app:app", host="0.0.0.0", port=8030)
