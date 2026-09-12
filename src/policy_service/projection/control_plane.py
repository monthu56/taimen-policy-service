"""Проекция журнала Control Plane (дизайн v0 §8).

| Событие | Tuples |
|---|---|
| workspace.created / moved | workspace#tenant, workspace#parent; корень → memory_namespace#scope |
| task.created / updated | task#scope, task#owner, task#assignee, task#requested_by |
| run.started | run#task, run#holder |
| approval.requested | approval#scope (через scope задачи), approval#requested_by |
| artifact.created | artifact#task |
| project.created / updated | project_profile#scope, project_profile#owner |

Поля, которых в payload сегодня нет (owner на создании задачи), берутся из
`changes` при обновлении; до расширения журнала в Control Plane (P2)
проекция консервативна: недостающее отношение означает deny, не allow.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from policy_service.core import PolicyCore, RelationChange
from policy_service.projection.runner import SourceEvent

TokenProvider = Callable[[], Awaitable[str]]


class ControlPlaneSource:
    name = "control-plane"

    def __init__(
        self,
        base_url: str,
        token_provider: TokenProvider,
        *,
        client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token_provider = token_provider
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)

    async def fetch(self, cursor: str, limit: int) -> tuple[list[SourceEvent], str]:
        params: dict[str, Any] = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        token = await self._token_provider()
        response = await self._client.get(
            f"{self._base_url}/api/v1/events",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        body = response.json()
        events = [
            SourceEvent(
                id=str(item.get("id", "")),
                tenant_id=uuid.UUID(str(item["tenantId"])) if item.get("tenantId") else None,
                type=str(item.get("type", "")),
                payload=dict(item.get("payload") or {}),
                actor_id=str(item["actorId"]) if item.get("actorId") else None,
                entity_id=str(item.get("entityId", "")),
            )
            for item in body.get("items", [])
        ]
        return events, str(body.get("nextCursor") or cursor)

    async def apply(self, core: PolicyCore, session: AsyncSession, event: SourceEvent) -> None:
        if event.tenant_id is None:
            return
        handler = _HANDLERS.get(event.type)
        if handler is None:
            return
        await handler(core, session, event)


async def _workspace_created(core: PolicyCore, session: AsyncSession, ev: SourceEvent) -> None:
    assert ev.tenant_id is not None
    ws = f"workspace:{ev.entity_id}"
    writes = [RelationChange(ws, "tenant", f"tenant:{ev.tenant_id}")]
    parent = ev.payload.get("parentId")
    if parent:
        writes.append(RelationChange(ws, "parent", f"workspace:{parent}"))
    else:
        writes.append(RelationChange(f"memory_namespace:{ev.entity_id}", "scope", ws))
    await core.apply_relations(
        session, ev.tenant_id, source="control-plane", event_id=ev.id, writes=writes
    )


async def _workspace_moved(core: PolicyCore, session: AsyncSession, ev: SourceEvent) -> None:
    assert ev.tenant_id is not None
    ws = f"workspace:{ev.entity_id}"
    to_parent = ev.payload.get("toParentId")
    await core.replace_relation(
        session,
        ev.tenant_id,
        source="control-plane",
        event_id=ev.id,
        object=ws,
        relation="parent",
        subject=f"workspace:{to_parent}" if to_parent else None,
    )
    ns = RelationChange(f"memory_namespace:{ev.entity_id}", "scope", ws)
    if to_parent:
        await core.apply_relations(
            session, ev.tenant_id, source="control-plane", event_id=ev.id, deletes=[ns]
        )
    else:
        await core.apply_relations(
            session, ev.tenant_id, source="control-plane", event_id=ev.id, writes=[ns]
        )


async def _task_created(core: PolicyCore, session: AsyncSession, ev: SourceEvent) -> None:
    assert ev.tenant_id is not None
    task = f"task:{ev.entity_id}"
    writes: list[RelationChange] = []
    if ev.payload.get("workspaceId"):
        writes.append(RelationChange(task, "scope", f"workspace:{ev.payload['workspaceId']}"))
    if ev.actor_id:
        writes.append(RelationChange(task, "requested_by", f"principal:{ev.actor_id}"))
    for key, relation in (("ownerId", "owner"), ("assigneeId", "assignee")):
        if ev.payload.get(key):
            writes.append(RelationChange(task, relation, f"principal:{ev.payload[key]}"))
    await core.apply_relations(
        session, ev.tenant_id, source="control-plane", event_id=ev.id, writes=writes
    )


async def _task_updated(core: PolicyCore, session: AsyncSession, ev: SourceEvent) -> None:
    assert ev.tenant_id is not None
    task = f"task:{ev.entity_id}"
    changes = ev.payload.get("changes") or {}
    for key, relation, prefix in (
        ("workspace_id", "scope", "workspace:"),
        ("owner_id", "owner", "principal:"),
        ("assignee_id", "assignee", "principal:"),
    ):
        if key in changes:
            value = changes[key]
            await core.replace_relation(
                session,
                ev.tenant_id,
                source="control-plane",
                event_id=ev.id,
                object=task,
                relation=relation,
                subject=f"{prefix}{value}" if value else None,
            )


async def _run_started(core: PolicyCore, session: AsyncSession, ev: SourceEvent) -> None:
    assert ev.tenant_id is not None
    run = f"run:{ev.entity_id}"
    writes: list[RelationChange] = []
    if ev.payload.get("taskId"):
        writes.append(RelationChange(run, "task", f"task:{ev.payload['taskId']}"))
    if ev.actor_id:
        writes.append(RelationChange(run, "holder", f"principal:{ev.actor_id}"))
    await core.apply_relations(
        session, ev.tenant_id, source="control-plane", event_id=ev.id, writes=writes
    )


async def _approval_requested(core: PolicyCore, session: AsyncSession, ev: SourceEvent) -> None:
    assert ev.tenant_id is not None
    approval = f"approval:{ev.entity_id}"
    writes: list[RelationChange] = []
    task_id = ev.payload.get("taskId")
    if task_id:
        scopes = await core.current_subjects(
            session, ev.tenant_id, object=f"task:{task_id}", relation="scope"
        )
        for scope in scopes[:1]:
            writes.append(RelationChange(approval, "scope", scope))
    if ev.actor_id:
        writes.append(RelationChange(approval, "requested_by", f"principal:{ev.actor_id}"))
    await core.apply_relations(
        session, ev.tenant_id, source="control-plane", event_id=ev.id, writes=writes
    )


async def _artifact_created(core: PolicyCore, session: AsyncSession, ev: SourceEvent) -> None:
    assert ev.tenant_id is not None
    if not ev.payload.get("taskId"):
        return
    await core.apply_relations(
        session,
        ev.tenant_id,
        source="control-plane",
        event_id=ev.id,
        writes=[RelationChange(f"artifact:{ev.entity_id}", "task", f"task:{ev.payload['taskId']}")],
    )


async def _project_created(core: PolicyCore, session: AsyncSession, ev: SourceEvent) -> None:
    assert ev.tenant_id is not None
    project = f"project_profile:{ev.entity_id}"
    writes: list[RelationChange] = []
    if ev.payload.get("workspaceId"):
        writes.append(RelationChange(project, "scope", f"workspace:{ev.payload['workspaceId']}"))
    owner = ev.payload.get("ownerPrincipalId") or ev.actor_id
    if owner:
        writes.append(RelationChange(project, "owner", f"principal:{owner}"))
    await core.apply_relations(
        session, ev.tenant_id, source="control-plane", event_id=ev.id, writes=writes
    )


async def _project_updated(core: PolicyCore, session: AsyncSession, ev: SourceEvent) -> None:
    assert ev.tenant_id is not None
    changes = ev.payload.get("changes") or {}
    if "owner_principal_id" in changes:
        value = changes["owner_principal_id"]
        await core.replace_relation(
            session,
            ev.tenant_id,
            source="control-plane",
            event_id=ev.id,
            object=f"project_profile:{ev.entity_id}",
            relation="owner",
            subject=f"principal:{value}" if value else None,
        )


_HANDLERS: dict[str, Callable[[PolicyCore, AsyncSession, SourceEvent], Awaitable[None]]] = {
    "workspace.created": _workspace_created,
    "workspace.moved": _workspace_moved,
    "task.created": _task_created,
    "task.updated": _task_updated,
    "run.started": _run_started,
    "approval.requested": _approval_requested,
    "artifact.created": _artifact_created,
    "project.created": _project_created,
    "project.updated": _project_updated,
}
