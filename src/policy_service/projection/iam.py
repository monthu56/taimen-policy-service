"""Проекция outbox IAM: tenants, группы, membership, отзыв principal.

| Событие | Действие |
|---|---|
| tenant.created | store tenant, memory_namespace:tenant-<id>#tenant |
| principal.created | memory_namespace:principal-<id>#owner |
| group_membership.added / removed | group#member |
| principal.disabled, credential.revoked (principal) | отзыв всех bindings subject и его делегаций |
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from policy_service.core import PolicyCore, RelationChange
from policy_service.projection.runner import SourceEvent


class IamSource:
    name = "iam"

    def __init__(
        self,
        base_url: str,
        bootstrap_token: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = bootstrap_token
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)

    async def fetch(self, cursor: str, limit: int) -> tuple[list[SourceEvent], str]:
        after = int(cursor) if cursor.isdigit() else 0
        response = await self._client.get(
            f"{self._base_url}/api/v1/events",
            params={"after": after, "limit": min(limit, 500)},
            headers={"X-IAM-Bootstrap-Token": self._token},
        )
        response.raise_for_status()
        body = response.json()
        events: list[SourceEvent] = []
        last = after
        for item in body.get("items", []):
            seq = int(item.get("sequence", 0))
            last = max(last, seq)
            events.append(
                SourceEvent(
                    id=str(seq),
                    tenant_id=_uuid(item.get("tenant_id") or item.get("tenantId")),
                    type=str(item.get("type", "")),
                    payload=dict(item.get("payload") or {}),
                    entity_id=str(item.get("aggregate_id") or item.get("aggregateId") or ""),
                )
            )
        return events, str(last)

    async def apply(self, core: PolicyCore, session: AsyncSession, event: SourceEvent) -> None:
        if event.tenant_id is None:
            return
        tenant = event.tenant_id
        if event.type == "tenant.created":
            await core.ensure_tenant(session, tenant)
            await core.apply_relations(
                session,
                tenant,
                source="iam",
                event_id=event.id,
                writes=[
                    RelationChange(
                        f"memory_namespace:tenant-{tenant}", "tenant", f"tenant:{tenant}"
                    )
                ],
            )
        elif event.type == "principal.created":
            pid = event.payload.get("principalId") or event.entity_id
            if pid:
                await core.apply_relations(
                    session,
                    tenant,
                    source="iam",
                    event_id=event.id,
                    writes=[
                        RelationChange(
                            f"memory_namespace:principal-{pid}", "owner", f"principal:{pid}"
                        )
                    ],
                )
        elif event.type in {"group_membership.added", "group_membership.removed"}:
            group = event.payload.get("groupId") or event.entity_id
            pid = event.payload.get("principalId")
            if group and pid:
                change = RelationChange(f"group:{group}", "member", f"principal:{pid}")
                if event.type.endswith("added"):
                    await core.apply_relations(
                        session, tenant, source="iam", event_id=event.id, writes=[change]
                    )
                else:
                    await core.apply_relations(
                        session, tenant, source="iam", event_id=event.id, deletes=[change]
                    )
        elif event.type == "principal.disabled":
            pid = event.payload.get("principalId") or event.entity_id
            if pid:
                await core.revoke_subject_bindings(
                    session, tenant, subject_id=str(pid), reason="principal_disabled"
                )


def _uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value)) if value else None
    except ValueError:
        return None
