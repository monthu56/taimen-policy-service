"""Проекция журнала Control Plane и IAM через подменённый httpx-транспорт."""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import pytest
import yaml
from tests.conftest import BOOTSTRAP_HEADERS, Environment, catalog_paths, requires_fga

from policy_service.core import RelationChange
from policy_service.projection import ControlPlaneSource, IamSource, ProjectionRunner

pytestmark = [requires_fga, pytest.mark.fga]


class Journal:
    """Заглушка GET /api/v1/events с непрозрачным курсором = индекс."""

    def __init__(self, events: list[dict[str, Any]]) -> None:
        self.events = events

    def handler(self, request: httpx.Request) -> httpx.Response:
        cursor = request.url.params.get("cursor") or "0"
        start = int(cursor)
        limit = int(request.url.params.get("limit") or 100)
        items = self.events[start : start + limit]
        return httpx.Response(
            200,
            json={
                "items": items,
                "nextCursor": str(start + len(items)),
                "hasMore": start + len(items) < len(self.events),
            },
        )


class IamJournal:
    def __init__(self, events: list[dict[str, Any]]) -> None:
        self.events = events

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.headers.get("X-IAM-Bootstrap-Token") == "iam-bootstrap"
        after = int(request.url.params.get("after") or 0)
        items = [e for e in self.events if e["sequence"] > after]
        return httpx.Response(200, json={"items": items, "next_after": None})


def _event(
    tenant: uuid.UUID, etype: str, entity: str, payload: dict[str, Any], actor: str | None = None
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "tenantId": str(tenant),
        "type": etype,
        "entityType": etype.split(".")[0],
        "entityId": entity,
        "actorId": actor,
        "payload": payload,
    }


def test_control_plane_projection(env: Environment) -> None:
    for path in catalog_paths():
        data = yaml.safe_load(path.read_text())
        env.client.post(f"/api/v1/catalogs/{data['service']}", json=data, headers=BOOTSTRAP_HEADERS)
    env.client.post("/api/v1/model-versions:publish", headers=BOOTSTRAP_HEADERS)
    tenant = uuid.uuid4()
    portfolio, child, other = (str(uuid.uuid4()) for _ in range(3))
    alice, bob = str(uuid.uuid4()), str(uuid.uuid4())
    task, run, approval, project = (str(uuid.uuid4()) for _ in range(4))
    journal = Journal(
        [
            _event(tenant, "workspace.created", portfolio, {"parentId": None}),
            _event(tenant, "workspace.created", child, {"parentId": portfolio}),
            _event(tenant, "workspace.created", other, {"parentId": None}),
            _event(tenant, "task.created", task, {"workspaceId": child}, actor=alice),
            _event(tenant, "task.updated", task, {"changes": {"assignee_id": bob}}),
            _event(tenant, "run.started", run, {"taskId": task}, actor=bob),
            _event(tenant, "approval.requested", approval, {"taskId": task}, actor=alice),
            _event(tenant, "project.created", project, {"workspaceId": portfolio}, actor=alice),
            _event(
                tenant, "workspace.moved", child, {"fromParentId": portfolio, "toParentId": other}
            ),
        ]
    )
    core = env.client.app.state.core
    sessions = env.client.app.state.db.sessions

    async def token() -> str:
        return "cp-token"

    source = ControlPlaneSource(
        "http://cp.test",
        token,
        client=httpx.AsyncClient(transport=httpx.MockTransport(journal.handler)),
    )

    async def run_projection() -> int:
        runner = ProjectionRunner(core, sessions, [source], poll_seconds=0)
        return await runner.run_once()

    applied = env.client.portal.call(run_projection)
    assert applied == len(journal.events)
    status = env.client.get("/api/v1/projection", headers=BOOTSTRAP_HEADERS).json()
    assert status[0]["eventsApplied"] == len(journal.events) and status[0]["lastError"] == ""

    # роль viewer на portfolio для carol → задача переехала в other, поэтому deny;
    # bob как assignee и holder видит задачу и управляет run
    carol = str(uuid.uuid4())
    env.client.post(
        f"/api/v1/tenants/{tenant}/roles",
        json={"key": "viewer", "actions": ["tasks.read", "runs.control", "projects.read"]},
        headers=BOOTSTRAP_HEADERS,
    )
    env.client.post(
        f"/api/v1/tenants/{tenant}/bindings",
        json={
            "subject": {"type": "principal", "id": carol},
            "roleKey": "viewer",
            "scope": {"type": "workspace", "id": portfolio},
        },
        headers=BOOTSTRAP_HEADERS,
    )

    def check(principal: str, action: str, rtype: str, rid: str) -> bool:
        r = env.client.post(
            "/api/v1/decisions:check",
            json={
                "action": action,
                "resource": {"type": rtype, "id": rid},
                "consistency": "strong",
            },
            headers=env.auth(tenant, subject_id=principal, scopes=["policy:check"]),
        )
        assert r.status_code == 200, r.text
        return bool(r.json()["allowed"])

    assert check(carol, "tasks.read", "task", task) is False  # child уехал под other
    assert check(carol, "projects.read", "project_profile", project) is True
    assert check(alice, "tasks.read", "task", task) is True  # requested_by
    assert check(bob, "tasks.read", "task", task) is True  # assignee
    assert check(bob, "runs.control", "run", run) is True  # holder
    assert check(carol, "runs.control", "run", run) is False
    assert check(alice, "approvals.decide", "approval", approval) is False  # requested_by
    # namespace памяти корневого воркспейса: portfolio есть, child (после move — не корень) нет
    r = env.client.post(
        "/api/v1/decisions:list-objects",
        json={"action": "memory.read", "resourceType": "memory_namespace", "consistency": "strong"},
        headers=env.auth(tenant, subject_id=carol, scopes=["policy:check"]),
    )
    assert r.json()["objects"] == []  # у viewer нет memory.read
    env.client.post(
        f"/api/v1/tenants/{tenant}/roles",
        json={
            "key": "viewer",
            "actions": ["tasks.read", "runs.control", "projects.read", "memory.read"],
        },
        headers=BOOTSTRAP_HEADERS,
    )
    r = env.client.post(
        "/api/v1/decisions:list-objects",
        json={"action": "memory.read", "resourceType": "memory_namespace", "consistency": "strong"},
        headers=env.auth(tenant, subject_id=carol, scopes=["policy:check"]),
    )
    assert r.json()["objects"] == [portfolio]

    # повторный прогон того же журнала идемпотентен
    async def rerun() -> None:
        async with sessions() as session:
            cursor = await core.get_cursor(session, "control-plane")
            cursor.cursor = "0"
            await session.commit()
        runner = ProjectionRunner(core, sessions, [source], poll_seconds=0)
        await runner.run_once()

    env.client.portal.call(rerun)
    assert check(bob, "tasks.read", "task", task) is True


def test_iam_projection_groups_and_disable(env: Environment) -> None:
    for path in catalog_paths():
        data = yaml.safe_load(path.read_text())
        env.client.post(f"/api/v1/catalogs/{data['service']}", json=data, headers=BOOTSTRAP_HEADERS)
    env.client.post("/api/v1/model-versions:publish", headers=BOOTSTRAP_HEADERS)
    tenant = uuid.uuid4()
    group, dave = str(uuid.uuid4()), str(uuid.uuid4())
    iam_events = [
        {
            "sequence": 1,
            "tenant_id": str(tenant),
            "type": "tenant.created",
            "aggregate_id": str(tenant),
            "payload": {},
        },
        {
            "sequence": 2,
            "tenant_id": str(tenant),
            "type": "principal.created",
            "aggregate_id": dave,
            "payload": {"principalId": dave, "kind": "human"},
        },
        {
            "sequence": 3,
            "tenant_id": str(tenant),
            "type": "group_membership.added",
            "aggregate_id": group,
            "payload": {"groupId": group, "principalId": dave},
        },
    ]
    core = env.client.app.state.core
    sessions = env.client.app.state.db.sessions
    iam = IamSource(
        "http://iam.test",
        "iam-bootstrap",
        client=httpx.AsyncClient(transport=httpx.MockTransport(IamJournal(iam_events).handler)),
    )
    env.client.portal.call(ProjectionRunner(core, sessions, [iam], poll_seconds=0).run_once)

    env.client.post(
        f"/api/v1/tenants/{tenant}/roles",
        json={"key": "reader", "actions": ["org.manage", "memory.read"]},
        headers=BOOTSTRAP_HEADERS,
    )
    r = env.client.post(
        f"/api/v1/tenants/{tenant}/bindings",
        json={
            "subject": {"type": "group", "id": group},
            "roleKey": "reader",
            "scope": {"type": "tenant", "id": str(tenant)},
        },
        headers=BOOTSTRAP_HEADERS,
    )
    assert r.status_code == 200, r.text
    headers = env.auth(tenant, subject_id=dave, scopes=["policy:check"])
    r = env.client.post(
        "/api/v1/decisions:check",
        json={
            "action": "org.manage",
            "resource": {"type": "tenant", "id": str(tenant)},
            "consistency": "strong",
        },
        headers=headers,
    )
    assert r.json()["allowed"] is True
    # приватный namespace principal и общий namespace tenant
    r = env.client.post(
        "/api/v1/decisions:list-objects",
        json={"action": "memory.read", "resourceType": "memory_namespace", "consistency": "strong"},
        headers=headers,
    )
    assert set(r.json()["objects"]) == {dave, str(tenant)}

    # отключение principal отзывает его прямые bindings
    env.client.post(
        f"/api/v1/tenants/{tenant}/bindings",
        json={
            "subject": {"type": "principal", "id": dave},
            "roleKey": "reader",
            "scope": {"type": "tenant", "id": str(tenant)},
        },
        headers=BOOTSTRAP_HEADERS,
    )
    iam_events.append(
        {
            "sequence": 4,
            "tenant_id": str(tenant),
            "type": "principal.disabled",
            "aggregate_id": dave,
            "payload": {"principalId": dave},
        }
    )
    env.client.portal.call(ProjectionRunner(core, sessions, [iam], poll_seconds=0).run_once)
    bindings = env.client.get(
        f"/api/v1/tenants/{tenant}/bindings",
        params={"subjectId": dave, "includeRevoked": "true"},
        headers=BOOTSTRAP_HEADERS,
    ).json()
    assert [b["status"] for b in bindings] == ["revoked"]
    assert json.loads(json.dumps(bindings[0]))["revokeReason"] == "principal_disabled"


def test_apply_relations_is_idempotent(env: Environment) -> None:
    for path in catalog_paths():
        data = yaml.safe_load(path.read_text())
        env.client.post(f"/api/v1/catalogs/{data['service']}", json=data, headers=BOOTSTRAP_HEADERS)
    env.client.post("/api/v1/model-versions:publish", headers=BOOTSTRAP_HEADERS)
    tenant = uuid.uuid4()
    core = env.client.app.state.core
    sessions = env.client.app.state.db.sessions
    ws = str(uuid.uuid4())

    async def twice() -> list[str]:
        async with sessions() as session:
            change = RelationChange(f"workspace:{ws}", "tenant", f"tenant:{tenant}")
            await core.apply_relations(session, tenant, source="t", event_id="1", writes=[change])
            await core.apply_relations(session, tenant, source="t", event_id="2", writes=[change])
            await session.commit()
            return await core.current_subjects(
                session, tenant, object=f"workspace:{ws}", relation="tenant"
            )

    assert env.client.portal.call(twice) == [f"tenant:{tenant}"]
