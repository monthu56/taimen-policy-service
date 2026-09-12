"""Сквозные тесты API против живого OpenFGA (маркер fga)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import yaml

from tests.conftest import BOOTSTRAP_HEADERS, Environment, catalog_paths, requires_fga

pytestmark = [requires_fga, pytest.mark.fga]


def _register_and_publish(env: Environment) -> None:
    for path in catalog_paths():
        data = yaml.safe_load(path.read_text())
        r = env.client.post(
            f"/api/v1/catalogs/{data['service']}", json=data, headers=BOOTSTRAP_HEADERS
        )
        assert r.status_code == 200, r.text
    r = env.client.post("/api/v1/model-versions:publish", headers=BOOTSTRAP_HEADERS)
    assert r.status_code == 200, r.text
    assert r.json()["version"] == 1


def _tree(env: Environment, tenant: uuid.UUID) -> tuple[str, str, str]:
    """portfolio → child; sibling — отдельное поддерево (store + tuples как из проекции)."""
    r = env.client.post(f"/api/v1/tenants/{tenant}/stores", headers=BOOTSTRAP_HEADERS)
    assert r.status_code == 200, r.text
    core = env.client.app.state.core
    portfolio, child, sibling = (str(uuid.uuid4()) for _ in range(3))
    from policy_service.core import RelationChange

    async def seed() -> None:
        async with env.client.app.state.db.sessions() as session:
            await core.apply_relations(
                session,
                tenant,
                source="test",
                event_id="seed",
                writes=[
                    RelationChange(f"workspace:{portfolio}", "tenant", f"tenant:{tenant}"),
                    RelationChange(f"workspace:{sibling}", "tenant", f"tenant:{tenant}"),
                    RelationChange(f"workspace:{child}", "tenant", f"tenant:{tenant}"),
                    RelationChange(f"workspace:{child}", "parent", f"workspace:{portfolio}"),
                    RelationChange(
                        f"memory_namespace:ws-{portfolio}", "scope", f"workspace:{portfolio}"
                    ),
                ],
            )
            await session.commit()

    env.client.portal.call(seed)
    return portfolio, child, sibling


def test_check_requires_scope_and_tenant(env: Environment) -> None:
    _register_and_publish(env)
    tenant = uuid.uuid4()
    body = {"action": "tasks.read", "resource": {"type": "workspace", "id": str(uuid.uuid4())}}
    r = env.client.post("/api/v1/decisions:check", json=body)
    assert r.status_code == 401
    r = env.client.post("/api/v1/decisions:check", json=body, headers=env.auth(tenant, scopes=[]))
    assert r.status_code == 403
    r = env.client.post(
        "/api/v1/decisions:check", json=body, headers=env.auth(tenant, scopes=["policy:check"])
    )
    assert r.status_code == 200
    assert r.json() == {
        **r.json(),
        "allowed": False,
        "reasonCode": "tenant_unknown",
    }


def test_binding_inheritance_and_revoke(env: Environment) -> None:
    _register_and_publish(env)
    tenant = uuid.uuid4()
    portfolio, child, sibling = _tree(env, tenant)
    alice = uuid.uuid4()
    r = env.client.post(
        f"/api/v1/tenants/{tenant}/roles",
        json={"key": "editor", "actions": ["tasks.read", "tasks.write", "memory.read"]},
        headers=BOOTSTRAP_HEADERS,
    )
    assert r.status_code == 200, r.text
    r = env.client.post(
        f"/api/v1/tenants/{tenant}/bindings",
        json={
            "subject": {"type": "principal", "id": str(alice)},
            "roleKey": "editor",
            "scope": {"type": "workspace", "id": portfolio},
        },
        headers=BOOTSTRAP_HEADERS,
    )
    assert r.status_code == 200, r.text
    binding_id = r.json()["id"]
    headers = env.auth(tenant, subject_id=alice, scopes=["policy:check"])

    def check(ws: str, action: str = "tasks.read") -> dict:
        resp = env.client.post(
            "/api/v1/decisions:check",
            json={"action": action, "resource": {"type": "workspace", "id": ws}},
            headers=headers,
        )
        assert resp.status_code == 200, resp.text
        return resp.json()

    assert check(child)["allowed"] is True
    assert check(child)["reasonCode"] == "allowed"
    assert check(sibling)["allowed"] is False
    assert check(child, "org.manage")["allowed"] is False
    # неизвестное действие / тип
    assert check(child, "nope.read")["reasonCode"] == "unknown_action"
    resp = env.client.post(
        "/api/v1/decisions:check",
        json={"action": "tasks.read", "resource": {"type": "ghost", "id": "1"}},
        headers=headers,
    )
    assert resp.json()["reasonCode"] == "unknown_resource_type"
    # memory namespace через scope
    resp = env.client.post(
        "/api/v1/decisions:check",
        json={
            "action": "memory.read",
            "resource": {"type": "memory_namespace", "id": f"ws-{portfolio}"},
        },
        headers=headers,
    )
    assert resp.json()["allowed"] is True

    # list_objects = ровно portfolio + child
    resp = env.client.post(
        "/api/v1/decisions:list-objects",
        json={"action": "tasks.read", "resourceType": "workspace"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert set(resp.json()["objects"]) == {portfolio, child}
    resp = env.client.post(
        "/api/v1/decisions:list-objects",
        json={"action": "memory.read", "resourceType": "memory_namespace"},
        headers=headers,
    )
    assert resp.json()["objects"] == [f"ws-{portfolio}"]

    # explain по decision_id
    decision = check(child)
    resp = env.client.get(f"/api/v1/decisions/{decision['decisionId']}:explain", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["bindingIds"] == [binding_id]
    assert any(p.get("object") == f"workspace:{portfolio}" for p in resp.json()["path"])

    # отзыв → deny на strong
    r = env.client.post(
        f"/api/v1/tenants/{tenant}/bindings/{binding_id}:revoke",
        json={"reason": "test"},
        headers=BOOTSTRAP_HEADERS,
    )
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    resp = env.client.post(
        "/api/v1/decisions:check",
        json={
            "action": "tasks.read",
            "resource": {"type": "workspace", "id": child},
            "consistency": "strong",
        },
        headers=headers,
    )
    assert resp.json()["allowed"] is False
    events = env.client.get("/api/v1/events", headers=BOOTSTRAP_HEADERS).json()["items"]
    assert [e["type"] for e in events][-2:] == ["binding.created", "binding.revoked"]


def test_task_relations_and_contextual_tuples(env: Environment) -> None:
    _register_and_publish(env)
    tenant = uuid.uuid4()
    portfolio, child, _ = _tree(env, tenant)
    owner, viewer = uuid.uuid4(), uuid.uuid4()
    task = str(uuid.uuid4())
    from policy_service.core import RelationChange

    core = env.client.app.state.core

    async def seed() -> None:
        async with env.client.app.state.db.sessions() as session:
            await core.apply_relations(
                session,
                tenant,
                source="test",
                event_id="task",
                writes=[
                    RelationChange(f"task:{task}", "scope", f"workspace:{child}"),
                    RelationChange(f"task:{task}", "owner", f"principal:{owner}"),
                ],
            )
            await session.commit()

    env.client.portal.call(seed)
    owner_headers = env.auth(tenant, subject_id=owner, scopes=["policy:check"])
    r = env.client.post(
        "/api/v1/decisions:check",
        json={"action": "tasks.write", "resource": {"type": "task", "id": task}},
        headers=owner_headers,
    )
    assert r.json()["allowed"] is True
    viewer_headers = env.auth(tenant, subject_id=viewer, scopes=["policy:check"])
    r = env.client.post(
        "/api/v1/decisions:check",
        json={"action": "tasks.read", "resource": {"type": "task", "id": task}},
        headers=viewer_headers,
    )
    assert r.json()["allowed"] is False
    # contextual: assignee даёт чтение
    r = env.client.post(
        "/api/v1/decisions:check",
        json={
            "action": "tasks.read",
            "resource": {"type": "task", "id": task},
            "context": {
                "contextualTuples": [
                    {
                        "object": f"task:{task}",
                        "relation": "assignee",
                        "subject": f"principal:{viewer}",
                    }
                ]
            },
        },
        headers=viewer_headers,
    )
    assert r.json()["allowed"] is True
    # contextual binding — запрещён (эскалация)
    r = env.client.post(
        "/api/v1/decisions:check",
        json={
            "action": "tasks.read",
            "resource": {"type": "task", "id": task},
            "context": {
                "contextualTuples": [
                    {"object": "binding:x", "relation": "subject", "subject": f"principal:{viewer}"}
                ]
            },
        },
        headers=viewer_headers,
    )
    assert r.status_code == 400 and r.json()["detail"] == "contextual_tuple_not_allowed"
    # on-behalf без scope — 403; со scope — решение за owner
    r = env.client.post(
        "/api/v1/decisions:check",
        json={
            "principalId": str(owner),
            "action": "tasks.write",
            "resource": {"type": "task", "id": task},
        },
        headers=viewer_headers,
    )
    assert r.status_code == 403
    r = env.client.post(
        "/api/v1/decisions:check",
        json={
            "principalId": str(owner),
            "action": "tasks.write",
            "resource": {"type": "task", "id": task},
        },
        headers=env.auth(tenant, scopes=["policy:check", "policy:check-on-behalf"]),
    )
    assert r.json()["allowed"] is True
    # batch
    r = env.client.post(
        "/api/v1/decisions:batch-check",
        json={
            "items": [
                {"action": "tasks.write", "resource": {"type": "task", "id": task}},
                {"action": "tasks.read", "resource": {"type": "workspace", "id": portfolio}},
                {"action": "nope.x", "resource": {"type": "task", "id": task}},
            ]
        },
        headers=owner_headers,
    )
    assert [i["allowed"] for i in r.json()["items"]] == [True, False, False]
    assert r.json()["items"][2]["reasonCode"] == "unknown_action"
    # list_subjects по задаче
    r = env.client.post(
        "/api/v1/decisions:list-subjects",
        json={"action": "tasks.write", "resource": {"type": "task", "id": task}},
        headers=owner_headers,
    )
    assert r.json()["principals"] == [str(owner)]


def test_delegation_window_and_ceiling(env: Environment) -> None:
    _register_and_publish(env)
    tenant = uuid.uuid4()
    portfolio, child, _ = _tree(env, tenant)
    delegator, delegate = uuid.uuid4(), uuid.uuid4()
    env.client.post(
        f"/api/v1/tenants/{tenant}/roles",
        json={"key": "viewer", "actions": ["tasks.read"]},
        headers=BOOTSTRAP_HEADERS,
    )
    env.client.post(
        f"/api/v1/tenants/{tenant}/roles",
        json={"key": "editor", "actions": ["tasks.read", "tasks.write"]},
        headers=BOOTSTRAP_HEADERS,
    )
    r = env.client.post(
        f"/api/v1/tenants/{tenant}/bindings",
        json={
            "subject": {"type": "principal", "id": str(delegator)},
            "roleKey": "viewer",
            "scope": {"type": "workspace", "id": portfolio},
        },
        headers=BOOTSTRAP_HEADERS,
    )
    assert r.status_code == 200
    expires = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    # шире прав делегатора — reject
    r = env.client.post(
        f"/api/v1/tenants/{tenant}/delegations",
        json={
            "delegatorId": str(delegator),
            "delegateId": str(delegate),
            "roleKey": "editor",
            "scope": {"type": "workspace", "id": portfolio},
            "expiresAt": expires,
        },
        headers=BOOTSTRAP_HEADERS,
    )
    assert r.status_code == 422 and r.json()["detail"] == "delegation_exceeds_delegator"
    r = env.client.post(
        f"/api/v1/tenants/{tenant}/delegations",
        json={
            "delegatorId": str(delegator),
            "delegateId": str(delegate),
            "roleKey": "viewer",
            "scope": {"type": "workspace", "id": portfolio},
            "expiresAt": expires,
        },
        headers=BOOTSTRAP_HEADERS,
    )
    assert r.status_code == 200, r.text
    assert r.json()["source"] == "delegation"
    headers = env.auth(tenant, subject_id=delegate, scopes=["policy:check"])
    r = env.client.post(
        "/api/v1/decisions:check",
        json={"action": "tasks.read", "resource": {"type": "workspace", "id": child}},
        headers=headers,
    )
    assert r.json()["allowed"] is True
    # после окна — deny
    later = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    r = env.client.post(
        "/api/v1/decisions:check",
        json={
            "action": "tasks.read",
            "resource": {"type": "workspace", "id": child},
            "context": {"asOf": later},
        },
        headers=headers,
    )
    assert r.json()["allowed"] is False
    # simulate: what-if editor на portfolio
    r = env.client.post(
        f"/api/v1/tenants/{tenant}/decisions:simulate",
        json={
            "principalId": str(delegate),
            "action": "tasks.write",
            "resource": {"type": "workspace", "id": child},
            "extraBindings": [
                {
                    "subject": {"type": "principal", "id": str(delegate)},
                    "roleKey": "editor",
                    "scope": {"type": "workspace", "id": portfolio},
                }
            ],
        },
        headers=BOOTSTRAP_HEADERS,
    )
    assert r.status_code == 200 and r.json()["allowed"] is True
    review = env.client.get(f"/api/v1/tenants/{tenant}/access-review", headers=BOOTSTRAP_HEADERS)
    assert len(review.json()["bindings"]) == 2


def test_admin_requires_bootstrap_or_admin_scope(env: Environment) -> None:
    tenant = uuid.uuid4()
    r = env.client.get(f"/api/v1/tenants/{tenant}/roles")
    assert r.status_code == 401
    r = env.client.get(
        f"/api/v1/tenants/{tenant}/roles", headers={"X-Policy-Bootstrap-Token": "bad"}
    )
    assert r.status_code == 401
    r = env.client.get(
        f"/api/v1/tenants/{tenant}/roles", headers=env.auth(tenant, scopes=["policy:check"])
    )
    assert r.status_code == 403
    r = env.client.get(
        f"/api/v1/tenants/{uuid.uuid4()}/roles", headers=env.auth(tenant, scopes=["policy:admin"])
    )
    assert r.status_code == 403
    r = env.client.get(
        f"/api/v1/tenants/{tenant}/roles", headers=env.auth(tenant, scopes=["policy:admin"])
    )
    assert r.status_code == 200 and r.json() == []
