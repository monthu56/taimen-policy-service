from __future__ import annotations

import json

import pytest

from policy_service.catalog import CatalogError, load_catalog_file, parse_catalog
from policy_service.model_builder import build_model
from tests.conftest import catalog_paths


def _types(model: dict) -> dict[str, dict]:
    return {t["type"]: t for t in model["type_definitions"]}


def test_platform_types_and_actions() -> None:
    catalogs = [load_catalog_file(p) for p in catalog_paths()]
    model = build_model(catalogs)
    types = _types(model)
    assert model["schema_version"] == "1.1"
    assert {"principal", "group", "role", "binding", "tenant", "workspace"} <= set(types)
    # каждое действие — отношение на role/binding/tenant/workspace
    for rel in ("tasks_read", "memory_read", "org_manage"):
        assert rel in types["role"]["relations"]
        assert rel in types["binding"]["relations"]
        assert rel in types["tenant"]["relations"]
        assert rel in types["workspace"]["relations"]
    # role: wildcard principal
    meta = types["role"]["metadata"]["relations"]["tasks_read"]["directly_related_user_types"]
    assert meta == [{"type": "principal", "wildcard": {}}]
    # binding: subject с условием окна
    subj = types["binding"]["metadata"]["relations"]["subject"]["directly_related_user_types"]
    assert {"type": "principal", "condition": "active_window"} in subj
    assert {"type": "group", "relation": "member"} in subj
    assert "active_window" in model["conditions"]


def test_resource_type_expressions() -> None:
    catalogs = [load_catalog_file(p) for p in catalog_paths()]
    types = _types(build_model(catalogs))
    task = types["task"]["relations"]
    # owner or requested_by or assignee or tasks_read from scope
    children = task["tasks_read"]["union"]["child"]
    assert {"computedUserset": {"object": "", "relation": "owner"}} in children
    assert {
        "tupleToUserset": {
            "tupleset": {"object": "", "relation": "scope"},
            "computedUserset": {"object": "", "relation": "tasks_read"},
        }
    } in children
    # по умолчанию — через scope
    assert task["tasks_claim"] == {
        "tupleToUserset": {
            "tupleset": {"object": "", "relation": "scope"},
            "computedUserset": {"object": "", "relation": "tasks_claim"},
        }
    }
    # run: holder or runs_control from task
    run = types["run"]["relations"]
    assert run["task"] == {"this": {}}
    assert {"computedUserset": {"object": "", "relation": "holder"}} in run["runs_control"][
        "union"
    ]["child"]
    # approval: difference
    approval = types["approval"]["relations"]["approvals_decide"]
    assert "difference" in approval
    # memory_namespace: tenant link
    ns = types["memory_namespace"]
    assert ns["relations"]["tenant"] == {"this": {}}
    assert ns["metadata"]["relations"]["tenant"]["directly_related_user_types"] == [
        {"type": "tenant"}
    ]


def test_model_is_deterministic() -> None:
    catalogs = [load_catalog_file(p) for p in catalog_paths()]
    a = json.dumps(build_model(catalogs), sort_keys=True)
    b = json.dumps(build_model(list(reversed(catalogs))), sort_keys=True)
    assert a == b


def test_type_collision_between_services() -> None:
    one = parse_catalog(
        {"service": "a", "version": 1, "resource_types": {"doc": {"scope": "workspace"}}}
    )
    two = parse_catalog(
        {"service": "b", "version": 1, "resource_types": {"doc": {"scope": "workspace"}}}
    )
    with pytest.raises(CatalogError, match="объявлен"):
        build_model([one, two])
