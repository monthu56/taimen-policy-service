from __future__ import annotations

import pytest
from tests.conftest import catalog_paths

from policy_service.catalog import (
    CatalogError,
    load_catalog_file,
    parse_catalog,
    parse_expression,
    relation_name,
)


def test_expression_grammar() -> None:
    assert parse_expression("owner") == ("rel", "owner")
    assert parse_expression("tasks.read@scope") == ("via", "tasks.read", "scope")
    assert parse_expression("a or b or c") == ("or", [("rel", "a"), ("rel", "b"), ("rel", "c")])
    assert parse_expression("a and b@scope") == ("and", [("rel", "a"), ("via", "b", "scope")])
    assert parse_expression("x@scope but not y") == ("butnot", ("via", "x", "scope"), ("rel", "y"))
    assert parse_expression("(a or b) and c") == (
        "and",
        [("or", [("rel", "a"), ("rel", "b")]), ("rel", "c")],
    )


@pytest.mark.parametrize("text", ["", "a or", "or a", "a @", "a b", "(a", "a)"])
def test_expression_errors(text: str) -> None:
    with pytest.raises(CatalogError):
        parse_expression(text)


def test_relation_name() -> None:
    assert relation_name("tasks.read") == "tasks_read"


def test_real_catalogs_parse() -> None:
    catalogs = [load_catalog_file(p) for p in catalog_paths()]
    services = {c.service for c in catalogs}
    assert {"control-plane", "memory-service"} <= services
    cp = next(c for c in catalogs if c.service == "control-plane")
    assert "tasks.read" in cp.actions
    assert cp.resource_types["run"].parent == "task"
    mem = next(c for c in catalogs if c.service == "memory-service")
    assert mem.resource_types["memory_namespace"].tenant_link


@pytest.mark.parametrize(
    ("data", "fragment"),
    [
        ({"service": "x", "version": 0}, "version"),
        ({"service": "x", "version": 1, "resource_types": {"tenant": {}}}, "встроенный"),
        ({"service": "x", "version": 1, "resource_types": {"doc": {}}}, "недостижим"),
        (
            {
                "service": "x",
                "version": 1,
                "resource_types": {"doc": {"scope": "workspace", "relations": ["scope"]}},
            },
            "зарезервировано",
        ),
        (
            {"service": "x", "version": 1, "actions": {"docs.read": {"resource": "ghost"}}},
            "неизвестный тип",
        ),
        (
            {
                "service": "x",
                "version": 1,
                "resource_types": {"doc": {"scope": "workspace"}},
                "actions": {"docs.read": {"resource": "doc", "derived": "editor"}},
            },
            "не является отношением",
        ),
        (
            {
                "service": "x",
                "version": 1,
                "resource_types": {"doc": {"scope": "workspace"}},
                "actions": {"docs.read": {"resource": "doc", "derived": "docs.read@parent"}},
            },
            "не структурное",
        ),
        (
            {
                "service": "x",
                "version": 1,
                "actions": {"docs.read": {"resource": "workspace", "derived": "x"}},
            },
            "выводится из bindings",
        ),
        (
            {"service": "x", "version": 1, "actions": {"bad": {"resource": "workspace"}}},
            "имя действия",
        ),
    ],
)
def test_catalog_validation_errors(data: dict, fragment: str) -> None:
    with pytest.raises(CatalogError, match=fragment):
        parse_catalog(data)


def test_catalog_hash_is_canonical() -> None:
    a = parse_catalog(
        {"service": "svc", "version": 1, "actions": {"a.read": {"resource": "tenant"}}}
    )
    b = parse_catalog(
        {"version": 1, "actions": {"a.read": {"resource": "tenant"}}, "service": "svc"}
    )
    assert a.content_hash == b.content_hash
