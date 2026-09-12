"""Сборка модели авторизации OpenFGA из каталогов сервисов (дизайн v0, раздел 5).

Инварианты модели, которые каталоги менять не могут:

* `principal`, `group#member`, `role`, `binding`, `tenant`, `workspace` —
  платформенные типы; каждое действие любого каталога становится отношением
  на `role` (wildcard `principal:*`), `binding` (`subject and A from role`),
  `tenant` (`A from binding`) и `workspace` (`A from binding or A from parent
  or A from tenant`);
* delegation — тот же binding, но subject с условием `active_window`;
* типы ресурсов из каталогов получают структурные отношения (`scope`,
  parent) и прямые отношения к principal, а действия — по выражению
  `derived` или по умолчанию через scope/parent.

Результат детерминирован: одинаковые каталоги дают байт-в-байт одинаковый JSON,
поэтому версия модели вычисляется от хэша каталогов.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from policy_service.catalog import (
    SCOPE_TYPES,
    Catalog,
    CatalogError,
    Expr,
    ResourceType,
    parse_expression,
    relation_name,
)

SCHEMA_VERSION = "1.1"
ACTIVE_WINDOW = "active_window"


def _this() -> dict[str, Any]:
    return {"this": {}}


def _computed(relation: str) -> dict[str, Any]:
    return {"computedUserset": {"object": "", "relation": relation}}


def _via(tupleset: str, relation: str) -> dict[str, Any]:
    return {
        "tupleToUserset": {
            "tupleset": {"object": "", "relation": tupleset},
            "computedUserset": {"object": "", "relation": relation},
        }
    }


def _union(children: list[dict[str, Any]]) -> dict[str, Any]:
    return children[0] if len(children) == 1 else {"union": {"child": children}}


def _intersection(children: list[dict[str, Any]]) -> dict[str, Any]:
    return children[0] if len(children) == 1 else {"intersection": {"child": children}}


def _difference(base: dict[str, Any], subtract: dict[str, Any]) -> dict[str, Any]:
    return {"difference": {"base": base, "subtract": subtract}}


def _direct(*types: dict[str, Any]) -> dict[str, Any]:
    return {"directly_related_user_types": list(types)}


def build_model(catalogs: Iterable[Catalog]) -> dict[str, Any]:
    catalogs = sorted(catalogs, key=lambda c: c.service)
    actions = sorted({name for c in catalogs for name in c.actions})
    action_relations = [relation_name(a) for a in actions]
    type_defs: list[dict[str, Any]] = [{"type": "principal"}]

    type_defs.append(
        {
            "type": "group",
            "relations": {"member": _this()},
            "metadata": {"relations": {"member": _direct({"type": "principal"})}},
        }
    )

    # role: набор действий; tuple role:r#A@principal:* включает действие в роль
    type_defs.append(
        {
            "type": "role",
            "relations": {rel: _this() for rel in action_relations},
            "metadata": {
                "relations": {
                    rel: _direct({"type": "principal", "wildcard": {}}) for rel in action_relations
                }
            },
        }
    )

    # binding: subject получает роль; delegation — subject с окном действия
    binding_relations: dict[str, Any] = {"subject": _this(), "role": _this()}
    for rel in action_relations:
        binding_relations[rel] = _intersection([_computed("subject"), _via("role", rel)])
    type_defs.append(
        {
            "type": "binding",
            "relations": binding_relations,
            "metadata": {
                "relations": {
                    "subject": _direct(
                        {"type": "principal"},
                        {"type": "group", "relation": "member"},
                        {"type": "principal", "condition": ACTIVE_WINDOW},
                    ),
                    "role": _direct({"type": "role"}),
                }
            },
        }
    )

    tenant_relations: dict[str, Any] = {"binding": _this()}
    for rel in action_relations:
        tenant_relations[rel] = _via("binding", rel)
    type_defs.append(
        {
            "type": "tenant",
            "relations": tenant_relations,
            "metadata": {"relations": {"binding": _direct({"type": "binding"})}},
        }
    )

    workspace_relations: dict[str, Any] = {
        "tenant": _this(),
        "parent": _this(),
        "binding": _this(),
    }
    for rel in action_relations:
        workspace_relations[rel] = _union(
            [_via("binding", rel), _via("parent", rel), _via("tenant", rel)]
        )
    type_defs.append(
        {
            "type": "workspace",
            "relations": workspace_relations,
            "metadata": {
                "relations": {
                    "tenant": _direct({"type": "tenant"}),
                    "parent": _direct({"type": "workspace"}),
                    "binding": _direct({"type": "binding"}),
                }
            },
        }
    )

    seen: dict[str, str] = {}
    for catalog in catalogs:
        for rtype in sorted(catalog.resource_types.values(), key=lambda r: r.name):
            if rtype.name in seen:
                raise CatalogError(
                    f"тип {rtype.name!r} объявлен и в {seen[rtype.name]}, и в {catalog.service}"
                )
            seen[rtype.name] = catalog.service
            type_defs.append(_resource_type_def(rtype, catalog, catalogs))

    return {
        "schema_version": SCHEMA_VERSION,
        "type_definitions": type_defs,
        "conditions": {
            ACTIVE_WINDOW: {
                "name": ACTIVE_WINDOW,
                "expression": "current_time >= starts_at && current_time < expires_at",
                "parameters": {
                    "current_time": {"type_name": "TYPE_NAME_TIMESTAMP"},
                    "starts_at": {"type_name": "TYPE_NAME_TIMESTAMP"},
                    "expires_at": {"type_name": "TYPE_NAME_TIMESTAMP"},
                },
            }
        },
    }


def _resource_type_def(
    rtype: ResourceType, catalog: Catalog, catalogs: list[Catalog]
) -> dict[str, Any]:
    relations: dict[str, Any] = {}
    metadata: dict[str, Any] = {}
    if rtype.scope:
        relations["scope"] = _this()
        metadata["scope"] = _direct({"type": rtype.scope})
    if rtype.parent:
        relations[rtype.parent] = _this()
        metadata[rtype.parent] = _direct({"type": rtype.parent})
    if rtype.tenant_link:
        relations["tenant"] = _this()
        metadata["tenant"] = _direct({"type": "tenant"})
    for rel in rtype.relations:
        relations[rel] = _this()
        metadata[rel] = _direct({"type": "principal"})

    for name in sorted(catalog.actions):
        action = catalog.actions[name]
        if rtype.name not in action.resources:
            continue
        expr = action.resources[rtype.name]
        rel = relation_name(name)
        if expr is None:
            via = "scope" if rtype.scope else rtype.parent
            assert via is not None
            relations[rel] = _via(via, rel)
        else:
            relations[rel] = _compile(parse_expression(expr), rtype, catalogs)

    definition: dict[str, Any] = {"type": rtype.name, "relations": relations}
    if metadata:
        definition["metadata"] = {"relations": metadata}
    return definition


def _compile(expr: Expr, rtype: ResourceType, catalogs: list[Catalog]) -> dict[str, Any]:
    kind = expr[0]
    if kind == "rel":
        name = expr[1]
        return _computed(name if name in rtype.relations else relation_name(name))
    if kind == "via":
        name, via = expr[1], expr[2]
        target = rtype.structural_relations[via]
        if target in SCOPE_TYPES or _is_action(name, catalogs):
            return _via(via, relation_name(name))
        return _via(via, name)
    if kind == "or":
        return _union([_compile(part, rtype, catalogs) for part in expr[1]])
    if kind == "and":
        return _intersection([_compile(part, rtype, catalogs) for part in expr[1]])
    if kind == "butnot":
        return _difference(_compile(expr[1], rtype, catalogs), _compile(expr[2], rtype, catalogs))
    raise CatalogError(f"неизвестный узел выражения {kind!r}")


def _is_action(name: str, catalogs: list[Catalog]) -> bool:
    return any(name in c.actions for c in catalogs)
