"""Каталог действий resource server (дизайн v0, разделы 5 и 8).

Каждый resource server описывает в `authz/catalog.yaml` свои типы ресурсов,
структурные отношения на них и действия. Policy-service из каталогов всех
сервисов собирает одну модель авторизации (`model_builder`). Здесь — разбор и
валидация: неизвестный тип, действие или отношение должны быть отвергнуты при
регистрации, а не всплыть как «deny» во время выполнения.

Формат:

```yaml
service: control-plane
version: 1
resource_types:
  task: {scope: workspace, relations: [owner, requested_by, assignee, type_role]}
  run: {parent: task, relations: [holder]}
actions:
  tasks.read: {resource: task, derived: "owner or requested_by or assignee or tasks.read@scope"}
  runs.control:
    resources:
      task: "runs.control@scope"
      run: "holder or runs.control@task"
  events.read: {resource: workspace}
```

Выражение `derived` — какие отношения на ресурсе дают действие:
`a or b`, `a and b`, `a but not b`, скобки; атом — прямое отношение типа
(`owner`), другое действие на том же типе (`tasks.read`) или действие/отношение,
унаследованное через структурное отношение: `tasks.read@scope`,
`runs.control@task`. Для действий на типах `tenant` и `workspace` выражение не
нужно: они всегда выводятся из bindings и дерева.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ACTION_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")

SCOPE_TYPES = frozenset({"tenant", "workspace"})
BUILTIN_TYPES = frozenset({"principal", "group", "role", "binding", *SCOPE_TYPES})
RESERVED_RELATIONS = frozenset({"scope", "parent", "tenant", "binding", "subject", "role"})


class CatalogError(ValueError):
    """Каталог не проходит валидацию; сообщение — точное место и причина."""


def relation_name(action: str) -> str:
    """Имя отношения в модели engine для действия: точка → подчёркивание."""
    return action.replace(".", "_")


# --- выражения ---------------------------------------------------------------

# AST: ("rel", name) | ("via", name, relation) | ("or", [...]) | ("and", [...])
#      | ("butnot", base, subtract)
Expr = tuple[Any, ...]

_TOKEN_RE = re.compile(r"\s*(\(|\)|@|[a-z][a-z0-9_.]*)")


def parse_expression(text: str) -> Expr:
    tokens = _tokenize(text)
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take(expected: str | None = None) -> str:
        nonlocal pos
        tok = peek()
        if tok is None or (expected is not None and tok != expected):
            raise CatalogError(f"выражение {text!r}: ожидалось {expected or 'продолжение'}")
        pos += 1
        return tok

    def parse_or() -> Expr:
        parts = [parse_and()]
        while peek() == "or":
            take("or")
            parts.append(parse_and())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def parse_and() -> Expr:
        parts = [parse_butnot()]
        while peek() == "and":
            take("and")
            parts.append(parse_butnot())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def parse_butnot() -> Expr:
        base = parse_atom()
        if peek() == "but":
            take("but")
            take("not")
            return ("butnot", base, parse_atom())
        return base

    def parse_atom() -> Expr:
        tok = take()
        if tok == "(":
            inner = parse_or()
            take(")")
            return inner
        if tok in {"or", "and", "but", "not", ")", "@"}:
            raise CatalogError(f"выражение {text!r}: неожиданный токен {tok!r}")
        if peek() == "@":
            take("@")
            via = take()
            if not NAME_RE.match(via):
                raise CatalogError(f"выражение {text!r}: некорректное отношение {via!r}")
            return ("via", tok, via)
        return ("rel", tok)

    if not tokens:
        raise CatalogError("пустое выражение")
    result = parse_or()
    if pos != len(tokens):
        raise CatalogError(f"выражение {text!r}: лишние токены с позиции {pos}")
    return result


def _tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    rest = text.strip()
    while rest:
        match = _TOKEN_RE.match(rest)
        if match is None:
            raise CatalogError(f"выражение {text!r}: нераспознанный фрагмент {rest[:16]!r}")
        tokens.append(match.group(1))
        rest = rest[match.end() :].lstrip()
    return tokens


def expression_atoms(expr: Expr) -> list[Expr]:
    kind = expr[0]
    if kind in {"rel", "via"}:
        return [expr]
    if kind in {"or", "and"}:
        return [atom for part in expr[1] for atom in expression_atoms(part)]
    return expression_atoms(expr[1]) + expression_atoms(expr[2])


# --- модель каталога ---------------------------------------------------------


@dataclass(frozen=True)
class ResourceType:
    name: str
    scope: str | None = None
    parent: str | None = None
    relations: tuple[str, ...] = ()
    # tenant: true — у типа есть прямое отношение `tenant`, через которое
    # действия наследуются с уровня tenant (например, общий namespace памяти).
    tenant_link: bool = False

    @property
    def structural_relations(self) -> dict[str, str]:
        """Отношение → тип объекта, через который наследуются действия."""
        out: dict[str, str] = {}
        if self.scope:
            out["scope"] = self.scope
        if self.parent:
            out[self.parent] = self.parent
        if self.tenant_link:
            out["tenant"] = "tenant"
        return out


@dataclass(frozen=True)
class ActionDef:
    name: str
    # тип ресурса → выражение (None — умолчание: унаследовать через scope/parent)
    resources: dict[str, str | None] = field(default_factory=dict)


@dataclass(frozen=True)
class Catalog:
    service: str
    version: int
    resource_types: dict[str, ResourceType]
    actions: dict[str, ActionDef]
    content_hash: str
    content: dict[str, Any]

    def action_names(self) -> list[str]:
        return sorted(self.actions)


def content_hash_of(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_catalog(data: dict[str, Any]) -> Catalog:
    if not isinstance(data, dict):
        raise CatalogError("каталог должен быть объектом")
    service = str(data.get("service") or "")
    if not NAME_RE.match(service.replace("-", "_")) or not service:
        raise CatalogError(f"service: недопустимое имя {service!r}")
    try:
        version = int(data.get("version", 0))
    except (TypeError, ValueError) as exc:
        raise CatalogError("version: ожидается целое число") from exc
    if version < 1:
        raise CatalogError("version: должно быть не меньше 1")

    resource_types = _parse_resource_types(data.get("resource_types") or {})
    actions = _parse_actions(data.get("actions") or {}, resource_types)
    return Catalog(
        service=service,
        version=version,
        resource_types=resource_types,
        actions=actions,
        content_hash=content_hash_of(data),
        content=data,
    )


def load_catalog_file(path: Path) -> Catalog:
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw) if path.suffix == ".json" else yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise CatalogError(f"{path}: каталог должен быть объектом")
    return parse_catalog(data)


def _parse_resource_types(raw: Any) -> dict[str, ResourceType]:
    if not isinstance(raw, dict):
        raise CatalogError("resource_types: ожидается объект")
    types: dict[str, ResourceType] = {}
    for name, spec in raw.items():
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise CatalogError(f"resource_types: недопустимое имя типа {name!r}")
        if name in BUILTIN_TYPES:
            raise CatalogError(f"resource_types.{name}: встроенный тип нельзя переопределить")
        spec = spec or {}
        if not isinstance(spec, dict):
            raise CatalogError(f"resource_types.{name}: ожидается объект")
        scope = spec.get("scope")
        parent = spec.get("parent")
        if scope is not None and scope not in SCOPE_TYPES:
            raise CatalogError(f"resource_types.{name}.scope: допустимо {sorted(SCOPE_TYPES)}")
        if parent is not None and (not isinstance(parent, str) or not NAME_RE.match(parent)):
            raise CatalogError(f"resource_types.{name}.parent: недопустимое имя {parent!r}")
        relations = tuple(spec.get("relations") or ())
        for rel in relations:
            if not isinstance(rel, str) or not NAME_RE.match(rel):
                raise CatalogError(f"resource_types.{name}.relations: недопустимое имя {rel!r}")
            if rel in RESERVED_RELATIONS or rel == parent:
                raise CatalogError(f"resource_types.{name}.relations: {rel!r} зарезервировано")
        tenant_link = bool(spec.get("tenant", False))
        types[name] = ResourceType(
            name=name, scope=scope, parent=parent, relations=relations, tenant_link=tenant_link
        )

    for rtype in types.values():
        if (
            rtype.parent is not None
            and rtype.parent not in types
            and rtype.parent not in SCOPE_TYPES
        ):
            raise CatalogError(
                f"resource_types.{rtype.name}.parent: неизвестный тип {rtype.parent!r}"
            )
        if not rtype.structural_relations:
            raise CatalogError(
                f"resource_types.{rtype.name}: нужен scope, parent или tenant, иначе тип недостижим"
            )
    return types


def _parse_actions(raw: Any, types: dict[str, ResourceType]) -> dict[str, ActionDef]:
    if not isinstance(raw, dict):
        raise CatalogError("actions: ожидается объект")
    actions: dict[str, ActionDef] = {}
    for name, spec in raw.items():
        if not isinstance(name, str) or not ACTION_RE.match(name):
            raise CatalogError(f"actions: недопустимое имя действия {name!r}")
        spec = spec or {}
        if not isinstance(spec, dict):
            raise CatalogError(f"actions.{name}: ожидается объект")
        resources: dict[str, str | None] = {}
        if "resources" in spec:
            if not isinstance(spec["resources"], dict) or not spec["resources"]:
                raise CatalogError(f"actions.{name}.resources: ожидается непустой объект")
            for rtype, expr in spec["resources"].items():
                resources[str(rtype)] = None if expr is None else str(expr)
        else:
            rtype = spec.get("resource")
            if not rtype:
                raise CatalogError(f"actions.{name}: нужен resource или resources")
            derived = spec.get("derived")
            resources[str(rtype)] = None if derived is None else str(derived)
        for rtype in resources:
            if rtype not in types and rtype not in SCOPE_TYPES:
                raise CatalogError(f"actions.{name}: неизвестный тип ресурса {rtype!r}")
            if rtype in SCOPE_TYPES and resources[rtype] is not None:
                raise CatalogError(
                    f"actions.{name}: для {rtype} выражение не задаётся, "
                    "действие выводится из bindings"
                )
        actions[name] = ActionDef(name=name, resources=resources)

    for action in actions.values():
        for rtype, expr in action.resources.items():
            if rtype in SCOPE_TYPES:
                continue
            _check_expression(action.name, types[rtype], expr, actions)
    return actions


def _check_expression(
    action: str, rtype: ResourceType, expr: str | None, actions: dict[str, ActionDef]
) -> None:
    if expr is None:
        if not rtype.structural_relations:
            raise CatalogError(f"actions.{action}: у типа {rtype.name} нет scope/parent")
        return
    tree = parse_expression(expr)
    for atom in expression_atoms(tree):
        if atom[0] == "rel":
            name = atom[1]
            is_relation = name in rtype.relations
            is_action = name in actions and rtype.name in actions[name].resources
            if not (is_relation or is_action):
                raise CatalogError(
                    f"actions.{action}: {name!r} не является отношением или действием "
                    f"типа {rtype.name}"
                )
        else:
            name, via = atom[1], atom[2]
            targets = rtype.structural_relations
            if via not in targets:
                raise CatalogError(
                    f"actions.{action}: {via!r} не структурное отношение типа {rtype.name}"
                )
            target = targets[via]
            if target in SCOPE_TYPES:
                if name not in actions:
                    raise CatalogError(
                        f"actions.{action}: {name!r} должно быть действием (через {via})"
                    )
            else:
                ok = (name in actions and target in actions[name].resources) or (
                    NAME_RE.match(name) is not None
                )
                if not ok:
                    raise CatalogError(f"actions.{action}: {name!r} недостижимо через {via}")
