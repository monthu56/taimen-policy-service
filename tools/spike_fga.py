"""Spike OpenFGA (дизайн v0, раздел 3 и 14): модель из каталогов, сценарий
дерева воркспейсов, замер латентности check и list-objects.

    uv run python tools/spike_fga.py --fga http://127.0.0.1:18090 --workspaces 200

Выход — JSON с результатами сценария и p50/p95 в миллисекундах.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from policy_service.catalog import load_catalog_file
from policy_service.fga import CheckItem, FgaClient, Tuple
from policy_service.model_builder import build_model

ROOT = Path(__file__).resolve().parents[2]
CATALOGS = [ROOT / "control-plane/authz/catalog.yaml", ROOT / "memory-service/authz/catalog.yaml"]


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fga", default="http://127.0.0.1:18090")
    parser.add_argument("--workspaces", type=int, default=200)
    parser.add_argument("--checks", type=int, default=300)
    args = parser.parse_args()

    catalogs = [load_catalog_file(p) for p in CATALOGS]
    model = build_model(catalogs)
    fga = FgaClient(args.fga)
    store = await fga.create_store(f"spike-{uuid.uuid4().hex[:8]}")
    model_id = await fga.write_model(store, model)
    print(
        json.dumps({"store": store, "model_id": model_id, "types": len(model["type_definitions"])})
    )

    tenant = f"tenant:{uuid.uuid4()}"
    alice, bob, carol = (f"principal:{uuid.uuid4()}" for _ in range(3))
    # дерево: portfolio → N воркспейсов (половина под portfolio A, половина под B)
    portfolio_a, portfolio_b = f"workspace:{uuid.uuid4()}", f"workspace:{uuid.uuid4()}"
    writes = [
        Tuple(portfolio_a, "tenant", tenant),
        Tuple(portfolio_b, "tenant", tenant),
    ]
    children_a: list[str] = []
    children_b: list[str] = []
    for i in range(args.workspaces):
        ws = f"workspace:{uuid.uuid4()}"
        parent = portfolio_a if i % 2 == 0 else portfolio_b
        (children_a if parent == portfolio_a else children_b).append(ws)
        writes.append(Tuple(ws, "tenant", tenant))
        writes.append(Tuple(ws, "parent", parent))
    # роли
    writes += [
        Tuple("role:editor", "tasks_read", "principal:*"),
        Tuple("role:editor", "tasks_write", "principal:*"),
        Tuple("role:editor", "memory_read", "principal:*"),
        Tuple("role:viewer", "tasks_read", "principal:*"),
        Tuple("role:approver", "approvals_decide", "principal:*"),
    ]
    # alice — editor на portfolio A; bob — viewer на tenant; carol — делегат alice на 1 час
    b1, b2, b3, b4 = (f"binding:{uuid.uuid4()}" for _ in range(4))
    now = datetime.now(UTC)
    writes += [
        Tuple(b1, "subject", alice),
        Tuple(b1, "role", "role:editor"),
        Tuple(portfolio_a, "binding", b1),
        Tuple(b2, "subject", bob),
        Tuple(b2, "role", "role:viewer"),
        Tuple(tenant, "binding", b2),
        Tuple(
            b3,
            "subject",
            carol,
            condition={
                "name": "active_window",
                "context": {
                    "starts_at": (now - timedelta(minutes=5)).isoformat(),
                    "expires_at": (now + timedelta(hours=1)).isoformat(),
                },
            },
        ),
        Tuple(b3, "role", "role:editor"),
        Tuple(portfolio_a, "binding", b3),
        Tuple(b4, "subject", bob),
        Tuple(b4, "role", "role:approver"),
        Tuple(portfolio_b, "binding", b4),
    ]
    # задача в первом дочернем воркспейсе A, approval от bob в B
    task = f"task:{uuid.uuid4()}"
    approval = f"approval:{uuid.uuid4()}"
    writes += [
        Tuple(task, "scope", children_a[0]),
        Tuple(task, "owner", carol),
        Tuple(approval, "scope", children_b[0]),
        Tuple(approval, "requested_by", bob),
    ]
    for i in range(0, len(writes), 100):
        await fga.write(store, writes=writes[i : i + 100], model_id=model_id)
    print(json.dumps({"tuples": len(writes)}))

    ctx = {"current_time": now.isoformat()}

    async def check(user: str, rel: str, obj: str, strong: bool = False) -> bool:
        return await fga.check(
            store,
            CheckItem(user, rel, obj, context=ctx),
            model_id=model_id,
            consistency="strong" if strong else "default",
        )

    scenario = {
        "alice tasks_read child A (наследование)": await check(alice, "tasks_read", children_a[0]),
        "alice tasks_read child B (сосед)": await check(alice, "tasks_read", children_b[0]),
        "alice tasks_read task via scope": await check(alice, "tasks_read", task),
        "bob tasks_read task via tenant viewer": await check(bob, "tasks_read", task),
        "bob tasks_write task (нет права)": await check(bob, "tasks_write", task),
        "carol tasks_write task (owner)": await check(carol, "tasks_write", task),
        "carol tasks_read child A (делегация в окне)": await check(
            carol, "tasks_read", children_a[1]
        ),
        "bob approvals_decide own approval (but not requested_by)": await check(
            bob, "approvals_decide", approval
        ),
        "alice memory_read child A": await check(alice, "memory_read", children_a[3]),
    }
    # делегация вне окна
    expired = await fga.check(
        store,
        CheckItem(
            carol,
            "tasks_read",
            children_a[1],
            context={"current_time": (now + timedelta(hours=2)).isoformat()},
        ),
        model_id=model_id,
    )
    scenario["carol tasks_read после окна"] = expired

    listed = await fga.list_objects(
        store,
        subject=alice,
        relation="tasks_read",
        object_type="workspace",
        context=ctx,
        model_id=model_id,
    )
    scenario["alice list_objects workspace count"] = len(listed)
    scenario["alice list_objects == portfolio A + children A"] = set(listed) == {
        portfolio_a,
        *children_a,
    }
    print(json.dumps(scenario, ensure_ascii=False, indent=2))

    # латентность
    lat_check: list[float] = []
    for i in range(args.checks):
        t0 = time.perf_counter()
        await check(alice, "tasks_read", children_a[i % len(children_a)])
        lat_check.append((time.perf_counter() - t0) * 1000)
    lat_list: list[float] = []
    for _ in range(20):
        t0 = time.perf_counter()
        await fga.list_objects(
            store,
            subject=alice,
            relation="tasks_read",
            object_type="workspace",
            context=ctx,
            model_id=model_id,
        )
        lat_list.append((time.perf_counter() - t0) * 1000)
    q = statistics.quantiles
    print(
        json.dumps(
            {
                "check_p50_ms": round(statistics.median(lat_check), 2),
                "check_p95_ms": round(q(lat_check, n=20)[18], 2),
                "list_objects_p50_ms": round(statistics.median(lat_list), 2),
                "list_objects_p95_ms": round(q(lat_list, n=20)[18], 2),
                "workspaces": args.workspaces,
            }
        )
    )
    await fga.delete_store(store)
    await fga.aclose()


if __name__ == "__main__":
    asyncio.run(main())
