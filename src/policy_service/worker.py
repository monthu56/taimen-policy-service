"""Воркер проекции: тянет журналы Control Plane и IAM в tuples engine.

Запускается отдельным процессом (`policy-worker`), делит с API базу и
engine. Источники включаются наличием URL в настройках; без источников
воркер завершается сразу с сообщением.
"""

from __future__ import annotations

import asyncio
import logging

from policy_service.config import Settings
from policy_service.core import PolicyCore
from policy_service.db import Database
from policy_service.fga import FgaClient
from policy_service.projection import ControlPlaneSource, IamSource, ProjectionRunner
from policy_service.projection.runner import ProjectionSource

log = logging.getLogger("policy_service.worker")


def build_sources(settings: Settings) -> list[ProjectionSource]:
    sources: list[ProjectionSource] = []
    if settings.control_plane_url:
        token = settings.control_plane_token

        async def static_token() -> str:
            return token

        sources.append(ControlPlaneSource(settings.control_plane_url, static_token))
    if settings.iam_url and settings.iam_events_bootstrap_token:
        sources.append(IamSource(settings.iam_url, settings.iam_events_bootstrap_token))
    return sources


async def run(settings: Settings | None = None) -> None:
    settings = settings or Settings()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    sources = build_sources(settings)
    if not sources:
        log.warning("источники проекции не настроены (POL_CONTROL_PLANE_URL / POL_IAM_URL)")
        return
    db = Database(settings)
    fga = FgaClient(
        settings.fga_url,
        preshared_key=settings.fga_preshared_key,
        timeout_seconds=settings.fga_timeout_seconds,
    )
    core = PolicyCore(settings, fga)
    async with db.sessions() as session:
        await core.load(session)
    runner = ProjectionRunner(
        core,
        db.sessions,
        sources,
        poll_seconds=settings.projection_poll_seconds,
        batch_size=settings.projection_batch_size,
    )
    log.info("проекция запущена: %s", ", ".join(s.name for s in sources))
    try:
        await runner.run_forever()
    finally:
        await fga.aclose()
        await db.close()


def main() -> None:
    asyncio.run(run())
