from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from policy_service.core import PolicyCore, PolicyUnavailable

log = logging.getLogger("policy_service.projection")


@dataclass(frozen=True)
class SourceEvent:
    id: str
    tenant_id: uuid.UUID | None
    type: str
    payload: dict[str, Any]
    actor_id: str | None = None
    entity_id: str = ""


class ProjectionSource(Protocol):
    name: str

    async def fetch(self, cursor: str, limit: int) -> tuple[list[SourceEvent], str]: ...

    async def apply(self, core: PolicyCore, session: AsyncSession, event: SourceEvent) -> None: ...


class ProjectionRunner:
    def __init__(
        self,
        core: PolicyCore,
        sessions: async_sessionmaker[AsyncSession],
        sources: list[ProjectionSource],
        *,
        poll_seconds: float = 2.0,
        batch_size: int = 200,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._core = core
        self._sessions = sessions
        self._sources = sources
        self._poll = poll_seconds
        self._batch = batch_size
        self._sleep = sleep
        self._stop = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    async def run_forever(self) -> None:
        while not self._stop.is_set():
            applied = await self.run_once()
            if applied == 0:
                await self._sleep(self._poll)

    async def run_once(self) -> int:
        total = 0
        for source in self._sources:
            try:
                total += await self._drain(source)
            except Exception as exc:
                log.warning("projection %s: %s", source.name, exc)
                async with self._sessions() as session:
                    cursor = await self._core.get_cursor(session, source.name)
                    cursor.last_error = str(exc)[:1000]
                    await session.commit()
        return total

    async def _drain(self, source: ProjectionSource) -> int:
        async with self._sessions() as session:
            cursor_row = await self._core.get_cursor(session, source.name)
            cursor = cursor_row.cursor
            await session.commit()
        events, next_cursor = await source.fetch(cursor, self._batch)
        applied = 0
        for event in events:
            async with self._sessions() as session:
                try:
                    await source.apply(self._core, session, event)
                except PolicyUnavailable:
                    await session.rollback()
                    raise
                cursor_row = await self._core.get_cursor(session, source.name)
                cursor_row.cursor = _advance(cursor_row.cursor, source.name, event, next_cursor)
                cursor_row.events_applied += 1
                cursor_row.last_error = ""
                await session.commit()
            applied += 1
        if not events and next_cursor and next_cursor != cursor:
            async with self._sessions() as session:
                cursor_row = await self._core.get_cursor(session, source.name)
                cursor_row.cursor = next_cursor
                await session.commit()
        return applied


def _advance(current: str, source: str, event: SourceEvent, next_cursor: str) -> str:
    # Источники с последовательным целочисленным курсором продвигаются по
    # событию, с непрозрачным — только по итоговому курсору страницы.
    if source == "iam":
        return event.id if event.id.isdigit() else next_cursor
    return next_cursor
