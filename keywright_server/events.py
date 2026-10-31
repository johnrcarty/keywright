"""Live updates for the admin UI.

The server runs one worker against one SQLite file, so fan-out is a set of asyncio queues: the
approval path publishes a small fact ("request req_x was decided"), each open dashboard turns it
into markup. Nothing here may block or fail a decision, so publishing is synchronous, non-blocking,
and lossy in exactly one way: a browser that stops draining is told to reload the whole region
rather than allowed to back the queue up behind a human tapping approve on their phone.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from typing import Any

log = logging.getLogger("keywright.events")

QUEUE_MAX = 64
RESYNC = {"type": "resync"}


class Subscriber:
    """One open dashboard."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=QUEUE_MAX)
        self._stale = False

    def offer(self, event: dict[str, Any]) -> None:
        if self._stale:
            return  # a resync is already waiting: it will carry whatever this event said
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._stale = True
            while not self._queue.empty():
                self._queue.get_nowait()
            self._queue.put_nowait(RESYNC)

    async def get(self) -> dict[str, Any]:
        event = await self._queue.get()
        if event is RESYNC:
            self._stale = False
        return event

    @property
    def waiting(self) -> int:
        return self._queue.qsize()


_subscribers: set[Subscriber] = set()


def publish(type: str, **fields: Any) -> None:
    """Announce a fact to every open dashboard. Safe to call from anywhere: it never awaits, never
    raises, and never touches the database."""
    if not _subscribers:
        return
    event = {"type": type, **fields}
    for sub in _subscribers:
        sub.offer(event)


@contextlib.asynccontextmanager
async def subscribe() -> AsyncIterator[Subscriber]:
    sub = Subscriber()
    _subscribers.add(sub)
    log.debug("dashboard subscribed (%d open)", len(_subscribers))
    try:
        yield sub
    finally:
        _subscribers.discard(sub)


def subscriber_count() -> int:
    return len(_subscribers)
