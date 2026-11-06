"""Durable assignment outbox. Task transactions never wait for notification delivery.

One lifespan worker in the supported single-worker broker. Deliveries are at least once:
external transports may repeat after a crash; stable event IDs support receiver deduplication.
"""
import asyncio
import logging
from datetime import timedelta

from sqlalchemy import select

from . import events
from .db import session
from .models import TaskNotification, now
from .notify.manager import manager

log = logging.getLogger(__name__)


async def deliver_pending():
    if not manager.active:
        return
    async with session() as db:
        ids = list(await db.scalars(select(TaskNotification.id).where(
            TaskNotification.delivered_at.is_(None), TaskNotification.next_attempt_at <= now())
            .order_by(TaskNotification.next_attempt_at).limit(20)))
    for event_id in ids:
        async with session() as db:
            event = await db.get(TaskNotification, event_id)
            from .approvals import public_url
            try:
                await manager.active.send_task(event.id, f"{public_url()}/ui/work/tasks/{event.task_id}")
            except Exception:  # noqa: BLE001 - transport diagnostics may contain credentials
                # Transport exceptions may contain credentials or private response bodies.
                event.error = "Delivery failed. Check notification settings; delivery will retry."
                event.attempts += 1
                event.next_attempt_at = now() + timedelta(seconds=min(3600, 30 * 2 ** min(event.attempts, 7)))
            else:
                event.attempts += 1
                event.error = ""
                event.delivered_at = now()
            await db.commit()
        events.publish("work.changed", kind="notification")


async def worker():
    while True:
        try:
            await deliver_pending()
        except Exception:  # noqa: BLE001 - worker must recover without logging private diagnostics
            log.warning("Task notification worker failed; retrying on the next pass")
        await asyncio.sleep(15)
