"""Nudges: an agent asking for the human in the conversation.

An approval request is the agent asking to *do* something and waiting on the answer. A nudge is the
opposite shape: the agent has a question only the human can settle, and the answer comes back in the
conversation, not through Keywright. So a nudge grants nothing, blocks nothing and is never gated by
policy - it is a push notification plus a card that stays on the dashboard until the human clears it.

What it does need is a limit. A ping costs the human an interruption, so an agent gets one per
minute and may leave at most a handful outstanding; repeats of the same question are folded into
the nudge already on the phone rather than buzzing again.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import NamedTuple

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from . import actions, audit, events
from .config import settings
from .models import Agent, Nudge, now

log = logging.getLogger("keywright.nudges")

COOLDOWN_S = 60      # between two different pings from one agent
MAX_OPEN = 5         # outstanding pings one agent may leave on the dashboard
MAX_MESSAGE = 1000
MAX_CONTEXT = 200
DISMISS = "KWN_DISMISS_"  # phone button: KWN_DISMISS_<nudge id>.<mac>


class Ping(NamedTuple):
    """What happened to an attempt to ping the human."""

    nudge: Nudge | None
    status: str          # sent | duplicate | throttled | backlog
    retry_after: int = 0

    @property
    def delivered(self) -> bool:
        return self.status in ("sent", "duplicate")


def dismiss_action(nudge_id: str) -> str:
    return actions.sign(DISMISS + nudge_id)


def parse_dismiss_action(action: str) -> str | None:
    """The nudge ID a phone button carries, or None if it is not one of ours."""
    body = actions.verify(action)
    return body[len(DISMISS):] or None if body and body.startswith(DISMISS) else None


async def open_nudges(db: AsyncSession, agent_id: str | None = None) -> list[Nudge]:
    q = select(Nudge).where(Nudge.cleared_at.is_(None)).order_by(Nudge.created_at.desc())
    if agent_id:
        q = q.where(Nudge.agent_id == agent_id)
    return list((await db.execute(q)).scalars().all())


async def create(db: AsyncSession, agent: Agent, session_id: str | None, message: str,
                 context: str = "") -> Ping:
    """Ask for the human. Returns what became of the ask; the caller tells the agent."""
    message = message.strip()[:MAX_MESSAGE]
    context = context.strip()[:MAX_CONTEXT]
    if not message:
        raise ValueError("A nudge needs a message: say what you need from them.")
    at = now()
    mine = await open_nudges(db, agent.id)
    same = next((n for n in mine if n.message == message and n.session_id == session_id), None)
    if same is not None:
        # The same question, still on their phone. Buzzing again would not add anything.
        return Ping(same, "duplicate")
    if len(mine) >= MAX_OPEN:
        return Ping(mine[0] if mine else None, "backlog")
    last = mine[0].created_at if mine else None
    if last is not None and (at - last).total_seconds() < COOLDOWN_S:
        return Ping(mine[0], "throttled", int(COOLDOWN_S - (at - last).total_seconds()) + 1)

    nudge = Nudge(agent_id=agent.id, session_id=session_id, message=message, context=context, created_at=at)
    db.add(nudge)
    await db.commit()
    await db.refresh(nudge)
    await audit.record(db, tool="attention", decision="sent", agent=agent, session_id=session_id,
                       detail={"nudge_id": nudge.id, "message": message, "context": context})
    from .notify.manager import manager

    await manager.notify_nudge(nudge, agent)
    events.publish("nudge.created", id=nudge.id)
    return Ping(nudge, "sent")


async def clear(db: AsyncSession, nudge_id: str, via: str) -> Nudge | None:
    """Mark a nudge answered and take it off the phone. Idempotent: two taps clear it once."""
    changed = await db.execute(update(Nudge).where(
        Nudge.id == nudge_id, Nudge.cleared_at.is_(None),
    ).values(cleared_at=now(), cleared_via=via).execution_options(synchronize_session=False))
    await db.commit()
    nudge = await db.get(Nudge, nudge_id, populate_existing=True)
    if nudge is None or changed.rowcount != 1:
        return nudge
    await audit.record(db, tool="attention.clear", decision="cleared", agent=nudge.agent,
                       session_id=nudge.session_id, detail={"nudge_id": nudge.id, "via": via})
    from .notify.manager import manager

    await manager.nudge_cleared(nudge)
    events.publish("nudge.cleared", id=nudge.id)
    return nudge


async def expire_stale(db: AsyncSession) -> int:
    """Nobody is still waiting on a day-old question. Clear it so the phone and dashboard agree."""
    cutoff = now() - timedelta(seconds=settings.nudge_ttl_s)
    stale = (await db.execute(select(Nudge.id).where(
        Nudge.cleared_at.is_(None), Nudge.created_at <= cutoff))).scalars().all()
    for nudge_id in stale:
        await clear(db, nudge_id, via="expired")
    return len(stale)
