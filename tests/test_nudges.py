"""Nudges: the ping an agent sends when it needs the human in the conversation."""

from datetime import timedelta

import pytest
from sqlalchemy import select

from keywright_server import actions, nudges
from keywright_server.config import settings
from keywright_server.models import AuditEvent, Nudge, now


async def test_ping_creates_one_open_nudge_and_audits_it(db, agent, log_notifier):
    ping = await nudges.create(db, agent, "claude:abc", "Which cert path do you want?", "ai-vm:~/p")
    assert ping.status == "sent" and ping.delivered
    assert ping.nudge.open and ping.nudge.message == "Which cert path do you want?"
    assert [n.id for n in await nudges.open_nudges(db)] == [ping.nudge.id]
    event = (await db.execute(select(AuditEvent).where(AuditEvent.tool == "attention"))).scalar_one()
    assert event.decision == "sent" and event.detail["nudge_id"] == ping.nudge.id


async def test_the_same_question_does_not_buzz_twice(db, agent, log_notifier):
    first = await nudges.create(db, agent, "s1", "Which one?")
    again = await nudges.create(db, agent, "s1", "Which one?")
    assert again.status == "duplicate" and again.nudge.id == first.nudge.id
    assert len(await nudges.open_nudges(db)) == 1


async def test_a_different_question_inside_the_cooldown_is_refused(db, agent, log_notifier):
    await nudges.create(db, agent, "s1", "Which one?")
    second = await nudges.create(db, agent, "s1", "Something else entirely")
    assert second.status == "throttled" and 0 < second.retry_after <= nudges.COOLDOWN_S + 1
    assert not second.delivered
    assert len(await nudges.open_nudges(db)) == 1


async def test_an_agent_may_not_pile_up_unanswered_pings(db, agent, log_notifier):
    for i in range(nudges.MAX_OPEN):
        n = Nudge(agent_id=agent.id, message=f"q{i}", created_at=now() - timedelta(hours=1))
        db.add(n)
    await db.commit()
    assert (await nudges.create(db, agent, None, "one more")).status == "backlog"
    assert len(await nudges.open_nudges(db)) == nudges.MAX_OPEN


async def test_clearing_is_idempotent_and_recorded(db, agent, log_notifier):
    ping = await nudges.create(db, agent, None, "look at this")
    cleared = await nudges.clear(db, ping.nudge.id, via="ui")
    assert not cleared.open and cleared.cleared_via == "ui"
    again = await nudges.clear(db, ping.nudge.id, via="homeassistant")
    assert again.cleared_via == "ui"  # the second tap does not rewrite who answered
    events = (await db.execute(select(AuditEvent).where(AuditEvent.tool == "attention.clear"))).scalars().all()
    assert len(events) == 1
    assert await nudges.open_nudges(db) == []


async def test_an_empty_message_is_not_a_nudge(db, agent, log_notifier):
    with pytest.raises(ValueError):
        await nudges.create(db, agent, None, "   ")


async def test_long_input_is_capped_not_rejected(db, agent, log_notifier):
    ping = await nudges.create(db, agent, None, "x" * 5000, "y" * 5000)
    assert len(ping.nudge.message) == nudges.MAX_MESSAGE
    assert len(ping.nudge.context) == nudges.MAX_CONTEXT


async def test_nobody_is_still_waiting_on_a_day_old_question(db, agent, log_notifier):
    stale = Nudge(agent_id=agent.id, message="old",
                  created_at=now() - timedelta(seconds=settings.nudge_ttl_s + 60))
    fresh = Nudge(agent_id=agent.id, message="new")
    db.add_all([stale, fresh])
    await db.commit()
    assert await nudges.expire_stale(db) == 1
    assert [n.id for n in await nudges.open_nudges(db)] == [fresh.id]
    assert (await db.get(Nudge, stale.id)).cleared_via == "expired"


# ---- phone buttons ------------------------------------------------------------------------------
async def test_dismiss_action_round_trips(_data_dir):
    assert nudges.parse_dismiss_action(nudges.dismiss_action("ndg_abc")) == "ndg_abc"


@pytest.mark.parametrize("action", [
    "KWN_DISMISS_ndg_abc",                      # unsigned
    "KWN_DISMISS_ndg_abc.AAAAAAAAAAAAAAAAAAAAAA",  # wrong MAC
    "KWN_DISMISS_.signature",                   # no id
    "ndg_abc",
    "",
])
async def test_a_nudge_id_alone_dismisses_nothing(_data_dir, action):
    assert nudges.parse_dismiss_action(action) is None


async def test_dismiss_actions_do_not_decide_access(_data_dir):
    """The two button families share a signing key and must not be confusable."""
    from keywright_server import approvals

    dismiss = nudges.dismiss_action("req_abc")
    assert approvals.parse_notification_action(dismiss) is None
    assert nudges.parse_dismiss_action(approvals.notification_action("req_abc", "once")) is None
    assert actions.verify(dismiss) == nudges.DISMISS + "req_abc"


async def test_a_phone_tap_clears_exactly_that_nudge(db, agent, log_notifier):
    ping = await nudges.create(db, agent, None, "which one?")
    other = await nudges.create(db, agent, "s2", "and this?")
    assert other.status == "throttled"  # the cooldown holds; only one is outstanding
    await log_notifier.on_decision_token(nudges.dismiss_action(ping.nudge.id))
    assert await nudges.open_nudges(db) == []
    assert (await db.get(Nudge, ping.nudge.id, populate_existing=True)).cleared_via == "log"


async def test_an_unsigned_tap_clears_nothing(db, agent, log_notifier):
    ping = await nudges.create(db, agent, None, "which one?")
    for action in (nudges.DISMISS + ping.nudge.id, nudges.DISMISS + ping.nudge.id + ".forged"):
        await log_notifier.on_decision_token(action)
    assert len(await nudges.open_nudges(db)) == 1
