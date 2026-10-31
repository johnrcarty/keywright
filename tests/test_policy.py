from datetime import timedelta

import pytest
from sqlalchemy import select

from keywright_server import approvals, policy
from keywright_server.config import settings
from keywright_server.models import Grant, Policy, Resource, now


@pytest.fixture
async def resources(db):
    db.add_all([
        Resource(kind="ssh", name="dev", default_mode="open", config={"host": "127.0.0.1"}),
        Resource(kind="ssh", name="nvr", default_mode="approval", config={"host": "127.0.0.1"}),
        Resource(kind="ssh", name="prod-ha", default_mode="locked", config={"host": "127.0.0.1"}),
        Resource(kind="mcp", name="ha", default_mode="approval", config={"url": "http://x"}),
    ])
    await db.commit()


async def test_default_modes(db, agent, resources):
    assert (await policy.evaluate(db, agent, None, ["ssh/dev/exec/ls"])).status == "allow"
    v = await policy.evaluate(db, agent, None, ["ssh/nvr/exec/ls"])
    assert v.status == "pending" and v.missing == ["ssh/nvr/exec/ls"]
    assert (await policy.evaluate(db, agent, None, ["ssh/prod-ha/exec/ls"])).status == "locked"
    assert (await policy.evaluate(db, agent, None, ["ssh/nope/exec/ls"])).status == "unknown"


async def test_deny_wins_over_everything(db, agent, resources):
    db.add(Policy(pattern="ssh/dev/exec/rm", effect="deny"))
    db.add(Grant(agent_id=agent.id, pattern="ssh/dev/exec/**", scope="ttl", expires_at=now() + timedelta(hours=1)))
    await db.commit()
    v = await policy.evaluate(db, agent, None, ["ssh/dev/exec/rm", "ssh/dev/exec/ls"])
    assert v.status == "deny" and v.denied == ["ssh/dev/exec/rm"]


async def test_allow_policy_scoped_to_agent(db, agent, resources):
    db.add(Policy(pattern="ssh/nvr/exec/journalctl", effect="allow", agent_id=agent.id))
    await db.commit()
    assert (await policy.evaluate(db, agent, None, ["ssh/nvr/exec/journalctl"])).status == "allow"
    assert (await policy.evaluate(db, agent, None, ["ssh/nvr/exec/docker/ps"])).status == "pending"


async def test_once_grant_is_consumed_atomically(db, agent, resources):
    db.add(Grant(agent_id=agent.id, pattern="ssh/nvr/exec/docker/ps", scope="once", uses_remaining=1))
    await db.commit()
    v1 = await policy.evaluate(db, agent, None, ["ssh/nvr/exec/docker/ps"])
    assert v1.allowed and len(v1.consumed_grants) == 1
    v2 = await policy.evaluate(db, agent, None, ["ssh/nvr/exec/docker/ps"])
    assert v2.status == "pending"


async def test_once_grant_not_consumed_when_other_pattern_blocks(db, agent, resources):
    db.add(Grant(agent_id=agent.id, pattern="ssh/nvr/exec/ls", scope="once", uses_remaining=1))
    await db.commit()
    v = await policy.evaluate(db, agent, None, ["ssh/nvr/exec/ls", "ssh/nvr/exec/rm"])
    assert v.status == "pending" and v.consumed_grants == []
    # grant still intact
    assert (await policy.evaluate(db, agent, None, ["ssh/nvr/exec/ls"])).allowed


async def test_session_grant_requires_matching_session(db, agent, resources):
    db.add(Grant(agent_id=agent.id, pattern="ssh/nvr/exec/**", scope="session", session_id="s1",
                 expires_at=now() + timedelta(hours=1)))
    await db.commit()
    assert (await policy.evaluate(db, agent, "s1", ["ssh/nvr/exec/ls"])).allowed
    assert (await policy.evaluate(db, agent, "s2", ["ssh/nvr/exec/ls"])).status == "pending"
    assert (await policy.evaluate(db, agent, None, ["ssh/nvr/exec/ls"])).status == "pending"


async def test_expired_grant_ignored(db, agent, resources):
    db.add(Grant(agent_id=agent.id, pattern="ssh/nvr/exec/**", scope="ttl", expires_at=now() - timedelta(seconds=1)))
    await db.commit()
    assert (await policy.evaluate(db, agent, None, ["ssh/nvr/exec/ls"])).status == "pending"


async def test_effective_access(db, agent, resources):
    db.add(Policy(pattern="ssh/nvr/exec/journalctl", effect="allow"))
    await db.commit()
    rows = await policy.effective_access(db, agent, None)
    by = {r["resource"]: r for r in rows}
    assert by["ssh/nvr"]["allow_rules"] == ["ssh/nvr/exec/journalctl"]
    assert by["ssh/dev"]["default"] == "open"
    assert by["mcp/ha"]["kind"] == "mcp"


async def test_decide_flow(db, agent, resources, log_notifier):
    req = await approvals.create(db, agent, "sess-1", ["ssh/nvr/exec/docker/ps"], "check containers")
    assert req.status == "pending"
    assert await approvals.find_pending(db, agent, ["ssh/nvr/exec/docker/ps"], session_id="sess-1") is not None

    await approvals.decide(db, req.id, "session", via="test")
    assert (await policy.evaluate(db, agent, "sess-1", ["ssh/nvr/exec/docker/ps"])).allowed
    assert (await policy.evaluate(db, agent, "other", ["ssh/nvr/exec/docker/ps"])).status == "pending"

    req2 = await approvals.create(db, agent, None, ["ssh/nvr/exec/rm"], "cleanup")
    await approvals.decide(db, req2.id, "deny", via="test", deny_reason="no")
    assert (await approvals.recently_denied(db, agent, ["ssh/nvr/exec/rm"])) is not None

    req3 = await approvals.create(db, agent, None, ["mcp/ha/tools/get_state"], "read")
    await approvals.decide(db, req3.id, "always", via="ui")
    assert (await policy.evaluate(db, agent, None, ["mcp/ha/tools/get_state"])).matched["mcp/ha/tools/get_state"].startswith("policy:")

    # deciding twice is a no-op
    again = await approvals.decide(db, req3.id, "deny", via="test")
    assert again.status == "approved"


async def test_decision_tokens_roundtrip(db):
    tok = approvals.decision_token("req_x", "once")
    assert approvals.parse_decision_token(tok) == ("req_x", "once")
    assert approvals.parse_decision_token(tok + "x") is None
    links = approvals.decision_links("req_x")
    assert set(links) == set(approvals.PHONE_SCOPES) and links["deny"].startswith("http://gk.test/d/")


async def test_session_grant_without_session_id_is_dead(db, agent, resources):
    """Legacy rows minted before the fix must fail closed, not become agent-wide."""
    db.add(Grant(agent_id=agent.id, pattern="ssh/nvr/exec/**", scope="session", session_id=None,
                 expires_at=now() + timedelta(hours=1)))
    await db.commit()
    for sid in (None, "s1"):
        assert (await policy.evaluate(db, agent, sid, ["ssh/nvr/exec/ls"])).status == "pending"
    assert (await policy.effective_access(db, agent, None))[1]["grants"] == []


async def test_session_scope_refused_for_requests_without_session(db, agent, resources):
    req = await approvals.create(db, agent, None, ["ssh/nvr/exec/ls"], "no session")
    assert approvals.offered_scopes(req) == ("once", "ttl15", "ttl30", "ttl", "deny")
    with pytest.raises(ValueError, match="no session id"):
        await approvals.decide(db, req.id, "session", via="ui")
    await db.refresh(req)
    assert req.status == "pending"
    ok = await approvals.decide(db, req.id, "ttl", via="ui", ttl_s=60)
    assert ok.status == "approved"

    with_session = await approvals.create(db, agent, "s1", ["ssh/nvr/exec/df"], "has session")
    assert "session" in approvals.offered_scopes(with_session)
    done = await approvals.decide(db, with_session.id, "session", via="ui")
    assert done.status == "approved"
    grant = (await db.execute(select(Grant).where(Grant.request_id == with_session.id))).scalar_one()
    assert grant.session_id == "s1"
    assert grant.expires_at <= now() + timedelta(seconds=settings.session_grant_ttl_s + 5)


def test_session_grant_ttl_default_is_one_hour():
    assert settings.session_grant_ttl_s == 3600


@pytest.fixture
async def ha(db):
    db.add(Resource(kind="mcp", name="ha", default_mode="approval",
                    config={"url": "http://ha.test/mcp", "arg_keys": ["service", "entity_id"]}))
    await db.commit()


async def test_qualified_deny_beats_tool_grant(db, agent, ha):
    from keywright.classify import classify_mcp
    t = "mcp/ha/tools/call_service"
    db.add(Grant(agent_id=agent.id, pattern=t, scope="ttl", expires_at=now() + timedelta(hours=1)))
    db.add(Policy(pattern=f"{t}/service=automation.turn_off", effect="deny"))
    db.add(Policy(pattern=f"{t}/entity_id=automation.eli_*", effect="deny"))
    await db.commit()
    ok = classify_mcp("ha", "call_service", {"service": "automation.trigger", "entity_id": "automation.sleep"},
                      ["service", "entity_id"])
    assert (await policy.evaluate(db, agent, None, ok)).allowed
    for args in ({"service": "automation.turn_off", "entity_id": "automation.sleep"},
                 {"service": "automation.trigger", "entity_id": "automation.eli_vent_alarm"},
                 {"service": "light.turn_on", "entity_id": ["light.a", "automation.eli_x"]}):
        req = classify_mcp("ha", "call_service", args, ["service", "entity_id"])
        assert (await policy.evaluate(db, agent, None, req)).status == "deny"
    # a call with none of the keys needs the bare tool, which the grant covers
    assert (await policy.evaluate(db, agent, None, classify_mcp("ha", "call_service", {}, ["service"]))).allowed


async def test_narrow_grant_covers_only_its_value(db, agent, ha):
    from keywright.classify import classify_mcp
    t = "mcp/ha/tools/call_service"
    db.add(Grant(agent_id=agent.id, pattern=f"{t}/service=automation.trigger", scope="ttl",
                 expires_at=now() + timedelta(hours=1)))
    db.add(Grant(agent_id=agent.id, pattern=f"{t}/entity_id=light.*", scope="ttl",
                 expires_at=now() + timedelta(hours=1)))
    await db.commit()
    keys = ["service", "entity_id"]
    assert (await policy.evaluate(db, agent, None, classify_mcp("ha", "call_service",
            {"service": "automation.trigger", "entity_id": "light.kitchen"}, keys))).allowed
    v = await policy.evaluate(db, agent, None, classify_mcp("ha", "call_service",
            {"service": "automation.turn_off", "entity_id": "light.kitchen"}, keys))
    assert v.status == "pending" and v.missing == [f"{t}/service=automation.turn_off"]
    v = await policy.evaluate(db, agent, None, classify_mcp("ha", "call_service",
            {"service": "automation.trigger", "entity_id": "switch.alarm"}, keys))
    assert v.status == "pending" and v.missing == [f"{t}/entity_id=switch.alarm"]
    # the narrow grant does not cover the bare tool (a call without those arguments)
    assert (await policy.evaluate(db, agent, None, [t])).status == "pending"
    listing = {r["resource"]: r for r in await policy.effective_access(db, agent, None)}
    assert listing["mcp/ha"]["argument_keys"] == ["service", "entity_id"]


async def test_proxy_call_is_gated_by_arguments(db, agent, ha, log_notifier, monkeypatch):
    from mcp import types

    from keywright_server import mcp_proxy, mcp_server
    calls = []

    async def fake_call(config, tool, arguments):
        calls.append((tool, arguments))
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])
    monkeypatch.setattr(mcp_proxy, "call_tool", fake_call)
    t = "mcp/ha/tools/call_service"
    db.add(Policy(pattern=t, effect="allow"))
    db.add(Policy(pattern=f"{t}/service=automation.turn_off", effect="deny"))
    await db.commit()
    out = await mcp_server._proxy_call(db, agent, None, "ha", "call_service",
                                       {"service": "light.turn_on", "entity_id": "light.a", "_reason": "lamp"})
    assert not out.is_error and calls == [("call_service", {"service": "light.turn_on", "entity_id": "light.a"})]
    out = await mcp_server._proxy_call(db, agent, None, "ha", "call_service",
                                       {"service": "automation.turn_off", "entity_id": "automation.alarm"})
    assert out.is_error and out.structured_content["error"] == "denied"
    assert out.structured_content["patterns"] == [f"{t}/service=automation.turn_off"]
    assert len(calls) == 1


async def test_allowed_calls_carry_an_audit_handle(db, agent, ha, log_notifier, monkeypatch):
    from mcp import types
    from sqlalchemy import select as sel

    from keywright_server import mcp_proxy, mcp_server
    from keywright_server.models import AuditEvent

    async def fake_call(config, tool, arguments):
        return types.CallToolResult(content=[types.TextContent(type="text", text="upstream")],
                                    structured_content={"ok": 1})
    monkeypatch.setattr(mcp_proxy, "call_tool", fake_call)
    t = "mcp/ha/tools/call_service"
    req = await approvals.create(db, agent, None, [f"{t}/service=light.turn_on"], "lamp")
    await approvals.decide(db, req.id, "ttl", via="ui", ttl_s=60)
    grant = (await db.execute(sel(Grant).where(Grant.request_id == req.id))).scalar_one()

    out = await mcp_server._proxy_call(db, agent, None, "ha", "call_service", {"service": "light.turn_on"})
    assert not out.is_error
    assert out.structured_content == {"ok": 1} and out.content[0].text == "upstream"  # upstream untouched
    handle = out.meta["keywright"]
    event = (await db.execute(sel(AuditEvent).order_by(AuditEvent.id.desc()))).scalars().first()
    assert handle["audit_id"] == event.id and event.tool == "mcp_call" and event.decision == "allow"
    assert handle["matched"] == {f"{t}/service=light.turn_on": f"grant:{grant.id}"}
    assert handle["request_ids"] == [req.id] and handle["consumed_grants"] == []
    assert out.content[-1].text.startswith(f"[keywright] audit #{event.id} | ") and req.id in out.content[-1].text

    # opt-out per resource leaves the upstream result exactly as it came
    res = (await db.execute(sel(Resource).where(Resource.name == "ha"))).scalar_one()
    res.config = {**res.config, "audit_handle": False}
    await db.commit()
    out = await mcp_server._proxy_call(db, agent, None, "ha", "call_service", {"service": "light.turn_on"})
    assert out.meta is None and len(out.content) == 1


async def test_invalid_pattern_explains_the_rules(db, agent, ha, log_notifier):
    from keywright.patterns import PATTERN_HELP

    from keywright_server import mcp_server
    for bad in (["mcp/ha/tools/*get_state"], ["mcp/ha/tools/ha get"], ["mcp/*/tools/x"], ["mcp/ha/**/x"]):
        out = await mcp_server._access_request(db, agent, None, {"patterns": bad, "reason": "r", "wait_seconds": 0})
        assert out.is_error and out.structured_content["error"] == "invalid_pattern", bad
        assert out.structured_content["hint"] == PATTERN_HELP and out.structured_content["message"]
    ok = await mcp_server._access_request(db, agent, None, {"patterns": ["mcp/ha/tools/ha_get_*"], "reason": "r",
                                                            "wait_seconds": 0})
    assert ok.structured_content["status"] == "pending"


@pytest.fixture
async def ha_bundled(db, ha):
    res = (await db.execute(select(Resource).where(Resource.name == "ha"))).scalar_one()
    res.config = {**res.config, "bundles": {"read-only": ["tools/ha_get_*", "tools/ha_search"],
                                            "control": ["tools/ha_call_service/service=light.*"]}}
    await db.commit()


async def test_bundle_request_expands_and_groups(db, agent, ha_bundled, log_notifier):
    from keywright_server import mcp_server
    from keywright_server.models import AccessRequest
    from keywright_server.notify.base import request_summary

    out = await mcp_server._access_request(db, agent, None, {
        "patterns": ["mcp/ha/bundle/read-only", "mcp/ha/bundle/control", "mcp/ha/tools/ha_search",
                     "mcp/ha/tools/ha_get_history"], "reason": "discover", "wait_seconds": 0})
    p = out.structured_content
    assert p["status"] == "pending"
    assert p["patterns"] == ["mcp/ha/tools/ha_get_*", "mcp/ha/tools/ha_search",
                             "mcp/ha/tools/ha_call_service/service=light.*", "mcp/ha/tools/ha_get_history"]
    req = await db.get(AccessRequest, p["request_id"])
    assert req.detail == {"bundles": {"ha/read-only": ["mcp/ha/tools/ha_get_*", "mcp/ha/tools/ha_search"],
                                      "ha/control": ["mcp/ha/tools/ha_call_service/service=light.*"]}}
    _, body = request_summary(req, agent)
    assert body.splitlines()[:3] == ["bundle ha/read-only (2 patterns)", "bundle ha/control (1 patterns)",
                                     "mcp/ha/tools/ha_get_history"]
    # the same request is reused, not duplicated
    again = await mcp_server._access_request(db, agent, None, {"patterns": ["mcp/ha/bundle/read-only",
                                             "mcp/ha/bundle/control", "mcp/ha/tools/ha_get_history"],
                                             "reason": "discover", "wait_seconds": 0})
    assert again.structured_content["request_id"] == p["request_id"]

    listing = {r["resource"]: r for r in await policy.effective_access(db, agent, None)}
    assert listing["mcp/ha"]["bundles"]["control"] == ["mcp/ha/tools/ha_call_service/service=light.*"]

    bad = await mcp_server._access_request(db, agent, None, {"patterns": ["mcp/ha/bundle/nope"], "reason": "r",
                                                             "wait_seconds": 0})
    assert bad.is_error and bad.structured_content["error"] == "unknown_bundle"
    assert bad.structured_content["available"] == ["control", "read-only"]


async def test_once_grant_from_bundle_request_covers_a_real_call(db, agent, ha_bundled, log_notifier, monkeypatch):
    from mcp import types

    from keywright_server import mcp_proxy, mcp_server

    async def fake_call(config, tool, arguments):
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])
    monkeypatch.setattr(mcp_proxy, "call_tool", fake_call)
    out = await mcp_server._access_request(db, agent, None, {"patterns": ["mcp/ha/bundle/read-only"],
                                                             "reason": "r", "wait_seconds": 0})
    rid = out.structured_content["request_id"]
    await approvals.decide(db, rid, "once", via="ui")
    call = await mcp_server._proxy_call(db, agent, None, "ha", "ha_get_state", {"entity_id": "light.a"})
    assert not call.is_error, call.structured_content
    # the bundle grouping only decorated the request; grants are on the expanded patterns
    assert call.meta["keywright"]["request_ids"] == [rid]


def test_server_instructions_state_the_proxy_scope():
    from keywright_server.mcp_server import build_server
    text = build_server().instructions
    assert "Only upstream TOOLS are proxied" in text and "prompts are not available" in text


async def test_repeated_discovery_with_large_grant_history(db, agent):
    """Exercise ORM refresh/collection across a realistic catalog and approval history."""
    db.add(Resource(name="catalog", kind="mcp", config={}, default_mode="approval"))
    db.add_all([
        Grant(agent_id=agent.id, pattern=f"mcp/catalog/tools/old-{i}", scope="once",
              uses_remaining=0, expires_at=now() - timedelta(days=1))
        for i in range(1200)
    ])
    active = Grant(agent_id=agent.id, pattern="mcp/catalog/tools/allowed", scope="once", uses_remaining=1)
    db.add(active)
    await db.commit()
    for i in range(150):
        verdict = await policy.evaluate(db, agent, None, [f"mcp/catalog/tools/read-{i}"],
                                        consume=False, discovery=True)
        assert verdict.status == "pending" and not verdict.allowed
    allowed = await policy.evaluate(db, agent, None, ["mcp/catalog/tools/allowed"],
                                    consume=False, discovery=True)
    assert allowed.allowed
    await db.refresh(active)
    assert active.uses_remaining == 1
