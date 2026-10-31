"""A flagged operation overrides standing access: high always prompts and is approved once, exactly;
critical is refused before anyone is asked."""
import json

import pytest
from sqlalchemy import select

from keywright_server import approvals, mcp_server, policy, ssh
from keywright_server.models import AccessRequest, AuditEvent, Grant, Policy, Resource
from keywright_server.notify.base import request_summary


@pytest.fixture
async def target(db):
    res = Resource(kind="ssh", name="prod", default_mode="approval", config={"host": "prod.internal", "user": "root"})
    db.add(res)
    await db.commit()
    return res


@pytest.fixture
def no_ssh(monkeypatch):
    calls = []

    async def run(config, command, **kwargs):
        calls.append(command)
        return ssh.RunResult(0, "ok", "", False, 1)

    monkeypatch.setattr(ssh, "run", run)
    return calls


def op(target, command):
    required, detail = mcp_server._run_operation(target, command, "root")
    return required, detail


async def test_standing_rule_covers_medium_but_not_high(db, agent, target):
    db.add(Policy(agent_id=None, pattern="ssh/prod/exec/rm", effect="allow", constraints=None))
    await db.commit()
    required, detail = op(target, "rm -rf /tmp/build")
    v = await policy.evaluate(db, agent, None, required, operation=detail)
    assert v.allowed and v.hazard == "medium"
    required, detail = op(target, "rm -rf /opt/*")
    v = await policy.evaluate(db, agent, None, required, operation=detail)
    assert not v.allowed and v.status == "pending" and v.hazard == "high" and v.missing == required


async def test_timed_and_wildcard_grants_do_not_cover_high(db, agent, target):
    for pattern, scope in (("ssh/prod/exec/**", "ttl"), ("ssh/prod/exec/git/push", "session")):
        db.add(Grant(agent_id=agent.id, pattern=pattern, scope=scope, constraints=None,
                     session_id="s1" if scope == "session" else None, expires_at=None, uses_remaining=None))
    # a once grant that is not bound to the exact command does not count either
    db.add(Grant(agent_id=agent.id, pattern="ssh/prod/exec/git/push", scope="once", constraints=None, uses_remaining=1))
    await db.commit()
    required, detail = op(target, "git push --force origin main")
    v = await policy.evaluate(db, agent, "s1", required, operation=detail)
    assert not v.allowed and v.hazard == "high"
    # deny rules still win outright
    db.add(Policy(agent_id=None, pattern="ssh/prod/exec/git/push", effect="deny", constraints=None))
    await db.commit()
    assert (await policy.evaluate(db, agent, "s1", required, operation=detail)).status == "deny"


async def test_high_is_approved_once_and_exactly(db, agent, target, log_notifier):
    required, detail = op(target, "docker compose down -v")
    req = await approvals.create(db, agent, "s1", required, "reset the stack", detail)
    assert approvals.offered_scopes(req) == ("once", "deny")
    title, body = request_summary(req, agent)
    assert title.startswith("Keywright DESTRUCTIVE (high)")
    assert "FLAGGED high: high: docker compose down -v" in body and "once" in body
    for scope, extent in (("ttl", None), ("ttl15", None), ("session", None), ("always", None), ("once", "patterns")):
        with pytest.raises(ValueError, match="destructive"):
            await approvals.decide(db, req.id, scope, via="ui", extent=extent)
    await db.refresh(req)
    assert req.status == "pending"
    await approvals.decide(db, req.id, "once", via="link")
    grant = (await db.execute(select(Grant).where(Grant.request_id == req.id))).scalar_one()
    assert grant.scope == "once" and grant.constraints == {k: v for k, v in detail.items() if k != "hazards"}
    v = await policy.evaluate(db, agent, "s1", required, operation=detail)
    assert v.allowed and v.hazard == "high" and v.consumed_grants == [grant.id]
    v = await policy.evaluate(db, agent, "s1", required, operation=detail)
    assert not v.allowed and v.status == "pending"
    # the same approval does not cover a different flagged command
    other_required, other = op(target, "docker compose down --volumes")
    again = await approvals.create(db, agent, "s1", other_required, "again", other)
    await approvals.decide(db, again.id, "once", via="link")
    assert not (await policy.evaluate(db, agent, "s1", required, operation=detail)).allowed


async def test_always_deny_still_works_for_flagged(db, agent, target, log_notifier):
    required, detail = op(target, "zpool destroy tank")
    req = await approvals.create(db, agent, None, required, "no", detail)
    await approvals.decide(db, req.id, "deny_always", via="ui")
    rule = (await db.execute(select(Policy).where(Policy.request_id == req.id))).scalar_one()
    assert rule.effect == "deny" and rule.constraints["command"] == "zpool destroy tank" and "hazards" not in rule.constraints
    assert (await policy.evaluate(db, agent, None, required, operation=detail)).status == "deny"


async def test_critical_is_refused_whatever_the_access(db, agent, target, log_notifier, no_ssh):
    db.add(Policy(agent_id=None, pattern="ssh/prod/exec/**", effect="allow", constraints=None))
    await db.commit()
    for command in ("rm -rf /home", "bash -c 'rm -rf /'", "python3 -c \"import shutil; shutil.rmtree('/home/john')\""):
        result = await mcp_server._ssh_run(db, agent, None, {"host": "prod", "command": command, "wait_seconds": 0})
        assert result.is_error and result.structured_content["error"] == "refused"
        assert result.structured_content["hazards"][0]["severity"] == "critical"
        assert "by hand" in result.structured_content["hint"]
    assert no_ssh == []
    assert (await db.execute(select(AccessRequest))).scalars().all() == []
    events = (await db.execute(select(AuditEvent).where(AuditEvent.decision == "refused"))).scalars().all()
    assert len(events) == 3 and events[0].detail["hazards"][0]["reason"] == "recursive delete of /home"


async def test_high_prompts_despite_a_wildcard_hour_and_runs_after_one_tap(db, agent, target, log_notifier, no_ssh, monkeypatch):
    db.add(Grant(agent_id=agent.id, pattern="ssh/prod/exec/**", scope="ttl", constraints=None, uses_remaining=None))
    await db.commit()
    args = {"host": "prod", "command": "qm destroy 118 --purge", "wait_seconds": 0}
    result = await mcp_server._ssh_run(db, agent, None, args)
    assert result.is_error and result.structured_content["error"] == "approval_required"
    assert result.structured_content["hazard"] == "high" and "reword" in result.structured_content["hint"]
    req = (await db.execute(select(AccessRequest))).scalar_one()
    assert req.detail["hazards"] == [{"severity": "high", "reason": "qm destroy 118: deletes a guest and its disks"}]
    assert no_ssh == []

    async def approve(request_id, timeout):
        from keywright_server.db import session

        async with session() as other:
            await approvals.decide(other, request_id, "once", via="link")

    monkeypatch.setattr(approvals, "wait", approve)
    result = await mcp_server._ssh_run(db, agent, None, {**args, "wait_seconds": 5})
    assert not result.is_error and no_ssh == ["qm destroy 118 --purge"]
    assert result.structured_content["keywright"]["hazard"] == "high"
    assert "flagged high" in result.content[0].text
    # the once grant is used up: the same call prompts again
    monkeypatch.setattr(approvals, "wait", lambda *_: _noop())
    result = await mcp_server._ssh_run(db, agent, None, args)
    assert result.is_error and result.structured_content["error"] == "approval_required"


async def _noop():
    return None


async def test_batched_request_refuses_critical_and_flags_the_rest(db, agent, target, log_notifier):
    ops = [{"host": "prod", "command": "docker ps"}, {"host": "prod", "command": "rm -rf /"}]
    result = await mcp_server._access_request(db, agent, None, {"operations": ops, "reason": "x", "wait_seconds": 0})
    assert result.is_error and result.structured_content["error"] == "refused" and result.structured_content["index"] == 1
    ops = [{"host": "prod", "command": "docker ps"}, {"host": "prod", "command": "docker volume rm data"}]
    result = await mcp_server._access_request(db, agent, None, {"operations": ops, "reason": "x", "wait_seconds": 0})
    req = (await db.execute(select(AccessRequest))).scalar_one()
    assert approvals.offered_scopes(req) == ("once", "deny")
    assert [h["severity"] for h in __import__("keywright_server.access", fromlist=["hazards_of"]).hazards_of(req.detail)] == ["high"]
    with pytest.raises(ValueError, match="destructive"):
        await approvals.decide(db, req.id, "ttl30", via="ui")
    await approvals.decide(db, req.id, "once", via="ui")
    grants = (await db.execute(select(Grant).where(Grant.request_id == req.id))).scalars().all()
    assert all("hazards" not in g.constraints for g in grants)


async def test_put_and_get_of_sensitive_paths_prompt_under_directory_rules(db, agent, target, log_notifier, no_ssh):
    db.add(Policy(agent_id=None, pattern="ssh/prod/put/**", effect="allow", constraints=None))
    db.add(Policy(agent_id=None, pattern="ssh/prod/get/**", effect="allow", constraints=None))
    await db.commit()
    ok = await mcp_server._ssh_put(db, agent, None, {"host": "prod", "path": "/etc/komodo/stacks/x.yml", "content": "a",
                                                     "wait_seconds": 0})
    assert not ok.is_error
    flagged = await mcp_server._ssh_put(db, agent, None, {"host": "prod", "path": "/etc/sudoers.d/agent", "content": "a",
                                                          "wait_seconds": 0})
    assert flagged.is_error and flagged.structured_content["error"] == "approval_required"
    assert flagged.structured_content["hazards"][0]["reason"].startswith("overwrites login and privilege configuration")
    read = await mcp_server._ssh_get(db, agent, None, {"host": "prod", "path": "/root/.ssh/id_ed25519", "wait_seconds": 0})
    assert read.is_error and read.structured_content["hazard"] == "high"
    assert len(no_ssh) == 1


async def test_flagged_ui_offers_once_only(live_server, db, agent, target, log_notifier):
    import httpx

    required, detail = op(target, "git reset --hard HEAD~3")
    req = await approvals.create(db, agent, None, required, "undo", detail)
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}, follow_redirects=True) as c:
        await c.post("/ui/login", data={"password": "adminpass123"})
        page = (await c.get(f"/ui/requests/{req.id}")).text
        assert "Flagged destructive (high)" in page and "git reset --hard" in page
        assert 'value="once"' in page and 'value="ttl"' not in page and 'value="always"' not in page
        r = await c.post(f"/ui/requests/{req.id}/decide", data={"scope": "ttl", "next": f"/ui/requests/{req.id}"})
        assert "destructive" in r.text
        link = (await c.get(f"/d/{approvals.decision_token(req.id, 'ttl')}")).text
        assert "Flagged destructive" in link
        r = await c.post(f"/d/{approvals.decision_token(req.id, 'ttl')}")
        assert "destructive" in r.text
    await db.refresh(req)
    assert req.status == "pending"


# ---- brokered MCP tools ---------------------------------------------------------------------------
@pytest.fixture
async def ha(db, monkeypatch):
    """A brokered server whose owner listed one tool as high and one service as critical."""
    from mcp import types

    from keywright_server import mcp_proxy

    res = Resource(kind="mcp", name="ha", default_mode="open", config={
        "url": "http://ha.test/mcp", "arg_keys": ["service"],
        "hazard_tools": {"high": ["tools/ha_manage_app"], "critical": ["tools/ha_call_service/service=homeassistant.stop"]},
    })
    db.add(res)
    await db.commit()
    calls = []

    async def call_tool(config, tool, arguments):
        calls.append((tool, dict(arguments or {})))
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])

    monkeypatch.setattr(mcp_proxy, "call_tool", call_tool)
    return calls


async def test_a_destructive_sounding_tool_name_is_flagged_medium_and_still_runs_on_open_access(db, agent, ha):
    out = await mcp_server._proxy_call(db, agent, None, "ha", "ha_delete_automation", {"id": "a1"})
    assert not out.is_error and ha == [("ha_delete_automation", {"id": "a1"})]
    ev = (await db.execute(select(AuditEvent).where(AuditEvent.decision == "allow"))).scalar_one()
    assert ev.detail["hazards"] == [{"severity": "medium",
                                     "reason": "tool name suggests a destructive action (delete)"}]


async def test_a_tool_the_owner_listed_high_needs_a_fresh_once_approval_despite_open_access(db, agent, ha):
    out = await mcp_server._proxy_call(db, agent, None, "ha", "ha_manage_app", {"slug": "core_ssh", "action": "stop",
                                                                                "_wait_seconds": 0})
    p = json.loads(out.content[0].text)
    assert out.is_error and p["error"] == "approval_required" and p["hazard"] == "high" and ha == []
    req = await db.get(AccessRequest, p["request_id"])
    assert approvals.offered_scopes(req) == ("once", "deny")
    with pytest.raises(ValueError, match="destructive"):
        await approvals.decide(db, req.id, "ttl15", via="ui")
    await approvals.decide(db, req.id, "once", via="ui")
    out = await mcp_server._proxy_call(db, agent, None, "ha", "ha_manage_app", {"slug": "core_ssh", "action": "stop"})
    assert not out.is_error and ha == [("ha_manage_app", {"slug": "core_ssh", "action": "stop"})]
    # the once grant bound the exact arguments: a different action asks again
    out = await mcp_server._proxy_call(db, agent, None, "ha", "ha_manage_app", {"slug": "core_ssh", "action": "uninstall",
                                                                                "_wait_seconds": 0})
    assert out.is_error and json.loads(out.content[0].text)["error"] == "approval_required" and len(ha) == 1


async def test_a_call_the_owner_listed_critical_is_refused_before_anyone_is_asked(db, agent, ha):
    out = await mcp_server._proxy_call(db, agent, None, "ha", "ha_call_service",
                                       {"service": "homeassistant.stop", "_wait_seconds": 0})
    p = json.loads(out.content[0].text)
    assert out.is_error and p["error"] == "refused" and ha == []
    assert (await db.execute(select(AccessRequest))).scalars().all() == []
    ev = (await db.execute(select(AuditEvent).where(AuditEvent.decision == "refused"))).scalar_one()
    assert ev.detail["hazards"][0]["severity"] == "critical"
    # the same tool with another service is not listed and runs on the open default
    out = await mcp_server._proxy_call(db, agent, None, "ha", "ha_call_service", {"service": "light.turn_on"})
    assert not out.is_error and ha == [("ha_call_service", {"service": "light.turn_on"})]


async def test_the_hazard_catalog_is_saved_from_the_resource_form_and_validated(live_server, db):
    import httpx

    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as http:
        await http.post("/ui/login", data={"password": "adminpass123"})
        form = {"kind": "mcp", "name": "ha", "url": "http://ha.test/mcp", "arg_keys": "service",
                "hazard_tools_text": "high: tools/ha_manage_app\ncritical: tools/ha_call_service/service=homeassistant.stop"}
        r = await http.post("/ui/resources", data=form, follow_redirects=True)
        assert "not saved" not in r.text and "must start" not in r.text, r.text[:400]
        res = (await db.execute(select(Resource).where(Resource.name == "ha"))).scalar_one()
        assert res.config["hazard_tools"] == {"high": ["tools/ha_manage_app"],
                                              "critical": ["tools/ha_call_service/service=homeassistant.stop"]}
        page = (await http.get(f"/ui/resources/{res.id}")).text
        assert "high: tools/ha_manage_app" in page
        r = await http.post("/ui/resources", data={**form, "rid": res.id, "hazard_tools_text": "severe: tools/x"},
                            follow_redirects=True)
        assert "must start with one of medium, high, critical" in r.text
