from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select

from keywright_server import audit, policy, policy_preview
from keywright_server.models import AccessRequest, Agent, AuditEvent, Grant, Policy, Resource, now


@pytest.fixture
async def target(db):
    target = Resource(kind="ssh", name="preview-host", default_mode="approval",
                      config={"host": "example.invalid", "user": "deploy"})
    db.add(target)
    await db.commit()
    return target


async def record(db, agent, target, *, command="docker ps", **kwargs):
    return await audit.record(db, agent=agent, session_id="session-a", tool="ssh_run", decision="allow",
                              patterns=[f"ssh/{target.name}/exec/docker/ps"],
                              detail={"resource_id": target.id, "host": target.name, "user": "deploy",
                                      "command": command, **kwargs})


def candidate(agent=None, effect="allow", pattern="ssh/preview-host/exec/docker/ps"):
    return Policy(id="preview", pattern=pattern, effect=effect, agent_id=agent.id if agent else None)


async def counts(db):
    return [await db.scalar(select(func.count()).select_from(model))
            for model in (Policy, Grant, AccessRequest, AuditEvent)]


async def test_preview_changes_decision_without_side_effects(db, agent, target, monkeypatch):
    from keywright_server import approvals, mcp_proxy, semantic, ssh

    async def forbidden(*args, **kwargs):
        pytest.fail("Preview attempted a side effect")

    for module, name in ((approvals, "create"), (mcp_proxy, "call_tool"), (mcp_proxy, "list_tools"),
                         (ssh, "run"), (semantic, "record")):
        monkeypatch.setattr(module, name, forbidden)
    ev = await record(db, agent, target)
    before = await counts(db)
    report = await policy_preview.preview(db, candidate())
    assert report["counts"] == {"changed": 1, "unchanged": 0, "inconclusive": 0}
    assert (report["rows"][0]["before"], report["rows"][0]["after"]) == ("pending", "allow")
    assert report["rows"][0]["id"] == ev.id
    assert await counts(db) == before
    assert not db.new and not db.dirty and not db.deleted


@pytest.mark.parametrize("guard,expected", [("deny", "deny"), ("disabled", "deny"),
                                            ("high", "pending"), ("critical", "refused")])
async def test_allow_candidate_cannot_bypass_guards(db, agent, target, guard, expected):
    command = "docker ps"
    if guard == "deny":
        db.add(Policy(pattern="ssh/preview-host/**", effect="deny"))
    elif guard == "disabled":
        agent.disabled_at = now()
    elif guard == "high":
        command = "reboot"
    elif guard == "critical":
        command = "rm -rf /"
    await db.commit()
    await record(db, agent, target, command=command)
    report = await policy_preview.preview(db, candidate(pattern="ssh/preview-host/**"))
    row = report["rows"][0]
    assert row["before"] == row["after"] == expected


async def test_grants_are_considered_independently_and_never_spent(db, agent, target):
    grant = Grant(agent_id=agent.id, pattern="ssh/preview-host/**", scope="once", uses_remaining=1,
                  expires_at=now() + timedelta(minutes=15))
    db.add(grant)
    await db.commit()
    await record(db, agent, target)
    await record(db, agent, target)
    report = await policy_preview.preview(db, candidate(effect="deny"))
    assert all((r["before"], r["after"]) == ("allow", "deny") for r in report["rows"])
    await db.refresh(grant)
    assert grant.uses_remaining == 1
    grant.expires_at = now() - timedelta(seconds=1)
    await db.commit()
    report = await policy_preview.preview(db, candidate(effect="deny"))
    assert all(r["before"] == "pending" for r in report["rows"])


async def test_exact_constraints_and_session_bindings_match_live_evaluator(db, agent, target):
    ev = await record(db, agent, target)
    paths, op = policy_preview._operation(ev, {target.id: target})
    db.add(Policy(pattern="ssh/preview-host/**", effect="deny", constraints={**op, "user": "root"}))
    db.add(Grant(agent_id=agent.id, pattern="ssh/preview-host/**", scope="session", session_id="other",
                 expires_at=now() + timedelta(minutes=15)))
    db.add(Policy(pattern="ssh/preview-host/**", effect="allow", constraints=op))
    await db.commit()
    live = await policy.evaluate(db, agent, "session-a", paths, consume=False, operation=op)
    report = await policy_preview.preview(db, candidate(pattern="ssh/preview-host/exec/df"))
    assert report["rows"][0]["before"] == live.status == "allow"
    assert report["rows"][0]["after"] == "allow"


async def test_agent_scope_and_global_candidate(db, agent, target):
    other = Agent(name="other", token_hash="other-hash", token_prefix="other")
    db.add(other)
    await db.commit()
    await record(db, agent, target)
    await record(db, other, target)
    one = await policy_preview.preview(db, candidate(agent))
    assert len(one["rows"]) == 1 and one["rows"][0]["agent"] == agent.name
    every = await policy_preview.preview(db, candidate())
    assert every["counts"]["changed"] == 2


@pytest.mark.parametrize("evidence", ["redacted", "truncated", "missing", "old_target", "deleted_agent"])
async def test_incomplete_evidence_never_claims_allow(db, agent, target, evidence):
    ev = await record(db, agent, target, command="x" * 4100 if evidence == "truncated" else "docker ps")
    if evidence == "redacted":
        ev.detail = {**ev.detail, "command": "***"}
    elif evidence == "missing":
        ev.detail = {k: v for k, v in ev.detail.items() if k != "user"}
    elif evidence == "old_target":
        ev.detail = {**ev.detail, "resource_id": "removed"}
    elif evidence == "deleted_agent":
        ev.agent_id = "removed"
    await db.commit()
    report = await policy_preview.preview(db, candidate())
    assert report["counts"]["inconclusive"] == 1
    assert report["rows"][0]["after"] == "inconclusive"
    assert "docker ps" not in str(report)


async def test_mcp_uses_current_argument_paths_hazards_and_typed_constraints(db, agent):
    res = Resource(kind="mcp", name="ha", default_mode="approval", config={"arg_keys": ["entity_id"]})
    db.add(res)
    await db.commit()
    op = {"resource_id": res.id, "server": "ha", "tool": "set",
          "arguments": {"entity_id": "light.a", "enabled": True}}
    ev = await audit.record(db, agent=agent, tool="mcp_call", decision="allow", detail=op,
                            patterns=["mcp/ha/tools/set"])
    db.add(Policy(pattern="mcp/ha/**", effect="deny",
                  constraints={"arguments": {"entity_id": "light.a", "enabled": 1}}))
    await db.commit()
    proposed = candidate(pattern="mcp/ha/tools/set/entity_id=light.a")
    report = await policy_preview.preview(db, proposed)
    assert report["rows"][0]["after"] == "allow"
    proposed.pattern = "mcp/ha/tools/set/entity_id=light.b"
    report = await policy_preview.preview(db, proposed)
    assert report["rows"][0]["after"] == "pending"
    proposed.pattern = "mcp/ha/tools/set"
    report = await policy_preview.preview(db, proposed)
    assert report["rows"][0]["after"] == "allow"
    res.config = {**res.config, "hazard_tools": {"high": ["tools/set"]}}
    await db.commit()
    report = await policy_preview.preview(db, proposed)
    assert report["rows"][0]["after"] == "pending"
    ev.detail = {**op, "arguments": {"password": "***"}}
    await db.commit()
    report = await policy_preview.preview(db, proposed)
    assert report["rows"][0]["after"] == "inconclusive"


async def test_window_limit_and_unsupported_llm_are_explicit(db, agent, target, monkeypatch):
    monkeypatch.setattr(policy_preview, "SAMPLE_LIMIT", 2)
    old = await record(db, agent, target)
    old.ts = now() - timedelta(days=31)
    await db.commit()
    assert not (await policy_preview.preview(db, candidate()))["rows"]
    await record(db, agent, target)
    await record(db, agent, target)
    ev = await audit.record(db, agent=agent, tool="llm.call", decision="allow", detail={"model": "test"})
    report = await policy_preview.preview(db, candidate())
    assert report["limited"] and len(report["rows"]) == 2
    assert report["rows"][0]["id"] == ev.id
    assert "LLM" in report["rows"][0]["reason"]
    assert report["counts"]["inconclusive"] == 1


@pytest.mark.parametrize("tool", ["ssh_get", "ssh_put", "ssh_capture"])
async def test_file_operations_keep_exact_binding_and_destination(db, agent, target, tool):
    op = {"resource_id": target.id, "host": target.name, "user": "deploy"}
    if tool == "ssh_capture":
        op.update(command="docker ps", to_host=target.name, to_resource_id=target.id,
                  to_user="deploy", to_path="/tmp/snapshot", append=False)
    else:
        op["path"] = "/tmp/snapshot"
        if tool == "ssh_put":
            op.update(sha256="a" * 64, bytes=25)
    ev = await audit.record(db, agent=agent, tool=tool, decision="allow", detail=op)
    db.add(Policy(pattern="ssh/preview-host/**", effect="allow", constraints=op))
    await db.commit()
    report = await policy_preview.preview(db, candidate(effect="deny", pattern="ssh/preview-host/**"))
    assert (report["rows"][0]["before"], report["rows"][0]["after"]) == ("allow", "deny")
    key = "to_path" if tool == "ssh_capture" else "path"
    ev.detail = {**op, key: "/tmp/other"}
    await db.commit()
    report = await policy_preview.preview(db, candidate(effect="deny", pattern="ssh/preview-host/**"))
    assert report["rows"][0]["before"] == "pending"


async def test_preview_ui_requires_auth_origin_and_explicit_save(db, agent, target):
    from keywright_server.web import auth
    from keywright_server.web.app import create_app

    await auth.set_password(db, "adminpass123")
    ev = await record(db, agent, target)
    transport = httpx.ASGITransport(app=create_app())
    data = {"pattern": "ssh/preview-host/**", "effect": "deny", "agent_id": agent.id,
            "note": '<script>alert("draft")</script>', "action": "preview"}
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        r = await http.post("/ui/policies", data=data, headers={"Origin": "http://testserver"})
        assert r.status_code in (303, 401, 403)
        await http.post("/ui/login", data={"password": "adminpass123"}, headers={"Origin": "http://testserver"})
        r = await http.post("/ui/policies", data=data, headers={"Origin": "https://evil.invalid"})
        assert r.status_code == 403
        before = await counts(db)
        r = await http.post("/ui/policies", data=data, headers={"Origin": "http://testserver"})
        assert r.status_code == 200 and "Rule preview · not saved" in r.text
        assert f'/ui/audit?q=%23{ev.id}' in r.text
        assert 'value="deny" selected' in r.text and f'value="{agent.id}" selected' in r.text
        assert "&lt;script&gt;" in r.text and '<script>alert("draft")</script>' not in r.text
        assert await counts(db) == before
        for invalid in ({"agent_id": "missing"}, {"effect": "bad"}, {"action": "bad"}, {"pattern": ""}):
            r = await http.post("/ui/policies", data={**data, **invalid}, headers={"Origin": "http://testserver"})
            assert "Rule preview · not saved" not in r.text
            assert await counts(db) == before
        r = await http.post("/ui/policies", data={**data, "action": "save"}, headers={"Origin": "http://testserver"})
        assert r.status_code == 303
        stored = (await db.execute(select(Policy))).scalar_one()
        assert stored.pattern == data["pattern"] and stored.agent_id == agent.id and stored.effect == "deny"
        assert stored.id != "preview"
