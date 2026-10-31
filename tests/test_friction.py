import re
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select

from keywright_server import audit, friction, policy
from keywright_server.models import AccessRequest, Agent, Grant, Policy, Resource, now


@pytest.fixture
async def target(db):
    res = Resource(kind="ssh", name="prod", default_mode="approval", config={"user": "deploy"})
    db.add(res)
    await db.commit()
    return res


def op(target, command="docker ps"):
    return {"resource_id": target.id, "host": target.name, "user": "deploy", "command": command}


async def request_row(db, agent, target, *, status="approved", via="ui", detail=None, index=0, **fields):
    created = now() - timedelta(minutes=20 + index)
    req = AccessRequest(agent_id=agent.id, session_id=f"run-{index}", patterns=["ssh/prod/exec/docker/ps"],
                        detail=detail if detail is not None else op(target), status=status, created_at=created,
                        expires_at=now() + timedelta(minutes=10),
                        decided_at=created + timedelta(seconds=60) if status in {"approved", "denied"} else None,
                        decided_via=via, decision_scope="once", decision_options={"extent": "exact"})
    for key, value in fields.items():
        setattr(req, key, value)
    db.add(req)
    await db.commit()
    return req


async def seed_support(db, agent, target):
    return [await request_row(db, agent, target, index=i) for i in range(3)]


async def report(db, **kwargs):
    return await friction.report(db, now() - timedelta(days=30), now(), **kwargs)


async def test_requests_are_not_counted_from_duplicate_lifecycle_events(db, agent, target):
    req = await request_row(db, agent, target)
    for tool, decision in [("access.request", "pending"), ("access.decide", "approved"),
                           ("ssh_run", "pending"), ("ssh_run", "pending"), ("ssh_run", "allow")]:
        await audit.record(db, agent=agent, tool=tool, decision=decision,
                           detail={**op(target), "request_id": req.id}, exit_code=0 if decision == "allow" else None)
    data = await report(db)
    assert data["totals"]["requests"] == data["totals"]["human_approved"] == 1
    assert data["totals"]["call_records"] == 3
    assert data["totals"]["lifecycle"] == 2
    assert data["totals"]["succeeded"] == 1
    assert not data["proposals"]


async def test_pending_expired_auto_and_missing_decision_times(db, agent, target):
    pending = await request_row(db, agent, target, status="pending")
    expired = await request_row(db, agent, target, status="pending", expires_at=now() - timedelta(seconds=1))
    await request_row(db, agent, target, decided_at=None)
    await request_row(db, agent, target, via="jev")
    await request_row(db, agent, target, status="denied")
    data = await report(db)
    assert data["totals"]["pending"] == data["totals"]["expired"] == 1
    assert data["totals"]["other_approved"] == 1
    assert data["coverage"]["missing_wait"] == 1
    assert data["wait_samples"] == 1 and data["median_wait"] == 60
    await db.refresh(expired)
    await db.refresh(pending)
    assert expired.status == pending.status == "pending"  # report is read-only


async def test_failed_results_and_policy_blocks_are_separate(db, agent, target):
    for decision, code in [("allow", 2), ("error", None), ("deny", None), ("allow", 0), ("allow", None)]:
        await audit.record(db, agent=agent, tool="ssh_run", decision=decision, detail=op(target), exit_code=code)
    await audit.record(db, agent=agent, tool="mcp_call", decision="allow", detail={"is_error": True})
    await audit.record(db, agent=agent, tool="mcp_call", decision="allow", detail={"is_error": False})
    await audit.record(db, agent=agent, tool="llm.call", decision="allow", detail={}, exit_code=200)
    await audit.record(db, agent=agent, tool="llm.call", decision="error", detail={}, exit_code=502)
    data = await report(db)
    assert data["totals"]["failed"] == 4
    assert data["totals"]["blocked"] == 1
    assert data["totals"]["succeeded"] == 3
    assert data["totals"]["unknown"] == 1
    assert data["totals"]["requests"] == 0
    assert data["rows"][0]["failures"] == 2


async def test_suggestion_preserves_exact_target_account_and_command(db, agent, target):
    support = await seed_support(db, agent, target)
    data = await report(db)
    assert len(data["proposals"]) == 1
    proposal = next(iter(data["proposals"].values()))
    assert proposal["support"] == 3
    candidate = proposal["rules"][0]
    assert candidate.agent_id == agent.id and candidate.constraints == op(target)
    assert candidate.request_id in {r.id for r in support}
    assert await db.scalar(select(func.count()).select_from(Policy)) == 0
    await friction.save_proposal(db, proposal)
    paths = ["ssh/prod/exec/docker/ps"]
    assert (await policy.evaluate(db, agent, None, paths, consume=False, operation=op(target))).allowed
    for changed in (op(target, "docker ps --all"), {**op(target), "user": "root"},
                    {**op(target), "resource_id": "replacement"}):
        assert not (await policy.evaluate(db, agent, None, paths, consume=False, operation=changed)).allowed
    assert not (await report(db))["proposals"]
    assert await db.scalar(select(func.count()).select_from(Grant)) == 0


@pytest.mark.parametrize("reason", ["deny", "locked", "disabled", "hazard", "old_hazard", "wildcard",
                                    "redacted", "truncated", "secret", "broad", "automatic", "failed", "blocked",
                                    "different", "batched", "missing", "partial", "future"])
async def test_no_suggestion_when_evidence_cannot_support_it(db, agent, target, reason):
    support = await seed_support(db, agent, target)
    if reason == "deny":
        db.add(Policy(pattern="ssh/prod/**", effect="deny"))
    elif reason == "locked":
        target.default_mode = "locked"
    elif reason == "disabled":
        agent.disabled_at = now()
    elif reason == "failed":
        await audit.record(db, agent=agent, tool="ssh_run", decision="allow", detail=op(target), exit_code=1)
    elif reason == "blocked":
        await audit.record(db, agent=agent, tool="ssh_run", decision="deny", detail=op(target))
    for i, req in enumerate(support):
        if reason == "hazard":
            req.detail = op(target, "reboot"); req.patterns = ["ssh/prod/exec/reboot"]
        elif reason == "old_hazard":
            req.detail = {**op(target), "hazards": [{"severity": "high", "reason": "old flag"}]}
        elif reason == "wildcard":
            req.detail = op(target, "bash -c 'ls'"); req.patterns = ["ssh/prod/exec/**"]
        elif reason == "redacted":
            req.detail = op(target, "***")
        elif reason == "truncated":
            req.detail = op(target, "x" * 5000)
        elif reason == "secret":
            req.detail = op(target, "curl -H 'Authorization: Bearer test-secret' https://example.test")
        elif reason == "broad":
            req.decision_options = {"extent": "patterns"}
        elif reason == "automatic":
            req.decided_via = "jev"
        elif reason == "different":
            req.detail = op(target, f"docker ps --filter name=service{i}")
        elif reason == "batched":
            req.detail = {"operations": [{"patterns": req.patterns, "operation": op(target)}]}
        elif reason == "missing":
            req.detail = {"command": "docker ps"}
        elif reason == "partial":
            req.patterns = []
        elif reason == "future":
            req.decided_at = now() + timedelta(days=1)
    await db.commit()
    assert not (await report(db))["proposals"]


async def test_denial_in_same_group_suppresses_suggestion(db, agent, target):
    await seed_support(db, agent, target)
    await request_row(db, agent, target, status="denied")
    assert not (await report(db))["proposals"]


async def test_invalid_legacy_patterns_do_not_crash_report(db, agent, target):
    target.name = "legacy name"
    await db.commit()
    for i in range(3):
        await request_row(db, agent, target, index=i, patterns=["ssh/legacy name/exec/docker/ps"])
    assert not (await report(db))["proposals"]


async def test_samples_agent_filters_dates_and_missing_evidence(db, agent, target, monkeypatch):
    await seed_support(db, agent, target)
    other = Agent(name="other", token_hash="other", token_prefix="other")
    db.add(other); await db.commit()
    await request_row(db, other, target)
    data = await report(db, agent_id=agent.id)
    assert data["totals"]["requests"] == 3
    assert len(data["proposals"]) == 1
    monkeypatch.setattr(friction, "ROW_LIMIT", 2)
    data = await report(db)
    assert data["limited"] and data["totals"]["requests"] == 2 and not data["proposals"]
    with pytest.raises(ValueError):
        await friction.report(db, now() - timedelta(days=91), now())
    data = await friction.report(db, now() - timedelta(days=5), now() - timedelta(days=4))
    assert not data["rows"]


async def test_mcp_suggestion_never_widens_arguments_or_json_types(db, agent):
    target = Resource(kind="mcp", name="ha", default_mode="approval", config={"arg_keys": ["entity_id"]})
    db.add(target); await db.commit()
    detail = {"resource_id": target.id, "server": "ha", "tool": "get_state",
              "arguments": {"entity_id": "light.a", "enabled": True}}
    for i in range(3):
        await request_row(db, agent, target, index=i, detail=detail,
                          patterns=["mcp/ha/tools/get_state/entity_id=light.a"])
    proposal = next(iter((await report(db))["proposals"].values()))
    assert proposal["rules"][0].constraints == detail
    await friction.save_proposal(db, proposal)
    paths = ["mcp/ha/tools/get_state/entity_id=light.a"]
    assert (await policy.evaluate(db, agent, None, paths, consume=False, operation=detail)).allowed
    changed = {**detail, "arguments": {"entity_id": "light.a", "enabled": 1}}
    assert not (await policy.evaluate(db, agent, None, paths, consume=False, operation=changed)).allowed


async def test_partial_audit_sample_disables_suggestions_and_incomplete_records_stay_separate(db, agent, target,
                                                                                           monkeypatch):
    await seed_support(db, agent, target)
    monkeypatch.setattr(friction, "ROW_LIMIT", 3)
    for _ in range(4):
        await audit.record(db, agent=agent, tool="mcp_call", decision="error", detail={"arguments": {"token": "***"}})
    data = await report(db)
    assert data["limited"] and not data["proposals"]
    assert data["coverage"]["incomplete_events"] == 3
    assert sum(1 for g in data["rows"] if g["failures"] == 1) == 3


async def test_multi_path_suggestion_previews_all_rules_together(db, agent):
    from keywright_server import policy_preview

    target = Resource(kind="mcp", name="ha", default_mode="approval", config={"arg_keys": ["entity_id", "mode"]})
    db.add(target); await db.commit()
    detail = {"resource_id": target.id, "server": "ha", "tool": "get_state",
              "arguments": {"entity_id": "light.a", "mode": "state"}}
    paths = ["mcp/ha/tools/get_state/entity_id=light.a", "mcp/ha/tools/get_state/mode=state"]
    for i in range(3):
        await request_row(db, agent, target, index=i, detail=detail, patterns=paths)
    await audit.record(db, agent=agent, tool="mcp_call", decision="allow", detail=detail)
    proposal = next(iter((await report(db))["proposals"].values()))
    rules = proposal["rules"]
    assert len(rules) == 2
    preview = await policy_preview.preview(db, rules[0], additional=tuple(rules[1:]))
    assert preview["rows"][0]["before"] == "pending" and preview["rows"][0]["after"] == "allow"
    assert await db.scalar(select(func.count()).select_from(Policy)) == 0


@pytest.mark.parametrize("change", ["deny", "expired", "disabled"])
async def test_save_rejects_changed_access_or_expired_review(db, agent, target, monkeypatch, change):
    import time

    from itsdangerous.timed import TimestampSigner

    from keywright_server.web import auth, friction_ui
    from keywright_server.web.app import create_app

    await auth.set_password(db, "adminpass123")
    support = await seed_support(db, agent, target)
    url = f"/ui/friction/review/{support[0].id}"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://testserver",
                                 headers={"Origin": "http://testserver"}) as http:
        await http.post("/ui/login", data={"password": "adminpass123"})
        page = await http.get(url)
        token = re.search(r'name="token" value="([^"]+)"', page.text).group(1)
        assert set(friction_ui.signer().loads(token)) == {"request", "fingerprint", "filters"}
        if change == "deny":
            db.add(Policy(pattern="ssh/prod/**", effect="deny"))
            await db.commit()
        elif change == "disabled":
            agent.disabled_at = now(); await db.commit()
        else:
            monkeypatch.setattr(TimestampSigner, "get_timestamp", lambda self: int(time.time()) + 601)
        response = await http.post(url, data={"token": token})
        assert response.status_code == 303
        assert await db.scalar(select(func.count()).select_from(Policy).where(Policy.effect == "allow")) == 0


async def test_ui_requires_review_token_revalidates_and_never_renders_inputs(db, agent, target):
    from keywright_server.web import auth
    from keywright_server.web.app import create_app

    await auth.set_password(db, "adminpass123")
    support = await seed_support(db, agent, target)
    await request_row(db, agent, target, detail=op(target, "echo PRIVATE-FREE-TEXT"))
    await audit.record(db, agent=agent, tool="ssh_run", decision="error",
                       detail={**op(target, "echo OTHER-PRIVATE-TEXT"), "error": "SECRET-ERROR-TEXT"})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://testserver",
                                 headers={"Origin": "http://testserver"}) as http:
        assert (await http.get("/ui/friction")).status_code == 303
        await http.post("/ui/login", data={"password": "adminpass123"})
        page = await http.get("/ui/friction")
        assert page.status_code == 200 and "4 distinct requests" in page.text
        assert all(s not in page.text for s in ("docker ps", "PRIVATE-FREE-TEXT", "OTHER-PRIVATE-TEXT", "SECRET-ERROR-TEXT"))
        url = f"/ui/friction/review/{support[0].id}"
        review = await http.get(url)
        assert review.status_code == 200 and "Rule preview · not saved" in review.text
        assert "docker ps" not in review.text and "exact recorded operation" in review.text
        token = re.search(r'name="token" value="([^"]+)"', review.text).group(1)
        response = await http.post(url, data={"token": token}, headers={"Origin": "https://evil.invalid"})
        assert response.status_code == 403
        await http.post(url, data={"token": "forged"})
        assert await db.scalar(select(func.count()).select_from(Policy)) == 0
        target.config = {"user": "root"}
        await db.commit()
        await http.post(url, data={"token": token})
        assert await db.scalar(select(func.count()).select_from(Policy)) == 0
        assert (await http.get(url)).status_code == 303  # new default account changes required paths
        target.config = {"user": "deploy", "host": "new-host"}
        await db.commit()
        await http.post(url, data={"token": token})
        assert await db.scalar(select(func.count()).select_from(Policy)) == 0  # target drift invalidates review too
        review = await http.get(url)
        token = re.search(r'name="token" value="([^"]+)"', review.text).group(1)
        response = await http.post(url, data={"token": token, "effect": "allow", "pattern": "**", "agent_id": ""})
        assert response.status_code == 303 and response.headers["location"] == "/ui/policies"
        stored = (await db.scalars(select(Policy))).one()
        assert stored.agent_id == agent.id and stored.pattern == "ssh/prod/exec/docker/ps"
        assert stored.constraints == op(target)
        await http.post(url, data={"token": token})
        assert await db.scalar(select(func.count()).select_from(Policy)) == 1
        assert await db.scalar(select(func.count()).select_from(Grant)) == 0
        bad_dates = await http.get("/ui/friction?start=2025-01-01&end=2026-01-01")
        assert "Showing the last 30 days" in bad_dates.text
