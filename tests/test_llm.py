"""LLM gateways: an approval mints a LiteLLM virtual key, a revocation deletes it, and nothing is
minted when the gateway cannot enforce budgets."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from sqlalchemy import select

from keywright_server import approvals, llm, policy
from keywright_server.models import AuditEvent, Grant, LlmKey, Resource

GW = "http://litellm.test:4000"


@pytest.fixture
async def gateway(db):
    res = Resource(kind="llm", name="litellm", default_mode="approval", config={
        "url": GW, "master_key": "sk-master", "models": ["claude-sonnet-5", "gpt-5.6", "openrouter/x/video"],
        "limits": {"max_budget": 2.0, "rpm_limit": 30, "tpm_limit": None, "max_parallel_requests": 4},
        "agent_budget": {"max_budget": 10.0, "budget_duration": "1d"},
    })
    db.add(res)
    await db.commit()
    return res


def mock_gateway(*, db="connected", user_exists=False):
    respx.get(f"{GW}/health/readiness").mock(return_value=httpx.Response(
        200, json={"status": "healthy", "db": db, "litellm_version": "1.101.0"}))
    respx.get(f"{GW}/v1/models").mock(return_value=httpx.Response(
        200, json={"data": [{"id": "gpt-5.6"}, {"id": "claude-sonnet-5"}]}))
    respx.get(f"{GW}/user/info").mock(return_value=httpx.Response(
        200, json={"user_id": "kw-x", "user_info": {"user_id": "kw-x"}}) if user_exists
        else httpx.Response(404, json={"error": {"message": "User not found"}}))
    respx.post(f"{GW}/user/new").mock(return_value=httpx.Response(200, json={"user_id": "kw-x"}))
    respx.post(f"{GW}/user/update").mock(return_value=httpx.Response(200, json={"user_id": "kw-x"}))
    generate = respx.post(f"{GW}/key/generate").mock(return_value=httpx.Response(
        200, json={"key": "sk-virtual-1", "expires": "2026-09-21T00:00:00Z"}))
    delete = respx.post(f"{GW}/key/delete").mock(return_value=httpx.Response(200, json={"deleted_keys": ["sk-virtual-1"]}))
    update = respx.post(f"{GW}/key/update").mock(return_value=httpx.Response(200, json={}))
    respx.get(f"{GW}/key/info").mock(return_value=httpx.Response(200, json={"info": {"spend": 0.84, "max_budget": 2.0}}))
    return generate, delete, update


@respx.mock
async def test_timed_approval_mints_a_key_with_the_lease_shape(db, agent, gateway):
    generate, _, _ = mock_gateway()
    req = await approvals.create(db, agent, "s1", ["llm/litellm/model/claude-sonnet-5"], "write code")
    await approvals.decide(db, req.id, "ttl30", via="ui")
    assert generate.called
    body = json.loads(generate.calls.last.request.content)
    assert body["models"] == ["claude-sonnet-5"]
    assert body["user_id"] == f"kw-{agent.id}" and body["max_budget"] == 2.0 and body["rpm_limit"] == 30
    assert body["max_parallel_requests"] == 4 and "tpm_limit" not in body
    assert body["duration"].endswith("s") and 1700 <= int(body["duration"][:-1]) <= 1800
    assert body["metadata"]["keywright"]["request_id"] == req.id
    # the user carrying the per-agent window was created with that budget
    user_body = json.loads(respx.calls[[c.request.url.path for c in respx.calls].index("/user/new")].request.content)
    assert user_body["max_budget"] == 10.0 and user_body["budget_duration"] == "1d"
    key = (await db.execute(select(LlmKey))).scalar_one()
    grant = (await db.execute(select(Grant).where(Grant.request_id == req.id))).scalar_one()
    assert key.key == "sk-virtual-1" and key.grant_ids == [grant.id] and key.expires_at == grant.expires_at
    assert key.models == ["claude-sonnet-5"] and key.is_active(grant.expires_at.replace(year=2000))
    # the secret never reaches the audit log
    rows = (await db.execute(select(AuditEvent).where(AuditEvent.tool == "llm.key"))).scalars().all()
    assert rows and rows[0].decision == "minted" and "sk-virtual" not in json.dumps(rows[0].detail)
    # and the lease is what policy sees
    assert (await policy.evaluate(db, agent, "s1", ["llm/litellm/model/claude-sonnet-5"], consume=False)).allowed


@respx.mock
async def test_wildcard_pattern_covers_every_model_and_slashes_are_segments(db, agent, gateway):
    generate, _, _ = mock_gateway(user_exists=True)
    req = await approvals.create(db, agent, None, ["llm/litellm/model/*"], "anything")
    await approvals.decide(db, req.id, "ttl", via="ui")
    body = json.loads(generate.calls.last.request.content)
    assert body["models"] == ["claude-sonnet-5", "gpt-5.6", "openrouter/x/video"]
    assert respx.calls[[c.request.url.path for c in respx.calls].index("/user/update")]
    req2 = await approvals.create(db, agent, None, ["llm/litellm/model/openrouter_x_video"], "one")
    await approvals.decide(db, req2.id, "ttl15", via="ui")
    assert json.loads(generate.calls.last.request.content)["models"] == ["openrouter/x/video"]


@respx.mock
async def test_no_database_means_no_key_and_the_request_stays_pending(db, agent, gateway):
    generate, _, _ = mock_gateway(db="Not connected")
    req = await approvals.create(db, agent, None, ["llm/litellm/model/gpt-5.6"], "x")
    with pytest.raises(ValueError, match="database"):
        await approvals.decide(db, req.id, "ttl30", via="ui")
    assert not generate.called
    await db.refresh(req)
    assert req.status == "pending"
    assert (await db.execute(select(Grant))).scalars().all() == []
    assert (await policy.evaluate(db, agent, None, ["llm/litellm/model/gpt-5.6"], consume=False)).status == "pending"


@respx.mock
async def test_gateway_refusal_rolls_the_approval_back(db, agent, gateway):
    generate, _, _ = mock_gateway()
    generate.mock(return_value=httpx.Response(500, json={"error": {"message": "DB not connected"}}))
    req = await approvals.create(db, agent, None, ["llm/litellm/model/gpt-5.6"], "x")
    with pytest.raises(ValueError, match="HTTP 500"):
        await approvals.decide(db, req.id, "ttl30", via="ui")
    await db.refresh(req)
    assert req.status == "pending" and (await db.execute(select(LlmKey))).scalars().all() == []


@respx.mock
async def test_unreachable_gateway_is_a_refusal_not_a_crash(db, agent, gateway):
    respx.get(f"{GW}/health/readiness").mock(side_effect=httpx.ConnectError("boom"))
    req = await approvals.create(db, agent, None, ["llm/litellm/model/gpt-5.6"], "x")
    with pytest.raises(ValueError, match="unreachable"):
        await approvals.decide(db, req.id, "ttl30", via="ui")


async def test_llm_lease_is_always_timed(db, agent, gateway):
    req = await approvals.create(db, agent, None, ["llm/litellm/model/gpt-5.6"], "x")
    assert approvals.offered_scopes(req) == ("ttl15", "ttl30", "ttl", "deny")
    for scope in ("once", "always"):
        with pytest.raises(ValueError, match="timed lease"):
            await approvals.decide(db, req.id, scope, via="ui")
    with_session = await approvals.create(db, agent, "s1", ["llm/litellm/model/gpt-5.6"], "y")
    assert "session" in approvals.offered_scopes(with_session)


@respx.mock
async def test_revoking_the_grant_deletes_the_key(db, agent, gateway):
    _, delete, _ = mock_gateway()
    req = await approvals.create(db, agent, None, ["llm/litellm/model/gpt-5.6"], "x")
    await approvals.decide(db, req.id, "ttl30", via="ui")
    grant = (await db.execute(select(Grant).where(Grant.request_id == req.id))).scalar_one()
    await approvals.revoke_grant(db, grant.id)
    assert json.loads(delete.calls.last.request.content) == {"keys": ["sk-virtual-1"]}
    key = (await db.execute(select(LlmKey))).scalar_one()
    assert key.revoked_at is not None
    assert not (await policy.evaluate(db, agent, None, ["llm/litellm/model/gpt-5.6"], consume=False)).allowed


@respx.mock
async def test_revoking_one_of_two_models_narrows_the_key(db, agent, gateway):
    _, delete, update = mock_gateway()
    req = await approvals.create(db, agent, None, ["llm/litellm/model/gpt-5.6", "llm/litellm/model/claude-sonnet-5"], "x")
    await approvals.decide(db, req.id, "ttl30", via="ui")
    key = (await db.execute(select(LlmKey))).scalar_one()
    assert key.models == ["claude-sonnet-5", "gpt-5.6"]
    gpt = (await db.execute(select(Grant).where(Grant.pattern == "llm/litellm/model/gpt-5.6"))).scalar_one()
    await approvals.revoke_grant(db, gpt.id)
    assert json.loads(update.calls.last.request.content) == {"key": "sk-virtual-1", "models": ["claude-sonnet-5"]}
    assert not delete.called
    await db.refresh(key)
    assert key.revoked_at is None and key.models == ["claude-sonnet-5"]
    await approvals.revoke_request_grants(db, req.id)
    assert delete.called
    await db.refresh(key)
    assert key.revoked_at is not None


@respx.mock
async def test_upstream_delete_failure_is_audited_and_the_key_is_still_dropped_locally(db, agent, gateway):
    _, delete, _ = mock_gateway()
    req = await approvals.create(db, agent, None, ["llm/litellm/model/gpt-5.6"], "x")
    await approvals.decide(db, req.id, "ttl30", via="ui")
    delete.mock(side_effect=httpx.ConnectError("down"))
    grant = (await db.execute(select(Grant).where(Grant.request_id == req.id))).scalar_one()
    await approvals.revoke_grant(db, grant.id)
    key = (await db.execute(select(LlmKey))).scalar_one()
    assert key.revoked_at is not None
    rows = (await db.execute(select(AuditEvent).where(AuditEvent.tool == "llm.key"))).scalars().all()
    assert rows[-1].decision == "revoked_locally_only"


@respx.mock
async def test_probe_refreshes_models_and_reports_the_database(gateway):
    mock_gateway(db="connected")
    ok, msg, health = await llm.probe(gateway.config)
    assert ok and health["models"] == ["claude-sonnet-5", "gpt-5.6"] and health["db"] == "connected"
    mock_gateway(db="Not connected")
    ok, msg, health = await llm.probe(gateway.config)
    assert not ok and "not enforced" in msg and not llm.enforces_budgets(health)


@respx.mock
async def test_exposure_is_what_is_left_to_spend(db, agent, gateway):
    mock_gateway()
    req = await approvals.create(db, agent, None, ["llm/litellm/model/gpt-5.6"], "x")
    await approvals.decide(db, req.id, "ttl30", via="ui")
    keys = await llm.active_keys(db, gateway)
    spend = {k.id: await llm.key_spend(gateway.config, k.key) for k in keys}
    assert spend[keys[0].id] == {"spend": 0.84, "max_budget": 2.0}
    assert llm.exposure(keys, spend) == pytest.approx(1.16)


async def test_discovery_lists_models_limits_and_enforcement(db, agent, gateway):
    entry = next(e for e in await policy.effective_access(db, agent, None) if e["resource"] == "llm/litellm")
    assert entry["models"]["openrouter/x/video"] == "llm/litellm/model/openrouter_x_video"
    assert entry["limits_per_lease"]["max_budget"] == 2.0 and entry["budgets_enforced"] is False


@respx.mock
async def test_the_resource_page_shows_active_leases_and_exposure(live_server, db, agent, gateway):
    from tests.test_live_dashboard import admin_cookie

    mock_gateway()
    respx.route(host="127.0.0.1").pass_through()
    req = await approvals.create(db, agent, None, ["llm/litellm/model/gpt-5.6"], "x")
    await approvals.decide(db, req.id, "ttl30", via="ui")
    cookie = await admin_cookie(live_server)
    async with httpx.AsyncClient(base_url=live_server, headers={"Cookie": f"kw_admin={cookie}"}) as http:
        page = (await http.get(f"/ui/resources/{gateway.id}")).text
    assert "test-agent" in page and "$0.84 / $2.00" in page and "Exposure remaining: $1.16" in page
    assert "sk-virtual-1" not in page and "sk-master" not in page
