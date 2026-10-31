"""The LLM proxy: a Keywright token in, the lease's virtual key out, the body and the stream untouched."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from sqlalchemy import select

from keywright_server import approvals
from keywright_server.models import AuditEvent, LlmKey, Policy, Resource
from tests.test_llm import GW, mock_gateway

TOKEN = {"Authorization": "Bearer gk_testtoken"}


@pytest.fixture
async def gateway(db):
    res = Resource(kind="llm", name="litellm", default_mode="approval", config={
        "url": GW, "master_key": "sk-master", "models": ["claude-sonnet-5", "gpt-5.6"],
        "limits": {"max_budget": 2.0, "rpm_limit": 30, "tpm_limit": None, "max_parallel_requests": 4},
        "agent_budget": {"max_budget": 10.0, "budget_duration": "1d"},
        "health": {"db": "connected"},
    })
    db.add(res)
    await db.commit()
    return res


def mock_upstream(*, stream=False):
    if stream:
        chunks = [b'event: message_start\ndata: {"type":"message_start"}\n\n',
                  b'event: content_block_delta\ndata: {"delta":{"text":"hi"}}\n\n', b"data: [DONE]\n\n"]

        async def body():
            for c in chunks:
                yield c
        return respx.post(f"{GW}/v1/messages").mock(return_value=httpx.Response(
            200, headers={"content-type": "text/event-stream"}, stream=body())), chunks
    return respx.post(f"{GW}/v1/messages").mock(return_value=httpx.Response(
        200, json={"id": "msg_1", "content": [{"type": "text", "text": "hi"}],
                   "usage": {"input_tokens": 12, "output_tokens": 3}})), None


async def lease(db, agent, *patterns):
    req = await approvals.create(db, agent, None, list(patterns), "code")
    await approvals.decide(db, req.id, "ttl30", via="ui")
    return req


async def audit_rows(db, tool="llm.call"):
    return (await db.execute(select(AuditEvent).where(AuditEvent.tool == tool).order_by(AuditEvent.id))).scalars().all()


@respx.mock
async def test_a_leased_model_goes_upstream_with_the_virtual_key(live_server, db, agent, gateway):
    mock_gateway()
    respx.route(host="127.0.0.1").pass_through()
    upstream, _ = mock_upstream()
    await lease(db, agent, "llm/litellm/model/claude-sonnet-5")
    payload = {"model": "claude-sonnet-5", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]}
    async with httpx.AsyncClient(base_url=live_server) as http:
        r = await http.post("/llm/litellm/v1/messages?beta=true", json=payload,
                            headers={**TOKEN, "anthropic-version": "2023-06-01", "X-Keywright-Session": "s1"})
    assert r.status_code == 200 and r.json()["id"] == "msg_1"
    sent = upstream.calls.last.request
    assert sent.headers["authorization"] == "Bearer sk-virtual-1" and sent.headers["anthropic-version"] == "2023-06-01"
    assert "x-keywright-session" not in sent.headers and json.loads(sent.content) == payload
    assert sent.url.params["beta"] == "true"
    rows = await audit_rows(db)
    assert rows[-1].decision == "allow" and rows[-1].patterns == ["llm/litellm/model/claude-sonnet-5"]
    assert rows[-1].detail["usage"] == {"input": 12, "output": 3} and rows[-1].exit_code == 200
    assert rows[-1].detail["standing"] is False and rows[-1].session_id == "s1"
    assert "sk-virtual" not in json.dumps(rows[-1].detail)
    assert rows[-1].detail["resource_id"] == gateway.id
    assert rows[-1].detail["gateway_key_id"].startswith("lkey_")


@respx.mock
async def test_the_stream_passes_through_byte_for_byte(live_server, db, agent, gateway):
    mock_gateway()
    respx.route(host="127.0.0.1").pass_through()
    _, chunks = mock_upstream(stream=True)
    await lease(db, agent, "llm/litellm/model/claude-sonnet-5")
    got = []
    async with httpx.AsyncClient(base_url=live_server) as http, http.stream(
            "POST", "/llm/litellm/v1/messages", json={"model": "claude-sonnet-5", "stream": True},
            headers={**TOKEN}) as r:
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
        async for chunk in r.aiter_raw():
            got.append(chunk)
    assert b"".join(got) == b"".join(chunks)
    rows = await audit_rows(db)
    assert rows[-1].detail["stream"] is True and "usage" not in rows[-1].detail


@respx.mock
async def test_stream_usage_is_recorded_without_changing_response(live_server, db, agent, gateway):
    mock_gateway()
    respx.route(host="127.0.0.1").pass_through()
    raw = (b'data: {"message":{"usage":{"input_tokens":12,"output_tokens":1}}}\n\n'
           b'data: {"usage":{"output_tokens":7}}\n\n'
           b'data: {"usage":{"output_tokens":9}}\n\n')

    async def body():
        for index in range(0, len(raw), 7):
            yield raw[index:index + 7]

    respx.post(f"{GW}/v1/messages").mock(return_value=httpx.Response(
        200, headers={"content-type": "text/event-stream"}, stream=body()))
    await lease(db, agent, "llm/litellm/model/claude-sonnet-5")
    async with httpx.AsyncClient(base_url=live_server) as http:
        r = await http.post("/llm/litellm/v1/messages", headers=TOKEN,
                            json={"model": "claude-sonnet-5", "stream": True})
    assert r.content == raw
    row = (await audit_rows(db))[-1]
    assert row.detail["usage"] == {"input": 12, "output": 9}
    assert row.detail["response_complete"] is True


@respx.mock
async def test_the_anthropic_sdk_header_spelling_works_too(live_server, db, agent, gateway):
    mock_gateway()
    respx.route(host="127.0.0.1").pass_through()
    upstream, _ = mock_upstream()
    await lease(db, agent, "llm/litellm/model/claude-sonnet-5")
    async with httpx.AsyncClient(base_url=live_server) as http:
        r = await http.post("/llm/litellm/v1/messages", json={"model": "claude-sonnet-5"}, headers={"x-api-key": "gk_testtoken"})
    assert r.status_code == 200
    assert "x-api-key" not in upstream.calls.last.request.headers


@respx.mock
async def test_no_token_unknown_gateway_and_unknown_model(live_server, db, agent, gateway):
    respx.route(host="127.0.0.1").pass_through()
    async with httpx.AsyncClient(base_url=live_server) as http:
        r = await http.post("/llm/litellm/v1/messages", json={"model": "gpt-5.6"})
        assert r.status_code == 401 and r.json()["error"]["type"] == "keywright_unauthorized"
        r = await http.post("/llm/nope/v1/messages", json={"model": "gpt-5.6"}, headers=TOKEN)
        assert r.status_code == 404
        r = await http.post("/llm/litellm/v1/messages", json={"model": "gpt-9"}, headers=TOKEN)
        assert r.status_code == 400 and r.json()["error"]["models"] == ["claude-sonnet-5", "gpt-5.6"]
        r = await http.post("/llm/litellm/v1/messages", content=b"not json", headers=TOKEN)
        assert r.status_code == 400 and r.json()["error"]["code"] == "no_model"


@respx.mock
async def test_an_unapproved_model_asks_the_human_and_works_once_approved(live_server, db, agent, gateway):
    mock_gateway()
    respx.route(host="127.0.0.1").pass_through()
    mock_upstream()
    async with httpx.AsyncClient(base_url=live_server, timeout=30) as http:
        r = await http.post("/llm/litellm/v1/messages", json={"model": "gpt-5.6"},
                            headers={**TOKEN, "X-Keywright-Wait": "1", "X-Keywright-Reason": "refactor"})
        assert r.status_code == 403 and r.json()["error"]["code"] == "approval_required"
        rid = r.json()["error"]["request_id"]
        req = await db.get(approvals.AccessRequest, rid)
        assert req.status == "pending" and req.patterns == ["llm/litellm/model/gpt-5.6"] and req.reason == "refactor"
        # the same call again reuses the pending request instead of buzzing the phone twice
        r = await http.post("/llm/litellm/v1/messages", json={"model": "gpt-5.6"}, headers={**TOKEN, "X-Keywright-Wait": "0"})
        assert r.json()["error"]["request_id"] == rid
        await approvals.decide(db, rid, "ttl30", via="ui")
        r = await http.post("/llm/litellm/v1/messages", json={"model": "gpt-5.6"}, headers=TOKEN)
        assert r.status_code == 200
    rows = await audit_rows(db)
    assert [x.decision for x in rows] == ["pending", "pending", "allow"]


@respx.mock
async def test_a_deny_rule_and_a_denied_request_answer_403(live_server, db, agent, gateway):
    mock_gateway()
    respx.route(host="127.0.0.1").pass_through()
    db.add(Policy(pattern="llm/litellm/model/gpt-5.6", effect="deny"))
    await db.commit()
    async with httpx.AsyncClient(base_url=live_server) as http:
        r = await http.post("/llm/litellm/v1/messages", json={"model": "gpt-5.6"}, headers=TOKEN)
        assert r.status_code == 403 and r.json()["error"]["code"] == "denied"
        r = await http.post("/llm/litellm/v1/messages", json={"model": "claude-sonnet-5"},
                            headers={**TOKEN, "X-Keywright-Wait": "0"})
        rid = r.json()["error"]["request_id"]
        await approvals.decide(db, rid, "deny", via="ui", deny_reason="not now")
        r = await http.post("/llm/litellm/v1/messages", json={"model": "claude-sonnet-5"}, headers=TOKEN)
        assert r.status_code == 403 and "Recently denied" in r.json()["error"]["message"]


@respx.mock
async def test_standing_access_mints_one_hourly_key_and_reuses_it(live_server, db, agent, gateway):
    generate, _, _ = mock_gateway()
    respx.route(host="127.0.0.1").pass_through()
    upstream, _ = mock_upstream()
    db.add(Policy(pattern="llm/litellm/model/*", effect="allow", agent_id=agent.id))
    await db.commit()
    async with httpx.AsyncClient(base_url=live_server) as http:
        for model in ("gpt-5.6", "claude-sonnet-5"):
            r = await http.post("/llm/litellm/v1/messages", json={"model": model}, headers=TOKEN)
            assert r.status_code == 200
    assert generate.call_count == 1
    body = json.loads(generate.calls.last.request.content)
    assert sorted(body["models"]) == ["claude-sonnet-5", "gpt-5.6"] and body["max_budget"] == 2.0
    assert 3500 <= int(body["duration"][:-1]) <= 3600 and body["metadata"]["keywright"]["standing"] is True
    key = (await db.execute(select(LlmKey))).scalar_one()
    assert key.grant_ids == [] and upstream.calls.last.request.headers["authorization"] == "Bearer sk-virtual-1"
    rows = await audit_rows(db)
    assert rows[-1].detail["standing"] is True
    # the model list, with no model in the body, rides on the same key
    async with httpx.AsyncClient(base_url=live_server) as http:
        respx.get(f"{GW}/v1/models").mock(return_value=httpx.Response(200, json={"data": [{"id": "gpt-5.6"}]}))
        r = await http.get("/llm/litellm/v1/models", headers=TOKEN)
        assert r.status_code == 200 and r.json()["data"][0]["id"] == "gpt-5.6"


@respx.mock
async def test_standing_access_without_a_database_is_refused(live_server, db, agent, gateway):
    mock_gateway(db="Not connected")
    respx.route(host="127.0.0.1").pass_through()
    db.add(Policy(pattern="llm/litellm/model/*", effect="allow"))
    await db.commit()
    async with httpx.AsyncClient(base_url=live_server) as http:
        r = await http.post("/llm/litellm/v1/messages", json={"model": "gpt-5.6"}, headers=TOKEN)
    assert r.status_code == 503 and "database" in r.json()["error"]["message"]
    assert (await db.execute(select(LlmKey))).scalars().all() == []


@respx.mock
async def test_an_unreachable_gateway_is_a_502_not_a_hang(live_server, db, agent, gateway):
    mock_gateway()
    respx.route(host="127.0.0.1").pass_through()
    respx.post(f"{GW}/v1/messages").mock(side_effect=httpx.ConnectError("down"))
    await lease(db, agent, "llm/litellm/model/gpt-5.6")
    async with httpx.AsyncClient(base_url=live_server) as http:
        r = await http.post("/llm/litellm/v1/messages", json={"model": "gpt-5.6"}, headers=TOKEN)
    assert r.status_code == 502
    assert (await audit_rows(db))[-1].decision == "error"


@respx.mock
async def test_no_lease_means_no_model_list(live_server, db, agent, gateway):
    respx.route(host="127.0.0.1").pass_through()
    async with httpx.AsyncClient(base_url=live_server) as http:
        r = await http.get("/llm/litellm/v1/models", headers=TOKEN)
    assert r.status_code == 403 and r.json()["error"]["code"] == "no_lease"


@respx.mock
async def test_standing_access_lists_models_before_any_call(live_server, db, agent, gateway):
    """Open WebUI asks GET /v1/models first; standing access mints its key on that request."""
    generate, _, _ = mock_gateway()
    respx.route(host="127.0.0.1").pass_through()
    respx.get(f"{GW}/v1/models").mock(return_value=httpx.Response(200, json={"data": [{"id": "gpt-5.6"}]}))
    db.add(Policy(pattern="llm/litellm/model/gpt-5.6", effect="allow", agent_id=agent.id))
    await db.commit()
    async with httpx.AsyncClient(base_url=live_server) as http:
        r = await http.get("/llm/litellm/v1/models", headers=TOKEN)
    assert r.status_code == 200 and r.json()["data"][0]["id"] == "gpt-5.6"
    assert generate.call_count == 1 and json.loads(generate.calls.last.request.content)["models"] == ["gpt-5.6"]
    key = (await db.execute(select(LlmKey))).scalar_one()
    assert key.grant_ids == [] and key.models == ["gpt-5.6"]
