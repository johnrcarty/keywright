from datetime import timedelta

import httpx
import pytest
from starlette.requests import Request

from keywright_server.llm_usage import UsageObserver
from keywright_server.models import AuditEvent, LlmKey, Resource, now
from keywright_server.usage import report, token_counts
from keywright_server.web.usage_ui import usage_page


def event(gateway="litellm", model="shared-model", alias="key-one", **kwargs):
    detail = {"gateway": gateway, "model": model, "key_alias": alias,
              "usage": {"prompt": 10, "completion": 5, "total": 15}, **kwargs.pop("detail", {})}
    return AuditEvent(tool="llm.call", decision=kwargs.pop("decision", "allow"),
                      agent_name="writer", agent_id="agent-one", detail=detail, **kwargs)


async def snapshot(db, **filters):
    return await report(db, now() - timedelta(days=30), now() + timedelta(minutes=1), **filters)


async def test_provider_model_key_rollups_filters_and_coverage(db):
    db.add_all([
        event(), event(gateway="openrouter"), event(alias="key-two", model="other-model"),
        event(detail={"usage": None}),
        event(decision="error", detail={"usage": {"input": 4}, "response_complete": False}),
        event(decision="deny"), event(decision="pending"), event(model=None),
        event(decision="error", alias="", detail={"usage": None}),
        event(ts=now() - timedelta(days=31)),
    ])
    await db.commit()
    data = await snapshot(db)
    assert data["totals"].requests == 5
    assert data["totals"].total == 49
    assert data["totals"].unreported == 1 and data["totals"].partial == 1
    assert data["totals"].errors == 1
    assert len(data["providers"]) == 2 and len(data["keys"]) == 3
    assert dict(data["models"])["shared-model"].total == 34
    scoped = await snapshot(db, provider="legacy:openrouter", model="shared-model")
    assert scoped["totals"].requests == 1 and scoped["totals"].total == 15
    focused = await snapshot(db, key=scoped["keys"][0]["id"])
    assert focused["totals"].requests == 1
    assert (await snapshot(db, agent="missing"))["totals"].requests == 0


async def test_legacy_rows_join_stable_ids_and_revoked_keys_keep_history(db, agent):
    res = Resource(kind="llm", name="litellm", config={})
    db.add(res)
    await db.flush()
    key = LlmKey(resource_id=res.id, agent_id=agent.id, key="sk-do-not-display",
                 key_alias="same-alias", revoked_at=now())
    db.add(key)
    await db.flush()
    old = event(alias=key.key_alias)
    old.agent_id = agent.id
    new = event(alias=key.key_alias, detail={"resource_id": res.id, "gateway_key_id": key.id})
    new.agent_id = agent.id
    db.add_all([old, new])
    await db.commit()
    data = await snapshot(db)
    assert len(data["keys"]) == 1 and data["keys"][0]["totals"].requests == 2
    assert data["providers"][0]["id"] == res.id
    assert "sk-do-not-display" not in str(data)
    # Same alias, distinct newly issued key IDs must never merge.
    db.add(event(alias=key.key_alias, detail={"resource_id": res.id, "gateway_key_id": "new-id"}))
    await db.commit()
    assert len((await snapshot(db))["keys"]) == 2


async def test_totals_are_not_limited_to_recent_calls_and_dates_are_exclusive(db):
    start = now() - timedelta(days=1)
    end = now()
    db.add_all([event(ts=start) for _ in range(1001)] + [event(ts=end)])
    await db.commit()
    data = await report(db, start, end)
    assert data["totals"].requests == 1001 and len(data["recent"]) == 50
    assert data["totals"].total == 15015


@pytest.mark.parametrize(("usage", "expected"), [
    ({"input": 10, "output": 3, "cache_read_input": 20, "cache_creation_input": 5}, (35, 3, 38)),
    ({"prompt": 10, "completion": 3, "total": 13, "prompt_details": {"cached": 5}}, (10, 3, 13)),
    ({"input": 10, "output": 3, "input_details": {"cached": 5}}, (10, 3, 13)),
    ({"input": 0, "output": 0}, (0, 0, 0)),
    ({"input": -1, "output": True, "total": "100"}, (None, None, None)),
    ({"cost": 2}, (None, None, None)),
])
def test_token_normalization(usage, expected):
    assert token_counts(usage) == expected


@pytest.mark.parametrize("chunk_size", [1, 7, 100000])
def test_stream_usage_handles_split_events_and_cumulative_counts(chunk_size):
    raw = (b'event: message_start\r\ndata: {"message":{"usage":{"input_tokens":12,"output_tokens":1}}}\r\n\r\n'
           b'data: {"usage":{"output_tokens":3}}\n\n'
           b'data: {"usage":{"output_tokens":8}}\n\n'
           b'data: [DONE]\n\n')
    observer = UsageObserver(True)
    for index in range(0, len(raw), chunk_size):
        observer.feed(raw[index:index + chunk_size])
    observer.finish()
    assert observer.usage == {"input": 12, "output": 8}


def test_openai_usage_response_usage_and_error_events():
    observer = UsageObserver(True)
    observer.feed(b'data: {"usage":null}\n\ndata: {"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}\n\n')
    assert observer.usage == {"prompt": 4, "completion": 2, "total": 6}
    observer = UsageObserver(True)
    observer.feed(b'data: {"type":"response.completed","response":{"usage":{"input_tokens":9,"output_tokens":3}}}\n\n')
    assert observer.usage == {"input": 9, "output": 3}
    observer.feed(b'data: {"type":"error","error":{"message":"failed"}}\n\n')
    assert observer.failed


def test_malformed_numeric_usage_never_breaks_the_relay():
    observer = UsageObserver(False)
    observer.feed(b'{"usage":{"input_tokens":' + b'9' * 400 + b',"output_tokens":NaN}}')
    observer.finish()
    assert observer.usage["input"] == int('9' * 400)
    assert "output" not in observer.usage


def test_observer_drops_large_events_and_recovers_without_retaining_content():
    observer = UsageObserver(True)
    observer.LIMIT = 100
    observer.feed(b'data: {"text":"' + b"x" * 500)
    observer.feed(b'"}\n\ndata: {"usage":{"output_tokens":2}}\n\n')
    assert observer.usage == {"output": 2}
    assert len(observer.buffer) <= 100
    observer = UsageObserver(False)
    observer.LIMIT = 100
    observer.feed(b"x" * 101)
    observer.finish()
    assert not observer.usage and not observer.buffer


async def test_usage_page_escapes_labels_and_handles_empty_invalid_filters(db):
    db.add(event(gateway="<script>alert(1)</script>"))
    await db.commit()
    request = Request({"type": "http", "method": "GET", "path": "/ui/usage", "headers": [],
                       "scheme": "http", "server": ("test", 80)})
    page = await usage_page(request)
    html = page.body.decode()
    assert "Keys driving usage" in html and "&lt;script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    page = await usage_page(request, start="bad", provider="unavailable")
    assert "Choose valid dates" in page.body.decode()
    assert "No usage in this selection" in page.body.decode()
    assert "no usage in this period" in page.body.decode()


async def test_usage_requires_admin_and_renders_after_login(live_server):
    async with httpx.AsyncClient(base_url=live_server) as client:
        response = await client.get("/ui/usage")
        assert response.status_code == 303 and "/ui/login" in response.headers["location"]
        await client.post("/ui/login", data={"password": "adminpass123"}, headers={"Origin": live_server})
        response = await client.get("/ui/usage")
        assert response.status_code == 200 and "LLM usage" in response.text
