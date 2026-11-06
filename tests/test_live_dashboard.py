"""The live dashboard: the event hub, the websocket that carries it, and the tiles it renders."""

import asyncio
import json
from datetime import timedelta

import httpx
import pytest
import websockets
from starlette.requests import Request

from keywright_server import approvals, events, knowledge, nudges
from keywright_server.models import Agent, Grant, Policy, Resource, now


@pytest.fixture
async def protected(db):
    res = Resource(kind="ssh", name="nvr", default_mode="approval",
                   config={"host": "10.0.0.5", "user": "root"})
    db.add(res)
    await db.commit()
    return res


def operation(res, command="systemctl restart komodo-core"):
    return {"host": res.name, "resource_id": res.id, "command": command, "user": "root"}


async def dashboard_html():
    from keywright_server.web.admin import dashboard

    response = await dashboard(Request({"type": "http", "method": "GET", "path": "/ui",
                                        "headers": [], "scheme": "http", "server": ("test", 80)}))
    return response.body.decode()


async def test_dashboard_shows_only_active_agents_and_their_approved_targets(db, agent, protected):
    idle = Agent(name="idle-agent", token_hash="idle-token-hash", token_prefix="idle")
    db.add(idle)
    db.add(Resource(kind="ssh", name="unrelated-target", default_mode="open", config={}))
    await db.flush()
    db.add(Policy(agent_id=idle.id, pattern="ssh/**", effect="allow"))
    db.add(Grant(agent_id=agent.id, pattern="ssh/nvr/exec/**", scope="ttl",
                 expires_at=now() + timedelta(minutes=30)))
    await db.commit()

    html = await dashboard_html()
    assert f'aria-label="Access for {agent.name}"' in html
    assert 'aria-label="Access for idle-agent"' not in html
    assert "unrelated-target" not in html
    assert "ssh/nvr/exec/**" in html
    assert 'class="access-detail"><summary>Target access details · 1</summary>' in html
    assert f'action="/ui/agents/{agent.id}/disable"' in html
    assert "Revoke approval" in html
    assert "No active approvals." not in html

    agent.disabled_at = now()
    await db.commit()
    html = await dashboard_html()
    assert "Retained approval while suspended" in html
    assert "Suspended · new operations blocked" in html
    assert "Revoke approval" in html


@pytest.mark.parametrize("state", ["none", "expired", "revoked", "spent"])
async def test_dashboard_empty_state_excludes_inactive_approvals(db, agent, protected, state):
    if state != "none":
        db.add(Grant(agent_id=agent.id, pattern="ssh/nvr/exec/**",
                     scope="once" if state == "spent" else "ttl",
                     expires_at=now() + timedelta(minutes=-1 if state == "expired" else 30),
                     revoked_at=now() if state == "revoked" else None,
                     uses_remaining=0 if state == "spent" else None))
    await db.commit()
    html = await dashboard_html()
    assert "No active approvals." in html
    assert 'aria-label="Access for ' not in html
    assert "No agents registered." not in html
    assert "Pending requests" in html and "Recent activity" in html


# ---- the hub ------------------------------------------------------------------------------------
async def test_publishing_with_nobody_watching_is_free():
    events.publish("request.created", id="req_x")  # must not raise or retain anything
    assert events.subscriber_count() == 0


async def test_every_open_dashboard_sees_every_fact():
    async with events.subscribe() as one, events.subscribe() as two:
        events.publish("request.created", id="req_x")
        assert await one.get() == {"type": "request.created", "id": "req_x"}
        assert await two.get() == {"type": "request.created", "id": "req_x"}
    assert events.subscriber_count() == 0


async def test_a_browser_that_stops_draining_is_told_to_resync_not_allowed_to_back_up():
    async with events.subscribe() as sub:
        for i in range(events.QUEUE_MAX + 10):
            events.publish("request.created", id=f"req_{i}")
        assert sub.waiting == 1  # everything it missed collapses into one reload
        assert await sub.get() == events.RESYNC
        events.publish("request.created", id="req_after")
        assert await sub.get() == {"type": "request.created", "id": "req_after"}


async def test_a_slow_dashboard_never_costs_another_one_its_events():
    async with events.subscribe() as slow, events.subscribe() as quick:
        for i in range(events.QUEUE_MAX + 5):
            events.publish("request.created", id=f"req_{i}")
            assert (await quick.get())["id"] == f"req_{i}"
        assert await slow.get() == events.RESYNC


# ---- the approval path publishes ----------------------------------------------------------------
async def test_a_request_and_its_decision_both_reach_the_dashboard(db, agent, protected, log_notifier):
    async with events.subscribe() as q:
        req = await approvals.create(db, agent, "s1", ["ssh/nvr/exec/systemctl"], "restart",
                                     operation(protected))
        assert await q.get() == {"type": "request.created", "id": req.id}
        await approvals.decide(db, req.id, "once", via="homeassistant")
        decided = await q.get()
    assert decided == {"type": "request.decided", "id": req.id, "status": "approved",
                       "via": "homeassistant", "label": "Allow once"}


async def test_an_expiring_request_resolves_on_the_dashboard(db, agent, protected, log_notifier):
    req = await approvals.create(db, agent, None, ["ssh/nvr/exec/systemctl"], "restart", operation(protected))
    req.expires_at = approvals.now()
    await db.commit()
    async with events.subscribe() as q:
        assert await approvals.expire_stale(db) == 1
        assert await q.get() == {"type": "request.decided", "id": req.id, "status": "expired"}


async def test_nudges_arrive_and_clear(db, agent, log_notifier):
    async with events.subscribe() as q:
        ping = await nudges.create(db, agent, None, "which one?")
        assert await q.get() == {"type": "nudge.created", "id": ping.nudge.id}
        await nudges.clear(db, ping.nudge.id, via="ui")
        assert await q.get() == {"type": "nudge.cleared", "id": ping.nudge.id}


# ---- the websocket ------------------------------------------------------------------------------
def ws_url(base: str) -> str:
    return base.replace("http://", "ws://") + "/ui/events"


async def admin_cookie(base: str) -> str:
    async with httpx.AsyncClient(base_url=base, headers={"Origin": base}) as http:
        r = await http.post("/ui/login", data={"password": "adminpass123"}, follow_redirects=False)
        return r.cookies["kw_admin"]


async def open_dashboard(base: str, *, cookie: str | None = None, origin: str | None = ...):
    headers = {}
    if cookie:
        headers["Cookie"] = f"kw_admin={cookie}"
    if origin is ...:
        origin = base
    if origin:
        headers["Origin"] = origin
    return await websockets.connect(ws_url(base), additional_headers=headers, open_timeout=10)


async def test_the_dashboard_socket_needs_the_admin_cookie(live_server):
    with pytest.raises(websockets.InvalidStatus) as rejected:
        await open_dashboard(live_server)
    assert rejected.value.response.status_code == 403


async def test_the_dashboard_socket_refuses_another_origin(live_server):
    """It carries the admin cookie like any same-site request, so a missing or foreign Origin on the
    handshake is the only thing standing between another page and a live read of this one."""
    cookie = await admin_cookie(live_server)
    for origin in ("https://evil.invalid", "null", None):
        with pytest.raises(websockets.InvalidStatus) as rejected:
            await open_dashboard(live_server, cookie=cookie, origin=origin)
        assert rejected.value.response.status_code == 403


async def test_a_request_made_after_the_page_loaded_arrives_as_a_tile(live_server, db, agent, protected,
                                                                     log_notifier):
    cookie = await admin_cookie(live_server)
    async with await open_dashboard(live_server, cookie=cookie) as ws:
        hello = json.loads(await asyncio.wait_for(ws.recv(), 10))
        assert hello["type"] == "hello" and hello["counts"]["pending"] == 0
        req = await approvals.create(db, agent, "s1", ["ssh/nvr/exec/systemctl"], "restart",
                                     operation(protected))
        event = json.loads(await asyncio.wait_for(ws.recv(), 10))
        assert event["type"] == "request.created" and event["id"] == req.id
        assert event["counts"]["pending"] == 1
        # The tile carries what the human decides on, and the buttons to decide it.
        assert agent.name in event["html"]
        assert "systemctl restart komodo-core" in event["html"]
        assert f'action="/ui/requests/{req.id}/decide"' in event["html"]

        await approvals.decide(db, req.id, "once", via="homeassistant")
        decided = json.loads(await asyncio.wait_for(ws.recv(), 10))
        assert decided["type"] == "request.decided" and decided["status"] == "approved"
        assert decided["via"] == "homeassistant" and decided["counts"]["pending"] == 0
        assert decided["counts"]["leases"] == 1


async def test_a_nudge_arrives_as_a_card_and_the_resync_matches(live_server, db, agent, log_notifier):
    cookie = await admin_cookie(live_server)
    async with await open_dashboard(live_server, cookie=cookie) as ws:
        await asyncio.wait_for(ws.recv(), 10)  # hello
        ping = await nudges.create(db, agent, "claude:abc", "Which cert path do you want?", "ai-vm:~/p")
        event = json.loads(await asyncio.wait_for(ws.recv(), 10))
        assert event["type"] == "nudge.created" and event["counts"]["nudges"] == 1
        assert "Which cert path do you want?" in event["html"]
        assert "needs you" in event["html"] and "ai-vm:~/p" in event["html"]

    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as http:
        await http.post("/ui/login", data={"password": "adminpass123"})
        state = (await http.get("/ui/live")).json()
        assert state["type"] == "resync" and state["counts"]["nudges"] == 1
        assert "Which cert path do you want?" in state["html"]
        r = await http.post(f"/ui/nudges/{ping.nudge.id}/dismiss", follow_redirects=False)
        assert r.status_code == 303
        assert (await http.get("/ui/live")).json()["counts"]["nudges"] == 0


@pytest.mark.parametrize("action,status", [("approve", "published"), ("reject", "rejected")])
async def test_knowledge_proposals_arrive_and_resolve_on_dashboard(live_server, db, agent, action, status):
    from keywright_server.mcp_server import _proxy_call

    collection = await knowledge.create_collection(db, "SharedKnowledge")
    collection.default_mode = "open"
    await db.commit()
    cookie = await admin_cookie(live_server)
    async with await open_dashboard(live_server, cookie=cookie) as ws:
        assert json.loads(await asyncio.wait_for(ws.recv(), 10))["counts"]["pending"] == 0
        result = await _proxy_call(db, agent, None, collection.name, "knowledge_propose", {
            "path": "lesson.md", "title": "A <script>lesson</script>", "body": "Full proposed content",
            "rationale": "Useful <b>discovery</b>", "_wait_seconds": 0,
        })
        revision_id = result.structured_content["proposal_id"]
        update = json.loads(await asyncio.wait_for(ws.recv(), 10))
        assert update["type"] == "knowledge.proposed" and update["id"] == revision_id
        assert update["counts"]["pending"] == 1 and update["counts"]["leases"] == 0
        assert agent.name in update["html"] and "SharedKnowledge / lesson.md" in update["html"]
        assert "&lt;script&gt;lesson&lt;/script&gt;" in update["html"]
        assert "&lt;b&gt;discovery&lt;/b&gt;" in update["html"]
        assert "Full proposed content" not in update["html"]
        review_url = f"/ui/knowledge/proposals/{revision_id}?next=/ui"
        assert f'href="{review_url}"' in update["html"]
        async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server},
                                     cookies={"kw_admin": cookie}) as http:
            html = (await http.get("/ui")).text
            assert f'id="proposal-{revision_id}"' in html and 'data-count="pending">1<' in html
            assert 'id="pending-empty" hidden' in html
            state = (await http.get("/ui/live")).json()
            assert state["counts"]["pending"] == 1 and f'id="proposal-{revision_id}"' in state["html"]
            review_page = await http.get(review_url)
            assert "Full proposed content" in review_page.text
            assert 'name="next" value="/ui"' in review_page.text
            rejected = await http.post(review_url, data={"action": action, "next": "/ui"},
                                       headers={"Origin": "https://evil.invalid"})
            assert rejected.status_code == 403
            response = await http.post(review_url, data={"action": action, "next": "/ui"})
            assert response.status_code == 303 and response.headers["location"] == "/ui"
            decision = json.loads(await asyncio.wait_for(ws.recv(), 10))
            assert decision["type"] == "knowledge.reviewed" and decision["id"] == revision_id
            assert decision["status"] == status and decision["counts"]["pending"] == 0
            state = (await http.get("/ui/live")).json()
            assert f'id="proposal-{revision_id}"' not in state["html"]
            assert state["counts"]["pending"] == 0


async def test_pending_count_includes_access_and_knowledge_and_ignores_resolved(db, agent, protected, log_notifier):
    from keywright_server.web.admin import _counts, _live_payload, _waiting

    collection = await knowledge.create_collection(db, "SharedKnowledge")
    proposal = await knowledge.propose(db, collection.id, path="a.md", title="Pending", body="Content")
    published = await knowledge.propose(db, collection.id, path="b.md", title="Published", body="Content")
    await knowledge.review(db, published.id, True)
    rejected = await knowledge.propose(db, collection.id, path="c.md", title="Rejected", body="Content")
    await knowledge.review(db, rejected.id, False)
    await db.commit()
    await approvals.create(db, agent, None, ["ssh/nvr/exec/uptime"], "check", operation(protected, "uptime"))
    assert (await _counts(db))["pending"] == 2
    waiting = await _waiting(db)
    assert len(waiting["pending"]) == 1
    assert [p["revision"].id for p in waiting["proposals"]] == [proposal.id]
    assert await _live_payload(db, {"type": "knowledge.proposed", "id": published.id}) is None
    assert await _live_payload(db, {"type": "knowledge.proposed", "id": "missing"}) is None
