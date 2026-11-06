import httpx
import pytest
import respx

from keywright_server.models import AccessRequest, Agent, now
from keywright_server.notify.homeassistant import HomeAssistantNotifier

BASE = "http://ha.test:8123"


@pytest.fixture
def ha():
    return HomeAssistantNotifier({"base_url": BASE, "token": "tok", "targets": ["mobile_app_phone"]})


@respx.mock
async def test_probe_discovers_notify_services(ha):
    respx.get(f"{BASE}/api/config").mock(return_value=httpx.Response(200, json={"location_name": "Home", "version": "2026.9"}))
    respx.get(f"{BASE}/api/services").mock(return_value=httpx.Response(200, json=[
        {"domain": "light", "services": {"turn_on": {}}},
        {"domain": "notify", "services": {"mobile_app_phone": {"name": "Send a notification via mobile_app_phone"},
                                          "persistent_notification": {}, "send_message": {}, "notify": {"name": "Send a notification"}}},
    ]))
    r = await ha.probe()
    assert r.ok and "Home" in r.message
    ids = [t[0] for t in r.choices["targets"]]
    assert ids == ["mobile_app_phone", "notify"]
    assert "(companion app)" in dict(r.choices["targets"])["mobile_app_phone"]


@respx.mock
async def test_probe_bad_token(ha):
    respx.get(f"{BASE}/api/config").mock(return_value=httpx.Response(401))
    r = await ha.probe()
    assert not r.ok and "401" in r.message


async def test_probe_missing_config():
    r = await HomeAssistantNotifier({}).probe()
    assert not r.ok


@respx.mock
async def test_send_builds_actionable_notification(ha, _data_dir):
    route = respx.post(f"{BASE}/api/services/notify/mobile_app_phone").mock(return_value=httpx.Response(200, json=[]))
    agent = Agent(id="agt_1", name="astra", token_hash="x")
    req = AccessRequest(id="req_1", agent_id="agt_1", patterns=["ssh/nvr/exec/docker/ps"], reason="look",
                        detail={"command": "docker ps"}, created_at=now())
    await ha.send(req, agent, {"once": "http://gk.test/d/abc"}, ["once", "session", "deny"])
    assert route.called
    body = route.calls.last.request.read().decode()
    import json

    payload = json.loads(body)
    assert payload["title"] == "Keywright: astra"
    assert "docker ps" in payload["message"]
    acts = payload["data"]["actions"]
    assert [a["title"] for a in acts] == ["Allow once", "This session", "Deny"]
    assert payload["data"]["persistent"] is True and payload["data"]["sticky"] is True
    assert payload["data"]["presentation_options"] == ["alert", "sound", "badge"]
    assert "push" not in payload["data"]
    from keywright_server.approvals import parse_notification_action
    assert [parse_notification_action(a["action"]) for a in acts] == [
        ("req_1", "once"), ("req_1", "session"), ("req_1", "deny")]
    assert all(len(a["action"]) < 80 for a in acts)
    assert acts[2]["destructive"] is True
    assert payload["data"]["tag"] == "req_1"
    assert payload["data"]["url"].endswith("/ui/requests/req_1")


async def test_send_without_targets_raises():
    n = HomeAssistantNotifier({"base_url": BASE, "token": "t", "targets": []})
    with pytest.raises(RuntimeError):
        await n.send(None, None, {}, [])


@respx.mock
async def test_deny_is_retained_when_more_than_three_buttons_selected(ha, _data_dir):
    from keywright_server.approvals import parse_notification_action
    route = respx.post(f"{BASE}/api/services/notify/mobile_app_phone").mock(return_value=httpx.Response(200, json=[]))
    agent = Agent(id="agt_1", name="agent", token_hash="x")
    req = AccessRequest(id="req_1", agent_id=agent.id, patterns=["ssh/box/exec/ls"], reason="inspect",
                        detail={}, created_at=now())
    await ha.send(req, agent, {"once": "http://gk.test/d/abc"}, ["once", "ttl15", "ttl30", "ttl", "deny"])
    import json

    actions = json.loads(route.calls.last.request.read())["data"]["actions"]
    assert [parse_notification_action(a["action"])[1] for a in actions] == ["once", "ttl15", "deny"]


async def test_manager_accepts_signed_short_and_legacy_actions(db, agent, log_notifier):
    from keywright_server import approvals
    from keywright_server.models import Resource

    db.add(Resource(kind="ssh", name="box", default_mode="approval", config={"host": "127.0.0.1"}))
    await db.commit()
    r1 = await approvals.create(db, agent, None, ["ssh/box/exec/ls"], "t1")
    await log_notifier.on_decision_token(approvals.notification_action(r1.id, "once"))
    await db.refresh(r1)
    assert r1.status == "approved" and r1.decision_scope == "once"
    r2 = await approvals.create(db, agent, None, ["ssh/box/exec/df"], "t2")
    await log_notifier.on_decision_token("GK:" + approvals.decision_token(r2.id, "deny"))
    await db.refresh(r2)
    assert r2.status == "denied"
    await log_notifier.on_decision_token("KW_BOGUS_nope")  # ignored, no exception
    await log_notifier.on_decision_token("LOCK")


async def test_manager_hides_session_button_when_request_has_no_session(db, agent, log_notifier, monkeypatch):
    from keywright_server import approvals

    seen = []

    async def capture(req, agent, links, buttons):
        seen.append((sorted(links), buttons))
    monkeypatch.setattr(log_notifier.active, "send", capture)
    no_sid = await approvals.create(db, agent, None, ["ssh/nvr/exec/ls"], "x")
    with_sid = await approvals.create(db, agent, "s1", ["ssh/nvr/exec/ls"], "x")
    await log_notifier.notify_request(no_sid, agent)
    await log_notifier.notify_request(with_sid, agent)
    assert seen[0] == (["deny", "once", "ttl", "ttl15", "ttl30"], ["once", "deny"])
    assert seen[1] == (["deny", "once", "session", "ttl", "ttl15", "ttl30"], ["once", "session", "deny"])


@respx.mock
async def test_buttons_without_deny_use_every_slot(ha, _data_dir):
    from keywright_server.approvals import parse_notification_action
    route = respx.post(f"{BASE}/api/services/notify/mobile_app_phone").mock(return_value=httpx.Response(200, json=[]))
    agent = Agent(id="agt_1", name="agent", token_hash="x")
    req = AccessRequest(id="req_1", agent_id=agent.id, patterns=["ssh/box/exec/ls"], reason="inspect",
                        detail={}, created_at=now())
    await ha.send(req, agent, {"once": "http://gk.test/d/abc"}, ["once", "ttl15", "ttl30", "ttl"])
    import json

    actions = json.loads(route.calls.last.request.read())["data"]["actions"]
    assert [parse_notification_action(a["action"])[1] for a in actions] == ["once", "ttl15", "ttl30"]


@respx.mock
async def test_ntfy_never_gets_more_than_three_actions(_data_dir):
    from keywright_server.notify.webhook import WebhookNotifier
    route = respx.post("http://ntfy.test/gk").mock(return_value=httpx.Response(200))
    agent = Agent(id="agt_1", name="agent", token_hash="x")
    req = AccessRequest(id="req_1", agent_id=agent.id, patterns=["ssh/box/exec/ls"], reason="inspect",
                        detail={}, created_at=now())
    scopes = ["once", "session", "ttl15", "ttl30", "ttl", "deny"]
    links = {s: f"http://gk.test/d/{s}" for s in scopes}
    await WebhookNotifier({"url": "http://ntfy.test/gk", "format": "ntfy"}).send(req, agent, links, scopes)
    actions = route.calls.last.request.headers["Actions"].split(", view, ")
    assert len(actions) == 3 and actions[-1].startswith("Deny, ")


@respx.mock
async def test_time_sensitive_adds_sound(_data_dir):
    ha = HomeAssistantNotifier({"base_url": BASE, "token": "tok", "targets": ["mobile_app_phone"], "critical": True})
    route = respx.post(f"{BASE}/api/services/notify/mobile_app_phone").mock(return_value=httpx.Response(200, json=[]))
    agent = Agent(id="agt_1", name="astra", token_hash="x")
    req = AccessRequest(id="req_2", agent_id="agt_1", patterns=["ssh/nvr/exec/uptime"], reason="x",
                        detail={"command": "uptime"}, created_at=now())
    await ha.send(req, agent, {"once": "http://gk.test/d/abc"}, ["once", "deny"])
    import json

    data = json.loads(route.calls.last.request.read().decode())["data"]
    assert data["push"] == {"interruption-level": "time-sensitive", "sound": "default"}
    assert data["priority"] == "high" and data["ttl"] == 0


async def test_expiry_clears_the_phone_notification(db, agent, monkeypatch):
    from datetime import timedelta

    from keywright_server import approvals
    from keywright_server.models import Resource
    from keywright_server.notify.manager import manager

    db.add(Resource(kind="ssh", name="nvr", default_mode="approval", config={"host": "x", "user": "root"}))
    await db.commit()
    req = await approvals.create(db, agent, None, ["ssh/nvr/exec/uptime"], "x", {"command": "uptime"})
    req.expires_at = now() - timedelta(seconds=1)
    await db.commit()
    cleared = []

    async def record(r):
        cleared.append(r.id)

    monkeypatch.setattr(manager, "request_decided", record)
    assert await approvals.expire_stale(db) == 1
    await db.refresh(req)
    assert req.status == "expired" and cleared == [req.id]


@respx.mock
async def test_nudge_is_a_dismissible_push_not_a_decision(ha, _data_dir):
    import json

    from keywright_server.models import Nudge
    from keywright_server.nudges import parse_dismiss_action

    route = respx.post(f"{BASE}/api/services/notify/mobile_app_phone").mock(return_value=httpx.Response(200, json=[]))
    agent = Agent(id="agt_1", name="astra", token_hash="x")
    nudge = Nudge(id="ndg_1", agent_id="agt_1", message="Which cert path?", context="ai-vm:~/p",
                  session_id="claude:abc", created_at=now())
    await ha.send_nudge(nudge, agent, "http://gk.test/ui")
    payload = json.loads(route.calls.last.request.read().decode())
    assert payload["title"] == "Keywright: astra needs you"
    assert "Which cert path?" in payload["message"] and "ai-vm:~/p" in payload["message"]
    acts = payload["data"]["actions"]
    assert [a["title"] for a in acts] == ["Dismiss"]
    assert parse_dismiss_action(acts[0]["action"]) == "ndg_1"
    assert payload["data"]["tag"] == "ndg_1" and payload["data"]["clickAction"] == "http://gk.test/ui"
    # A question is not an emergency: it never claims the time-sensitive channel approvals use.
    assert "push" not in payload["data"]


@respx.mock
async def test_clearing_a_nudge_retracts_it_from_the_phone(ha, _data_dir):
    import json

    from keywright_server.models import Nudge

    route = respx.post(f"{BASE}/api/services/notify/mobile_app_phone").mock(return_value=httpx.Response(200, json=[]))
    await ha.clear_nudge(Nudge(id="ndg_1", agent_id="agt_1", message="x", created_at=now()))
    payload = json.loads(route.calls.last.request.read().decode())
    assert payload == {"message": "clear_notification", "data": {"tag": "ndg_1"}}


@respx.mock
async def test_shopping_notification_opens_broker_without_allow_once(ha, _data_dir, monkeypatch):
    import json

    from keywright_server import approvals

    monkeypatch.setattr(approvals, 'public_url', lambda: 'https://broker.test/keywright')
    route = respx.post(f'{BASE}/api/services/notify/mobile_app_phone').respond(200, json=[])
    agent = Agent(id='agt_shop', name='shopper', token_hash='x')
    req = AccessRequest(id='req_shop', agent_id=agent.id, session_id='s1', patterns=[], reason='Browse',
                        detail={'shopping_session': True}, created_at=now())
    scopes = approvals.offered_scopes(req)
    assert set(scopes) == {'shopping20', 'deny'}
    links = approvals.decision_links(req.id, scopes)
    assert 'once' not in links
    await ha.send(req, agent, links, list(scopes))
    data = json.loads(route.calls.last.request.read())['data']
    assert data['url'] == data['clickAction'] == 'https://broker.test/keywright/ui/requests/req_shop'
    assert {approvals.parse_notification_action(a['action'])[1] for a in data['actions']} == set(scopes)
