import json

import httpx
import pytest
import respx
from sqlalchemy import select

from keywright_server import approvals, mcp_proxy, omada
from keywright_server.mcp_server import _proxy_call
from keywright_server.models import AuditEvent, Policy, Resource

CONFIG = {"adapter": "omada", "url": "https://omada.test:8043", "omada_id": "controller-1",
          "client_id": "client-1", "client_secret": "never-show-this-secret", "verify_tls": True}
TOKEN_URL = CONFIG["url"] + "/openapi/authorize/token"
BASE = CONFIG["url"] + "/openapi/v1/controller-1"


@pytest.fixture(autouse=True)
def clear_tokens():
    omada._tokens.clear()
    yield
    omada._tokens.clear()


def token_response(token="AT-private", expires=7200):
    return httpx.Response(200, json={"errorCode": 0, "result": {"accessToken": token, "expiresIn": expires}})


def data_response(data=None):
    return httpx.Response(200, json={"errorCode": 0, "result": data or {"data": [], "totalRows": 0}})


@respx.mock
async def test_token_protocol_reuse_and_paginated_routes():
    auth = respx.post(TOKEN_URL, params={"grant_type": "client_credentials"}).mock(return_value=token_response())
    for tool, path, args in [
        ("omada_list_sites", "/sites", {}),
        ("omada_list_devices", "/sites/site-1/devices", {"site_id": "site-1"}),
        ("omada_list_clients", "/sites/site-1/clients", {"site_id": "site-1"}),
    ]:
        endpoint = respx.get(BASE + path, params={"page": 2, "pageSize": 25}).mock(
            return_value=data_response({"data": [{"name": "router"}], "totalRows": 26}))
        result = await mcp_proxy.call_tool(CONFIG, tool, {**args, "page": 2, "page_size": 25})
        assert not result.is_error and json.loads(result.content[0].text)["totalRows"] == 26
        assert endpoint.calls.last.request.headers["Authorization"] == "AccessToken=AT-private"
    assert auth.call_count == 1
    assert json.loads(auth.calls.last.request.content) == {
        "omadacId": "controller-1", "client_id": "client-1", "client_secret": CONFIG["client_secret"]}
    tools = await mcp_proxy.list_tools("router", CONFIG)
    assert {t.name for t in tools} == set(omada.OPERATIONS)
    assert all(t.annotations.read_only_hint for t in tools)


@respx.mock
async def test_expiry_rotation_and_401_reauthenticate_once(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(omada.time, "monotonic", lambda: clock[0])
    auth = respx.post(TOKEN_URL).mock(side_effect=[token_response("AT-one"), token_response("AT-two"),
                                                 token_response("AT-three"), token_response("AT-four")])
    endpoint = respx.get(BASE + "/sites").mock(return_value=data_response())
    await omada.request(CONFIG, "omada_list_sites", {})
    clock[0] += 7200
    await omada.request(CONFIG, "omada_list_sites", {})
    assert auth.call_count == 2
    await omada.request({**CONFIG, "client_secret": "rotated"}, "omada_list_sites", {})
    assert auth.call_count == 3
    endpoint.side_effect = [httpx.Response(401), httpx.Response(401)]
    result = await omada.call_tool(CONFIG, "omada_list_sites", {})
    assert result.is_error and "HTTP 401" in result.content[0].text
    assert auth.call_count == 4 and endpoint.call_count == 5


@pytest.mark.parametrize("tool,args", [
    ("request", {"url": "https://attacker.test"}),
    ("omada_list_devices", {"site_id": "../authorize"}),
    ("omada_list_devices", {"site_id": "site%2Fother"}),
    ("omada_list_devices", {}),
    ("omada_list_sites", {"headers": {"Authorization": "override"}}),
    ("omada_list_sites", {"page": True}),
    ("omada_list_sites", {"page": 0}),
    ("omada_list_sites", {"page_size": 1001}),
])
@respx.mock
async def test_invalid_calls_never_make_http_requests(tool, args):
    assert (await omada.call_tool(CONFIG, tool, args)).is_error
    assert not respx.calls


@pytest.mark.parametrize("url", ["http://omada.test", "https://user:pass@omada.test", "https://omada.test/api",
                                 "https://omada.test?token=x", "https://omada.test/#x", "https://omada.test:bad"])
def test_bad_config(url):
    with pytest.raises(omada.OmadaError):
        omada.validate_config({**CONFIG, "url": url})


@pytest.mark.parametrize("response", [
    httpx.Response(200, json={"errorCode": -1, "msg": "never-show-this-secret"}),
    httpx.Response(200, text="never-show-this-secret"),
    httpx.Response(200, json={"errorCode": 0}),
    httpx.Response(403, text="never-show-this-secret"),
    httpx.Response(302, headers={"Location": "https://attacker.test"}),
])
@respx.mock
async def test_errors_and_redirects_do_not_leak_credentials(response):
    respx.post(TOKEN_URL).mock(return_value=token_response())
    respx.get(BASE + "/sites").mock(return_value=response)
    ok, message = await mcp_proxy.probe(CONFIG)
    assert not ok and CONFIG["client_secret"] not in message and "AT-private" not in message
    assert len(respx.calls) == 2


@respx.mock
async def test_tls_and_timeout_configuration(monkeypatch):
    real_client = httpx.AsyncClient
    options = []

    def client(**kwargs):
        options.append(kwargs)
        return real_client(**kwargs)

    monkeypatch.setattr(omada.httpx, "AsyncClient", client)
    respx.post(TOKEN_URL).mock(return_value=token_response())
    respx.get(BASE + "/sites").mock(return_value=data_response())
    assert (await omada.probe(CONFIG))[0]
    assert (await omada.probe({**CONFIG, "verify_tls": False}))[0]
    assert options[0] == {"verify": True, "timeout": 30, "follow_redirects": False, "trust_env": False}
    assert options[1]["verify"] is False


@respx.mock
async def test_approval_and_deny_boundary_and_audit(db, agent, log_notifier):
    resource = Resource(kind="mcp", name="router", config={**CONFIG, "arg_keys": ["site_id"]},
                        default_mode="approval")
    db.add(resource)
    await db.commit()
    auth = respx.post(TOKEN_URL).mock(return_value=token_response())
    endpoint = respx.get(BASE + "/sites/site-1/devices").mock(return_value=data_response())
    args = {"site_id": "site-1", "_wait_seconds": 0}
    pending = await _proxy_call(db, agent, None, "router", "omada_list_devices", args)
    body = pending.structured_content or json.loads(pending.content[0].text)
    assert body["error"] == "approval_required" and not respx.calls
    await approvals.decide(db, body["request_id"], "once", via="ui")
    out = await _proxy_call(db, agent, None, "router", "omada_list_devices", args)
    assert not out.is_error and auth.call_count == endpoint.call_count == 1
    assert out.meta["keywright"]["audit_id"]
    assert (await _proxy_call(db, agent, None, "router", "omada_list_devices", args)).is_error
    db.add(Policy(pattern="mcp/router/**", effect="deny", agent_id=agent.id))
    await db.commit()
    assert (await _proxy_call(db, agent, None, "router", "omada_list_devices", args)).is_error
    assert endpoint.call_count == 1
    events = (await db.execute(select(AuditEvent))).scalars().all()
    assert CONFIG["client_secret"] not in json.dumps([e.detail for e in events])
    assert "AT-private" not in json.dumps([e.detail for e in events])


async def test_admin_setup_edit_and_secret_preservation(live_server, db):
    form = {"kind": "mcp", "adapter": "omada", "name": "router", "default_mode": "approval",
            "url": CONFIG["url"], "omada_id": CONFIG["omada_id"], "client_id": CONFIG["client_id"],
            "client_secret": CONFIG["client_secret"], "verify_tls": "1", "arg_keys": "site_id",
            "audit_handle": "1"}
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as client:
        await client.post("/ui/login", data={"password": "adminpass123"})
        page = await client.get("/ui/resources/new?kind=mcp&adapter=omada")
        assert "Add TP-Link Omada" in page.text and 'value="site_id"' in page.text
        saved = await client.post("/ui/resources", data=form)
        assert saved.status_code == 303
        resource = (await db.execute(select(Resource).where(Resource.name == "router"))).scalar_one()
        assert resource.config["adapter"] == "omada" and resource.default_mode == "approval"
        edit = await client.get(f"/ui/resources/{resource.id}")
        assert "Edit TP-Link Omada" in edit.text and CONFIG["client_secret"] not in edit.text
        assert "Omada" in (await client.get("/ui/resources")).text
        await client.post("/ui/resources", data={**form, "rid": resource.id, "client_secret": "",
                                                "description": "My router"})
        await db.refresh(resource)
        assert resource.config["client_secret"] == CONFIG["client_secret"]
        assert resource.description == "My router"
        invalid = await client.post("/ui/resources", data={**form, "name": "bad", "client_secret": ""})
        assert invalid.headers["location"] == "/ui/resources/new?kind=mcp&adapter=omada"
        assert "An Omada Client Secret is required" in (await client.get(invalid.headers["location"])).text
        assert (await db.execute(select(Resource).where(Resource.name == "bad"))).scalar_one_or_none() is None


@respx.mock
async def test_rejected_token_is_replaced_for_read():
    auth = respx.post(TOKEN_URL).mock(side_effect=[token_response("AT-old"), token_response("AT-new")])
    endpoint = respx.get(BASE + "/sites").mock(side_effect=[httpx.Response(401), data_response()])
    assert (await omada.probe(CONFIG))[0]
    assert auth.call_count == 2
    assert endpoint.calls.last.request.headers["Authorization"] == "AccessToken=AT-new"


@pytest.mark.parametrize("response", [
    httpx.Response(200, json={"errorCode": 0, "result": {"accessToken": "AT-private"}}),
    httpx.Response(200, json={"errorCode": 0, "result": {"accessToken": "bad\r\nheader", "expiresIn": 7200}}),
    httpx.Response(200, json={"errorCode": -44101, "msg": "never-show-this-secret"}),
])
@respx.mock
async def test_invalid_auth_never_calls_api(response):
    respx.post(TOKEN_URL).mock(return_value=response)
    ok, message = await omada.probe(CONFIG)
    assert not ok and CONFIG["client_secret"] not in message
    assert len(respx.calls) == 1


@respx.mock
async def test_transport_failure_is_safe():
    respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("never-show-this-secret"))
    ok, message = await omada.probe(CONFIG)
    assert not ok and "connectivity" in message and CONFIG["client_secret"] not in message


@respx.mock
async def test_ap_details_use_fixed_route_and_do_not_send_pagination():
    respx.post(TOKEN_URL).mock(return_value=token_response())
    endpoint = respx.get(BASE + '/sites/site-1/aps/AA-BB-CC-DD-EE-FF').mock(
        return_value=data_response({'wirelessLinked': True, 'wirelessUplink': {'uplinkMac': '00-11-22-33-44-55'}}))
    result = await omada.request(CONFIG, 'omada_get_ap', {'site_id': 'site-1', 'ap_mac': 'aa:bb:cc:dd:ee:ff'})
    assert result['wirelessLinked'] is True and not endpoint.calls.last.request.url.params
    assert next(t for t in omada.list_tools() if t.name == 'omada_get_ap').annotations.read_only_hint


@pytest.mark.parametrize('mac', ['../devices', 'AA-BB-CC-DD-EE-FF?all=true', 'invalid', 123])
@respx.mock
async def test_ap_details_validate_mac_before_making_requests(mac):
    result = await omada.call_tool(CONFIG, 'omada_get_ap', {'site_id': 'site-1', 'ap_mac': mac})
    assert result.is_error and not respx.calls
