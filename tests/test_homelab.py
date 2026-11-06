import json

import httpx
import pytest
import respx
from sqlalchemy import select

from keywright_server import approvals, homelab, mcp_proxy
from keywright_server.mcp_server import _proxy_call
from keywright_server.models import AuditEvent, Policy, Resource


def config(adapter):
    return {"adapter": adapter, "url": "https://service.test", "api_secret": "fixture-private-secret",
            "token_id": "reader@pve!inventory", "verify_tls": True}


CASES = [
    ("proxmox", "proxmox_list_nodes", "/api2/json/nodes", {}),
    ("proxmox", "proxmox_list_resources", "/api2/json/cluster/resources", {}),
    ("proxmox", "proxmox_get_node_status", "/api2/json/nodes/pve-1/status", {"node": "pve-1"}),
    ("proxmox", "proxmox_get_guest_status", "/api2/json/nodes/pve-1/lxc/101/status/current",
     {"node": "pve-1", "guest_type": "lxc", "vmid": 101}),
    ("proxmox", "proxmox_get_guest_status", "/api2/json/nodes/pve-1/qemu/102/status/current",
     {"node": "pve-1", "guest_type": "qemu", "vmid": 102}),
    ("pihole", "pihole_get_summary", "/api/stats/summary", {}),
    ("pihole", "pihole_get_blocking", "/api/dns/blocking", {}),
    ("pihole", "pihole_get_version", "/api/info/version", {}),
    ("homeassistant", "ha_check_api", "/api/", {}),
    ("homeassistant", "ha_list_states", "/api/states", {}),
    ("homeassistant", "ha_get_state", "/api/states/sensor.temperature", {"entity_id": "sensor.temperature"}),
    ("homeassistant", "ha_list_services", "/api/services", {}),
    ("jellyfin", "jellyfin_get_system_info", "/System/Info", {}),
    ("jellyfin", "jellyfin_list_libraries", "/Library/VirtualFolders", {}),
    ("jellyfin", "jellyfin_list_sessions", "/Sessions", {}),
    ("sonarr", "sonarr_get_status", "/api/v3/system/status", {}),
    ("sonarr", "sonarr_get_health", "/api/v3/health", {}),
    ("sonarr", "sonarr_list_library", "/api/v3/series", {}),
    ("sonarr", "sonarr_list_queue", "/api/v3/queue?page=2&pageSize=10", {"page": 2, "page_size": 10}),
    ("radarr", "radarr_get_status", "/api/v3/system/status", {}),
    ("radarr", "radarr_get_health", "/api/v3/health", {}),
    ("radarr", "radarr_list_library", "/api/v3/movie", {}),
    ("radarr", "radarr_list_queue", "/api/v3/queue?page=1&pageSize=50", {}),
    ("authentik", "authentik_get_current_user", "/api/v3/core/users/me/", {}),
]


def pihole_auth():
    auth = respx.post("https://service.test/api/auth").respond(
        200, json={"session": {"valid": True, "sid": "fixture-private-sid"}})
    logout = respx.delete("https://service.test/api/auth").respond(204)
    return auth, logout


@pytest.mark.parametrize("adapter,tool,path,args", CASES)
@respx.mock
async def test_protocol_and_routes(adapter, tool, path, args):
    if adapter == "pihole":
        auth, logout = pihole_auth()
    result = {"data": [{"name": "fixture"}]} if adapter == "proxmox" else [{"name": "fixture"}]
    expected_result = [{"name": "fixture"}]
    if adapter == "authentik":
        result = expected_result = {"user": {"pk": 12, "username": "reader"}}
    route = respx.get("https://service.test" + path).respond(200, json=result)
    out = await mcp_proxy.call_tool(config(adapter), tool, args)
    assert not out.is_error and json.loads(out.content[0].text) == expected_result
    headers = route.calls.last.request.headers
    expected = {
        "proxmox": ("Authorization", "PVEAPIToken=reader@pve!inventory=fixture-private-secret"),
        "homeassistant": ("Authorization", "Bearer fixture-private-secret"),
        "jellyfin": ("Authorization", 'MediaBrowser Token="fixture-private-secret"'),
        "sonarr": ("X-Api-Key", "fixture-private-secret"),
        "radarr": ("X-Api-Key", "fixture-private-secret"),
        "pihole": ("X-FTL-SID", "fixture-private-sid"),
        "authentik": ("Authorization", "Bearer fixture-private-secret"),
    }
    key, value = expected[adapter]
    assert headers[key] == value
    assert "fixture-private" not in str(route.calls.last.request.url)
    if adapter == "pihole":
        assert json.loads(auth.calls.last.request.content) == {"password": "fixture-private-secret"}
        assert logout.calls.last.request.headers["X-FTL-SID"] == "fixture-private-sid"


@pytest.mark.parametrize("url", ["file:///etc/passwd", "https://user:pw@service.test", "https://service.test?x=1",
                                "https://service.test/#x", "https://service.test/../else", "https://service.test/%2f",
                                "https://service.test\n", "https://service.test:bad", "https://service.test\\@evil.test"])
def test_reject_ambiguous_addresses(url):
    with pytest.raises(homelab.ConnectorError):
        homelab.validate_config({**config("sonarr"), "url": url})


@pytest.mark.parametrize("tool,args", [
    ("proxmox_get_node_status", {"node": "../access"}),
    ("proxmox_get_guest_status", {"node": "pve", "guest_type": "qemu", "vmid": "101"}),
    ("proxmox_list_nodes", {"url": "https://evil.test"}),
    ("proxmox_list_nodes", {"headers": {"Authorization": "other"}}),
    ("proxmox_list_nodes", {"method": "DELETE"}),
    ("ha_get_state", {"entity_id": "sensor.a/../../config"}),
    ("sonarr_list_queue", {"page_size": 10000}),
    ("not_a_tool", {}),
])
@respx.mock
async def test_invalid_arguments_never_send_credentials(tool, args):
    adapter = "homeassistant" if tool.startswith("ha_") else "sonarr" if tool.startswith("sonarr_") else "proxmox"
    assert (await mcp_proxy.call_tool(config(adapter), tool, args)).is_error
    assert not respx.calls


@pytest.mark.parametrize("status", [302, 401, 403, 500])
@respx.mock
async def test_pihole_cleanup_and_safe_errors(status):
    _, logout = pihole_auth()
    respx.get("https://service.test/api/stats/summary").respond(
        status, text="fixture-private-secret", headers={"Location": "https://evil.test"})
    out = await mcp_proxy.call_tool(config("pihole"), "pihole_get_summary", {})
    assert out.is_error and str(status) in out.content[0].text
    assert "fixture-private" not in out.content[0].text
    assert logout.called and len(respx.calls) == 3


@pytest.mark.parametrize("payload", [{}, {"session": {"valid": False, "sid": "bad"}},
                                    {"session": {"valid": True, "sid": "bad\r\nHeader: value"}}])
@respx.mock
async def test_pihole_rejects_invalid_session(payload):
    respx.post("https://service.test/api/auth").respond(200, json=payload)
    out = await mcp_proxy.call_tool(config("pihole"), "pihole_get_summary", {})
    assert out.is_error and len(respx.calls) == 1


@respx.mock
async def test_base_path_tls_options_and_reflected_credential(monkeypatch):
    options = []
    original = httpx.AsyncClient

    def client(**kwargs):
        options.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client)
    respx.get("https://service.test/media/System/Info").respond(
        200, json={"reflection": "Bearer fixture-private-secret", "flag": True, "empty": None})
    out = await mcp_proxy.call_tool({**config("jellyfin"), "url": "https://service.test/media",
                                     "verify_tls": False}, "jellyfin_get_system_info", {})
    assert not out.is_error and "fixture-private-secret" not in out.content[0].text
    assert json.loads(out.content[0].text)["flag"] is True
    assert options == [{"verify": False, "timeout": 30, "follow_redirects": False, "trust_env": False}]


@pytest.mark.parametrize("body", [b"<html>private upstream text</html>", b"x" * (homelab.MAX_RESPONSE_BYTES + 1)])
@respx.mock
async def test_invalid_or_large_response_is_safe(body):
    respx.get("https://service.test/api/").respond(200, content=body)
    out = await mcp_proxy.call_tool(config("homeassistant"), "ha_check_api", {})
    assert out.is_error and "private upstream" not in out.content[0].text


@pytest.mark.parametrize("adapter", homelab.CONNECTORS)
@respx.mock
async def test_approval_deny_and_audit(db, agent, log_notifier, adapter):
    cfg = config(adapter)
    db.add(Resource(kind="mcp", name="service", config=cfg, default_mode="approval"))
    await db.commit()
    tool = next(iter(homelab.CONNECTORS[adapter].operations))
    args = {"_wait_seconds": 0}
    pending = await _proxy_call(db, agent, None, "service", tool, args)
    payload = pending.structured_content or json.loads(pending.content[0].text)
    assert payload["error"] == "approval_required" and not respx.calls
    await approvals.decide(db, payload["request_id"], "once", via="ui")
    if adapter == "pihole":
        pihole_auth()
    path = homelab.CONNECTORS[adapter].operations[tool].path
    response = {"data": []} if adapter == "proxmox" else {"user": {}} if adapter == "authentik" else {}
    route = respx.get(cfg["url"] + path).respond(200, json=response)
    out = await _proxy_call(db, agent, None, "service", tool, args)
    assert not out.is_error and route.call_count == 1 and out.meta["keywright"]["audit_id"]
    assert (await _proxy_call(db, agent, None, "service", tool, args)).is_error
    db.add(Policy(pattern="mcp/service/**", effect="deny", agent_id=agent.id))
    await db.commit()
    assert (await _proxy_call(db, agent, None, "service", tool, args)).is_error
    assert route.call_count == 1
    events = (await db.execute(select(AuditEvent))).scalars().all()
    assert "fixture-private" not in json.dumps([event.detail for event in events])
    tools = await mcp_proxy.list_tools("service", cfg)
    assert "fixture-private" not in str(tools)
    assert all(t.annotations.read_only_hint and not t.annotations.destructive_hint for t in tools)


@pytest.mark.parametrize("tool,path,row,expected", [
    ("authentik_list_users", "/core/users/", {"pk": 8, "username": "alice", "groups": ["group-id"],
        "attributes": {"secret": "hidden"}, "groups_obj": [{"attributes": {"secret": "hidden"}}]},
        {"pk": 8, "username": "alice", "groups": ["group-id"]}),
    ("authentik_list_groups", "/core/groups/", {"pk": "group-id", "name": "readers", "users": [8],
        "attributes": {"secret": "hidden"}, "users_obj": [{"password": "hidden"}]},
        {"pk": "group-id", "name": "readers", "users": [8]}),
    ("authentik_list_applications", "/core/applications/", {"name": "wiki", "provider": 3,
        "provider_obj": {"client_secret": "hidden"}, "backchannel_providers_obj": [{"token": "hidden"}]},
        {"name": "wiki", "provider": 3}),
    ("authentik_list_providers", "/providers/all/", {"pk": 3, "name": "OIDC", "client_secret": "hidden",
        "signing_key": {"key_data": "hidden"}, "authentication_flow": "flow-id"},
        {"pk": 3, "name": "OIDC", "authentication_flow": "flow-id"}),
    ("authentik_list_events", "/events/events/", {"action": "login_failed", "app": "authentik.core",
        "created": "2026-11-03T12:00:00Z", "context": {"password": "hidden"}, "brand": {"secret": "hidden"},
        "user": {"pk": 8, "username": "alice", "secret": "hidden"}},
        {"action": "login_failed", "app": "authentik.core", "created": "2026-11-03T12:00:00Z",
         "user": {"pk": 8, "username": "alice"}}),
])
@respx.mock
async def test_authentik_pagination_and_safe_summaries(tool, path, row, expected):
    search = "alice &page_size=999"
    route = respx.get("https://service.test/api/v3" + path).respond(200, json={
        "pagination": {"current": 2, "next": 3, "count": 101, "secret": "hidden"},
        "results": [row], "autocomplete": {"secret": "hidden"}, "next": "https://evil.test/secret",
    })
    out = await mcp_proxy.call_tool(config("authentik"), tool, {"page": 2, "page_size": 10, "search": search})
    assert not out.is_error
    assert json.loads(out.content[0].text) == {
        "pagination": {"current": 2, "next": 3, "count": 101}, "results": [expected]}
    req = route.calls.last.request
    assert req.method == "GET" and req.headers["Authorization"] == "Bearer fixture-private-secret"
    assert dict(req.url.params) == {"page": "2", "page_size": "10", "search": search,
                                    "ordering": "-created" if tool.endswith("events") else "pk"}
    assert len(respx.calls) == 1


@respx.mock
async def test_authentik_probe_uses_identity_without_directory_permissions():
    respx.get("https://service.test/api/v3/core/users/me/").respond(200, json={"user": {
        "pk": 9, "username": "reader", "settings": {"secret": "hidden"}, "email": "fixture-private-secret",
    }, "original": {"secret": "hidden"}, "users": [{"secret": "hidden"}]})
    ok, message = await homelab.probe(config("authentik"))
    assert ok and "6 read-only tools" in message
    out = await homelab.request(config("authentik"), "authentik_get_current_user", {})
    assert out == {"user": {"pk": 9, "username": "reader", "email": "[redacted]"}}


@pytest.mark.parametrize("args", [{"page": 0}, {"page": "2"}, {"page_size": 101}, {"page_size": True},
                                  {"search": "x" * 201}, {"url": "https://evil.test"},
                                  {"ordering": "secret"}, {"method": "POST"}])
@respx.mock
async def test_authentik_rejects_invalid_arguments_before_network(args):
    out = await mcp_proxy.call_tool(config("authentik"), "authentik_list_users", args)
    assert out.is_error and not respx.calls


@pytest.mark.parametrize("status", [302, 401, 403, 500])
@respx.mock
async def test_authentik_errors_do_not_disclose_upstream_details_or_follow_redirects(status):
    respx.get("https://service.test/api/v3/core/users/").respond(
        status, text="hidden", headers={"Location": "https://evil.test"})
    out = await mcp_proxy.call_tool(config("authentik"), "authentik_list_users", {})
    assert out.is_error and str(status) in out.content[0].text and "hidden" not in out.content[0].text
    assert len(respx.calls) == 1


@pytest.mark.parametrize("body", [[], {}, {"results": {}, "pagination": {}},
                                  {"results": ["hidden"], "pagination": {}}])
@respx.mock
async def test_authentik_fails_closed_on_unexpected_response_shape(body):
    respx.get("https://service.test/api/v3/core/users/").respond(200, json=body)
    out = await mcp_proxy.call_tool(config("authentik"), "authentik_list_users", {})
    assert out.is_error and "hidden" not in out.content[0].text


def test_authentik_rejects_admin_and_api_urls():
    for path in ("/api/v3", "/if/admin"):
        with pytest.raises(homelab.ConnectorError, match="base address"):
            homelab.validate_config({**config("authentik"), "url": "https://service.test" + path})


@respx.mock
async def test_authentik_defaults_and_nested_values_cannot_expand_output():
    route = respx.get("https://service.test/api/v3/core/users/").respond(200, json={
        "pagination": {"current": 1, "next": "https://evil.test/hidden", "count": {"secret": "hidden"}},
        "results": [{"pk": 7, "username": {"secret": "hidden"}, "groups": [{"secret": "hidden"}]}],
    })
    out = await homelab.request(config("authentik"), "authentik_list_users", {})
    assert out == {"pagination": {"current": 1}, "results": [{"pk": 7}]}
    assert dict(route.calls.last.request.url.params) == {"page": "1", "page_size": "25", "ordering": "pk"}
    assert len(respx.calls) == 1
