"""OAuth against a simulated provider, including real HTTP transport and browser routes."""
import asyncio
import hashlib
import json
import logging
import time
from base64 import urlsafe_b64encode
from dataclasses import replace
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import httpx2
import pytest
from sqlalchemy import select, update

from keywright_server import integrations, mcp_proxy
from keywright_server import mcp_oauth as oauth
from keywright_server.config import settings
from keywright_server.db import session
from keywright_server.models import AuditEvent, MCPOAuthConnection, MCPOAuthFlow, Resource, now
from keywright_server.web import auth, mcp_oauth_ui, oidc
from keywright_server.web.app import create_app

ORIGIN = "https://kw.test"
SERVER = "https://mcp.example.test/mcp"
ISSUER = "https://mcp.example.test"


@pytest.fixture
async def provider(db, monkeypatch):
    monkeypatch.setattr(settings, "public_url", ORIGIN)
    monkeypatch.setattr(settings, "auth_mode", "password")
    await auth.set_password(db, "adminpass123")
    state = {"calls": [], "refreshes": 0, "exchanges": 0, "tool_calls": 0, "tool_attempts": 0, "registrations": 0}
    metadata = {"issuer": ISSUER, "authorization_endpoint": ISSUER + "/authorize",
                "token_endpoint": ISSUER + "/token", "registration_endpoint": ISSUER + "/register",
                "code_challenge_methods_supported": ["S256"],
                "authorization_response_iss_parameter_supported": True}
    state["metadata"] = metadata

    async def handler(request):
        state["calls"].append(request)
        path = request.url.path
        server_path = urlsplit(state.get("resource", SERVER)).path
        # Some providers advertise their origin as resource, with /mcp as transport.
        server_path = server_path or "/mcp"
        if request.method == "GET" and path == server_path:
            if state.get("get_not_allowed"):
                return httpx2.Response(405)
            return httpx2.Response(401, headers={"WWW-Authenticate":
                f'Bearer resource_metadata="{ISSUER}/.well-known/oauth-protected-resource/mcp", '
                f'scope="{state.get("scope", "read write")}"'})
        if path == "/.well-known/oauth-protected-resource" + server_path:
            if state.get("root_metadata"):
                return httpx2.Response(404)
            return httpx2.Response(200, json={"resource": state.get("resource", SERVER),
                                             "scopes_supported": state.get("scopes_supported", []),
                                             "authorization_servers": [state.get("issuer", ISSUER)]})
        if path == "/.well-known/oauth-protected-resource":
            return httpx2.Response(200, json={"resource": state.get("resource", SERVER),
                                             "authorization_servers": [state.get("issuer", ISSUER)]})
        if path == "/.well-known/oauth-authorization-server" and state.get("oidc_metadata"):
            return httpx2.Response(404)
        if path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
            return httpx2.Response(200, json=metadata)
        if path == "/.well-known/oauth-authorization-server" + urlsplit(state.get("issuer", ISSUER)).path:
            return httpx2.Response(200, json=metadata)
        if path == urlsplit(metadata["registration_endpoint"]).path:
            state["registrations"] += 1
            body = json.loads(request.content)
            state["registration_body"] = body
            assert body["redirect_uris"] == [ORIGIN + oauth.CALLBACK_PATH]
            return httpx2.Response(201, json={**body, "client_id": "registered-client"})
        if path == urlsplit(metadata["token_endpoint"]).path:
            form = parse_qs(request.content.decode())
            assert form["resource"] == [state.get("resource", SERVER)]
            state["token_form"] = form
            if form["grant_type"] == ["authorization_code"]:
                state["exchanges"] += 1
                challenge = urlsafe_b64encode(hashlib.sha256(form["code_verifier"][0].encode()).digest()).rstrip(b"=").decode()
                assert challenge == state["authorize"]["code_challenge"][0]
                assert form["redirect_uri"] == [ORIGIN + oauth.CALLBACK_PATH]
            else:
                assert form["grant_type"] == ["refresh_token"]
                state["refreshes"] += 1
                assert form["refresh_token"] == ["refresh-secret"]
                if state.get("refresh_started"):
                    state["refresh_started"].set()
                    await state["refresh_continue"].wait()
                if state.get("refresh_error"):
                    return httpx2.Response(400, json={"error": state["refresh_error"],
                                                     "error_description": "DO-NOT-LEAK-provider-secret"})
            body = {"access_token": "access-secret" if not state["refreshes"] else "refreshed-secret",
                    "token_type": "Bearer", "expires_in": 3600, "refresh_token": "refresh-secret"}
            if state["refreshes"] and not state.get("omit_refresh"):
                body["refresh_token"] = "rotated-refresh-secret"
            if state["refreshes"] and state.get("omit_refresh"):
                body.pop("refresh_token")
            return httpx2.Response(200, json=body)
        if path == server_path and request.method == "POST":
            assert request.headers["authorization"] == "Bearer " + state.get("expected_access", "access-secret")
            message = json.loads(request.content)
            if "id" not in message:
                return httpx2.Response(202)
            if message["method"] == "tools/call":
                state["tool_attempts"] += 1
            if state.get("reject_mcp") and message["method"] == "tools/call":
                return httpx2.Response(401, json={"error": "access-secret"})
            if message["method"] == "server/discover":
                return httpx2.Response(200, json={"jsonrpc": "2.0", "id": message["id"],
                                                  "error": {"code": -32601, "message": "Method not found"}})
            if message["method"] == "initialize":
                result = {"protocolVersion": message["params"]["protocolVersion"],
                          "capabilities": {"tools": {}}, "serverInfo": {"name": "Mock MCP", "version": "1"}}
            elif message["method"] == "tools/list":
                result = {"tools": [{"name": "search", "inputSchema": {"type": "object"}}]}
            elif message["method"] == "tools/call":
                state["tool_calls"] += 1
                result = {"content": [{"type": "text", "text": "found a page"}]}
            else:
                raise AssertionError(message)
            return httpx2.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": result})
        if path == server_path and request.method in ("GET", "DELETE"):
            return httpx2.Response(405)
        raise AssertionError(f"Unexpected request {request.method} {request.url}")

    transport = httpx2.MockTransport(handler)
    original_client = httpx2.AsyncClient
    class MockClient(original_client):
        def __init__(self, **kwargs):
            original_client.__init__(self, transport=transport, **kwargs)

    monkeypatch.setattr(oauth.httpx, "AsyncClient", MockClient)
    monkeypatch.setattr(mcp_proxy, "create_mcp_http_client", MockClient)
    mcp_proxy._tool_cache.clear()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url=ORIGIN) as browser:
        browser.cookies.set(auth.COOKIE, auth.signer().sign(auth._session_payload()).decode())
        yield browser, state


async def save(browser, **overrides):
    form = {"kind": "mcp", "name": "notion", "url": SERVER, "auth_type": "oauth", **overrides}
    response = await browser.post("/ui/resources", data=form, headers={"Origin": ORIGIN})
    assert response.status_code == 303
    rid = response.headers["location"].split("/")[-1]
    async with session() as db:
        resource = await db.get(Resource, rid)
    assert resource is not None, response.headers.get("set-cookie")
    return resource


async def begin(browser, state, resource):
    response = await browser.post(f"/ui/mcp-oauth/{resource.id}/connect", headers={"Origin": ORIGIN})
    import re
    from html import unescape
    assert response.status_code == 200, response.text
    assert "form-action 'self'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert "window.location.replace" in response.text
    link = re.search(r'id="oauth-continue"[^>]*href="([^"]+)"', response.text)
    assert link, "Sign-in must have a working link when JavaScript is unavailable"
    params = parse_qs(urlsplit(unescape(link[1])).query)
    state["authorize"] = params
    assert params["code_challenge_method"] == ["S256"]
    assert params["resource"] == [state.get("resource", SERVER)]
    assert params["scope"] == [state.get("scope", "read write")]
    return params["state"][0]


async def connect(browser, state, resource):
    value = await begin(browser, state, resource)
    response = await browser.get(oauth.CALLBACK_PATH, params={
        "state": value, "code": "code-secret", "iss": state.get("issuer", ISSUER),
    })
    assert response.status_code == 303, response.text
    return value


async def expire(config):
    async with session() as db:
        row = await db.get(MCPOAuthConnection, config["oauth_id"])
        data = oauth.unseal(row.sealed_data)
        data["token"]["expires_at"] = time.time() - 1
        row.sealed_data = oauth.seal(data)
        await db.commit()


async def test_browser_connect_transport_encryption_and_disconnect(provider):
    browser, state = provider
    resource = await save(browser)
    await connect(browser, state, resource)
    assert await oauth.status(resource.config) == "connected"
    row = await oauth.load(resource.config)
    assert "access-secret" not in row.sealed_data and "refresh-secret" not in row.sealed_data
    assert "secret" not in json.dumps(resource.config)
    page = await browser.get(f"/ui/resources/{resource.id}")
    assert "Connected" in page.text and "access-secret" not in page.text
    tools = await mcp_proxy.list_tools(resource.name, resource.config)
    assert [tool.name for tool in tools] == ["search"]
    result = await mcp_proxy.call_tool(resource.config, "search", {})
    assert result.content[0].text == "found a page"
    response = await browser.post(f"/ui/mcp-oauth/{resource.id}/disconnect", headers={"Origin": ORIGIN})
    assert response.status_code == 303
    assert "token" not in oauth.unseal((await oauth.load(resource.config)).sealed_data)
    with pytest.raises(oauth.ConnectionError, match="not connected"):
        await mcp_proxy.list_tools(resource.name, resource.config)
    assert state["tool_calls"] == 1


@pytest.mark.parametrize("omit_refresh", [False, True])
async def test_refresh_rotation_persists_across_clients_and_is_serialized(provider, omit_refresh):
    browser, state = provider
    resource = await save(browser)
    await connect(browser, state, resource)
    await expire(resource.config)
    state["omit_refresh"] = omit_refresh
    tokens = await asyncio.gather(*(oauth.access_token(resource.config) for _ in range(5)))
    assert tokens == ["refreshed-secret"] * 5 and state["refreshes"] == 1
    row = await oauth.load(resource.config)
    assert row.lease_owner is None
    token = oauth.unseal(row.sealed_data)["token"]
    assert token["refresh_token"] == ("refresh-secret" if omit_refresh else "rotated-refresh-secret")
    assert await oauth.access_token(resource.config) == "refreshed-secret"


async def test_invalid_grant_requires_reconnect_and_hides_provider_errors(provider):
    browser, state = provider
    resource = await save(browser)
    await connect(browser, state, resource)
    await expire(resource.config)
    state["refresh_error"] = "invalid_grant"
    with pytest.raises(oauth.ConnectionError) as exc:
        await oauth.access_token(resource.config)
    assert "DO-NOT-LEAK" not in str(exc.value)
    assert await oauth.status(resource.config) == "needs_reconnect"
    with pytest.raises(oauth.ConnectionError):
        await oauth.access_token(resource.config)
    assert state["refreshes"] == 1


async def test_disconnect_during_refresh_cannot_restore_tokens(provider):
    browser, state = provider
    resource = await save(browser)
    await connect(browser, state, resource)
    await expire(resource.config)
    state.update(refresh_started=asyncio.Event(), refresh_continue=asyncio.Event())
    task = asyncio.create_task(oauth.access_token(resource.config))
    await asyncio.wait_for(state["refresh_started"].wait(), 5)
    await oauth.disconnect(resource.config)
    state["refresh_continue"].set()
    with pytest.raises(oauth.ConnectionError, match="changed during refresh"):
        await task
    row = await oauth.load(resource.config)
    assert row.status == "disconnected" and "token" not in oauth.unseal(row.sealed_data)


@pytest.mark.parametrize("bad", ["browser", "admin", "state", "issuer", "missing_issuer", "denied", "expired"])
async def test_callback_binding_and_replay(provider, bad):
    browser, state = provider
    resource = await save(browser)
    value = await begin(browser, state, resource)
    params = {"state": value, "code": "code-secret", "iss": ISSUER}
    cookie = browser.cookies.get(mcp_oauth_ui.COOKIE)
    if bad == "browser":
        browser.cookies.delete(mcp_oauth_ui.COOKIE)
    elif bad == "admin":
        # Another valid local administrator session must not complete this browser's flow.
        async with session() as db:
            await db.execute(update(MCPOAuthFlow).values(admin_hash="other-admin-session"))
            await db.commit()
    elif bad == "state":
        params["state"] = "wrong"
    elif bad == "issuer":
        params["iss"] = "https://wrong.test"
    elif bad == "missing_issuer":
        params.pop("iss")
    elif bad == "denied":
        params["error"] = "access_denied"
    elif bad == "expired":
        async with session() as db:
            await db.execute(update(MCPOAuthFlow).values(expires_at=now() - timedelta(seconds=1)))
            await db.commit()
    response = await browser.get(oauth.CALLBACK_PATH, params=params)
    assert response.status_code == 400 and state["exchanges"] == 0
    # Restart so successful callback replay is checked for every variation too.
    value = await connect(browser, state, resource)
    browser.cookies.set(mcp_oauth_ui.COOKIE, cookie)
    replay = await browser.get(oauth.CALLBACK_PATH, params={"state": value, "code": "again", "iss": ISSUER})
    assert replay.status_code == 400 and state["exchanges"] == 1


async def test_changed_endpoint_and_disconnect_invalidate_pending_callback(provider):
    browser, state = provider
    resource = await save(browser)
    value = await begin(browser, state, resource)
    await oauth.disconnect(resource.config)
    response = await browser.get(oauth.CALLBACK_PATH, params={"state": value, "code": "code", "iss": ISSUER})
    assert response.status_code == 400 and state["exchanges"] == 0
    value = await begin(browser, state, resource)
    changed = await save(browser, rid=resource.id, url="https://other.test/mcp")
    assert changed.config["oauth_id"] != resource.config["oauth_id"]
    response = await browser.get(oauth.CALLBACK_PATH, params={"state": value, "code": "code", "iss": ISSUER})
    assert response.status_code == 400 and state["exchanges"] == 0
    with pytest.raises(oauth.ConnectionError):
        await oauth.access_token(resource.config)


@pytest.mark.parametrize("bad", ["resource", "issuer", "endpoint", "pkce"])
async def test_discovery_rejects_mismatched_or_untrusted_metadata(provider, bad):
    browser, state = provider
    resource = await save(browser)
    if bad == "resource":
        state["resource"] = "https://other.test/mcp"
    elif bad == "issuer":
        state["metadata"]["issuer"] = "https://other.test"
    elif bad == "endpoint":
        state["metadata"]["token_endpoint"] = "https://untrusted.test/token"
    else:
        state["metadata"]["code_challenge_methods_supported"] = ["plain"]
    response = await browser.post(f"/ui/mcp-oauth/{resource.id}/connect", headers={"Origin": ORIGIN})
    assert response.status_code == 400 and state["registrations"] == 0
    assert all(request.url.host == "mcp.example.test" for request in state["calls"])


async def test_preregistered_client_and_preserving_secret(provider):
    browser, state = provider
    resource = await save(browser, oauth_client_id="custom-client", oauth_client_secret="client-secret",
                          oauth_auth_method="client_secret_basic")
    await connect(browser, state, resource)
    assert state["registrations"] == 0
    token_requests = [r for r in state["calls"] if r.url.path == "/token"]
    assert token_requests[0].headers["authorization"].startswith("Basic ")
    saved = await save(browser, rid=resource.id, oauth_client_id="custom-client",
                       oauth_auth_method="client_secret_basic")
    assert saved.config["oauth_id"] == resource.config["oauth_id"]
    assert await oauth.status(saved.config) == "connected"
    page = await browser.get(f"/ui/resources/{resource.id}")
    assert "client-secret" not in page.text


async def test_connect_requires_admin_and_same_origin(provider):
    browser, state = provider
    resource = await save(browser)
    path = f"/ui/mcp-oauth/{resource.id}/connect"
    assert (await browser.post(path)).status_code == 403
    assert (await browser.post(path, headers={"Origin": "https://evil.test"})).status_code == 403
    browser.cookies.clear()
    response = await browser.post(path, headers={"Origin": ORIGIN})
    assert response.status_code == 303 and "/ui/login" in response.headers["location"]
    assert state["calls"] == []


async def test_401_does_not_replay_mcp_call_and_next_attempt_refreshes(provider):
    browser, state = provider
    resource = await save(browser, headers="authorization: stale-static-secret")
    assert "authorization" not in resource.config["headers"]
    await connect(browser, state, resource)
    state["reject_mcp"] = True
    with pytest.raises(oauth.ConnectionError) as exc:
        await mcp_proxy.call_tool(resource.config, "search", {})
    assert "access-secret" not in str(exc.value)
    assert state["refreshes"] == 0 and state["tool_attempts"] == 1
    state.update(reject_mcp=False, expected_access="refreshed-secret")
    result = await mcp_proxy.call_tool(resource.config, "search", {})
    assert result.content[0].text == "found a page" and state["refreshes"] == 1
    assert state["tool_attempts"] == 2


async def test_static_headers_still_work(provider):
    browser, state = provider
    resource = await save(browser, auth_type="headers", headers="Authorization: Bearer access-secret")
    assert "oauth_id" not in resource.config
    tools = await mcp_proxy.list_tools(resource.name, resource.config, force=True)
    assert tools[0].name == "search" and state["registrations"] == 0


async def test_discovery_fallback_and_separate_authorization_origin(provider):
    browser, state = provider
    issuer = "https://login.example.test"
    state.update(root_metadata=True, oidc_metadata=True, issuer=issuer)
    state["metadata"].update(issuer=issuer, token_endpoint=issuer + "/token",
                             registration_endpoint=issuer + "/register", authorization_endpoint=issuer + "/authorize")
    resource = await save(browser, oauth_origins=issuer)
    value = await begin(browser, state, resource)
    response = await browser.get(oauth.CALLBACK_PATH, params={"state": value, "code": "code", "iss": issuer})
    assert response.status_code == 303 and await oauth.status(resource.config) == "connected"
    assert any(str(r.url) == issuer + "/.well-known/openid-configuration" for r in state["calls"])
    assert all("authorization" not in r.headers for r in state["calls"] if r.method == "GET")


async def test_untrusted_authorization_origin_is_not_contacted(provider):
    browser, state = provider
    state["issuer"] = "https://untrusted.test"
    resource = await save(browser)
    response = await browser.post(f"/ui/mcp-oauth/{resource.id}/connect", headers={"Origin": ORIGIN})
    assert response.status_code == 400
    assert all(r.url.host != "untrusted.test" for r in state["calls"])


@pytest.mark.parametrize("grants", [None, ["authorization_code"], ["authorization_code", "refresh_token"]])
async def test_coinstats_preset_cross_origin_oauth_and_registration(provider, monkeypatch, grants):
    """Model CoinStats' three origins and root resource using an isolated provider."""
    import re
    from html import unescape

    browser, state = provider
    issuer = "https://api.example.test"
    consent = "https://consent.example.test"
    monkeypatch.setitem(integrations.PRESET_BY_ID, "coinstats", replace(
        integrations.PRESET_BY_ID["coinstats"], url=SERVER, oauth_origins=(issuer, consent),
    ))
    state.update(root_metadata=True, resource=ISSUER, issuer=issuer, scope="coinstats")
    state["metadata"].update(issuer=issuer, authorization_endpoint=consent + "/consent",
                             token_endpoint=issuer + "/token", registration_endpoint=issuer + "/register")
    if grants is not None:
        state["metadata"]["grant_types_supported"] = grants
    resource = await save(browser, name="CoinStats", integration="coinstats")
    response = await browser.post(f"/ui/mcp-oauth/{resource.id}/connect", headers={"Origin": ORIGIN})
    assert response.status_code == 200
    link = re.search(r'id="oauth-continue"[^>]*href="([^"]+)"', response.text)
    assert link
    url = urlsplit(unescape(link[1]))
    assert url.hostname == "consent.example.test"
    params = parse_qs(url.query)
    state["authorize"] = params
    assert params["resource"] == [ISSUER]
    assert params["scope"] == ["coinstats"]
    assert params["code_challenge_method"] == ["S256"]
    assert state["registration_body"]["grant_types"] == (grants or ["authorization_code", "refresh_token"])
    response = await browser.get(oauth.CALLBACK_PATH, params={
        "state": params["state"][0], "code": "code-secret", "iss": issuer,
    })
    assert response.status_code == 303 and await oauth.status(resource.config) == "connected"
    assert all("authorization" not in r.headers for r in state["calls"] if r.method == "GET")
    with pytest.raises(oauth.ConnectionError, match="another OAuth origin"):
        oauth.checked_url("https://untrusted.test/token", resource.config)


async def test_robinhood_path_issuer_discovery_and_approval(provider, db, agent, log_notifier, monkeypatch):
    """Reproduce Robinhood's GET 405, path issuer, and separate consent/token origins."""
    from keywright_server import approvals, mcp_server

    browser, state = provider
    server = ISSUER + "/mcp/trading"
    consent = "https://consent.example.test"
    api = "https://api.example.test"
    monkeypatch.setitem(integrations.PRESET_BY_ID, "robinhood", replace(
        integrations.PRESET_BY_ID["robinhood"], url=server, oauth_origins=(consent, api),
    ))
    state.update(resource=server, issuer=server, get_not_allowed=True, scope="internal",
                 scopes_supported=["internal"])
    state["metadata"].update(
        issuer=server, authorization_endpoint=consent + "/oauth",
        registration_endpoint=ISSUER + "/oauth/trading/register", token_endpoint=api + "/oauth2/token/",
        grant_types_supported=["authorization_code", "refresh_token"], token_endpoint_auth_methods_supported=["none"],
    )
    resource = await save(browser, name="Robinhood", integration="robinhood")
    await connect(browser, state, resource)
    assert await oauth.status(resource.config) == "connected"
    assert state["registration_body"]["client_name"] == "Keywright"
    assert state["registration_body"]["token_endpoint_auth_method"] == "none"
    assert any(str(r.url) == ISSUER + "/.well-known/oauth-authorization-server/mcp/trading"
               for r in state["calls"])
    assert any(str(r.url) == api + "/oauth2/token/" for r in state["calls"])
    assert all("authorization" not in r.headers for r in state["calls"] if r.method == "GET")
    await expire(resource.config)
    args = {"query": "synthetic account", "_wait_seconds": 0}
    denied = await mcp_server._proxy_call(db, agent, None, resource.name, "search", args)
    assert denied.structured_content["error"] == "approval_required"
    assert state["tool_calls"] == state["refreshes"] == 0
    await approvals.decide(db, denied.structured_content["request_id"], "once", via="ui")
    state["expected_access"] = "refreshed-secret"
    result = await mcp_server._proxy_call(db, agent, None, resource.name, "search", args)
    assert not result.is_error and state["tool_calls"] == state["refreshes"] == 1
    assert "access-secret" not in json.dumps(resource.config)
    with pytest.raises(oauth.ConnectionError, match="another OAuth origin"):
        oauth.checked_url("https://untrusted.test/token", resource.config)


async def test_oauth_refresh_still_requires_broker_approval(provider, db, agent, log_notifier):
    from keywright_server import approvals, mcp_server

    browser, state = provider
    resource = await save(browser)
    await connect(browser, state, resource)
    await expire(resource.config)
    args = {"query": "project", "_wait_seconds": 0}
    denied = await mcp_server._proxy_call(db, agent, None, resource.name, "search", args)
    payload = denied.structured_content or json.loads(denied.content[0].text)
    assert payload["error"] == "approval_required"
    assert state["tool_calls"] == state["refreshes"] == 0
    await approvals.decide(db, payload["request_id"], "once", via="ui")
    state["expected_access"] = "refreshed-secret"
    allowed = await mcp_server._proxy_call(db, agent, None, resource.name, "search", args)
    assert not allowed.is_error and state["tool_calls"] == state["refreshes"] == 1
    events = (await db.execute(select(AuditEvent))).scalars().all()
    assert any(e.tool == "mcp_call" and e.decision == "allow" for e in events)
    details = json.dumps([e.detail for e in events])
    assert all(secret not in details for secret in ("access-secret", "refresh-secret", "refreshed-secret"))
    denied_again = await mcp_server._proxy_call(db, agent, None, resource.name, "search", args)
    assert denied_again.is_error and state["tool_calls"] == 1


@pytest.mark.parametrize("action", ["headers", "delete"])
async def test_switching_auth_or_deleting_resource_removes_credentials(provider, action):
    browser, state = provider
    resource = await save(browser)
    await connect(browser, state, resource)
    await begin(browser, state, resource)
    if action == "headers":
        await save(browser, rid=resource.id, auth_type="headers")
    else:
        response = await browser.post(f"/ui/resources/{resource.id}/delete", headers={"Origin": ORIGIN})
        assert response.status_code == 303
    async with session() as db:
        assert await db.get(MCPOAuthConnection, resource.config["oauth_id"]) is None
        assert (await db.execute(select(MCPOAuthFlow))).scalars().all() == []
    with pytest.raises(oauth.ConnectionError):
        await oauth.access_token(resource.config)


async def test_changed_encryption_key_has_a_recovery_path(provider, monkeypatch):
    browser, state = provider
    resource = await save(browser)
    await connect(browser, state, resource)
    monkeypatch.setattr(settings, "secret_key", lambda: b"a-new-encryption-key")
    with pytest.raises(oauth.ConnectionError, match="cannot be opened"):
        await oauth.access_token(resource.config)
    saved = await save(browser, rid=resource.id)
    assert saved.config["oauth_id"] != resource.config["oauth_id"]
    await connect(browser, state, saved)
    assert await oauth.status(saved.config) == "connected"


def test_callback_codes_are_filtered_from_access_logs():
    record = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "%s %s %s %s %s",
                               ("127.0.0.1", "GET", oauth.CALLBACK_PATH + "?code=secret&state=secret", "1.1", 303), None)
    assert oidc.CallbackLogFilter().filter(record)
    assert "secret" not in record.getMessage()
