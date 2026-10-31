"""Exercise real discovery, PKCE and signed ID token validation against a mocked provider."""
import hashlib
import logging
import time
from base64 import urlsafe_b64encode
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import httpx2
import pytest
import respx
import websockets
from joserfc import jwt
from joserfc.jwk import RSAKey
from sqlalchemy import select

from keywright_server.config import settings
from keywright_server.models import AdminLoginFlow, AdminSession, now
from keywright_server.web import auth, oidc
from keywright_server.web.app import create_app

ISSUER = "https://auth.test/application/o/keywright/"
ORIGIN = "https://kw.test"


@pytest.fixture
def oidc_settings(monkeypatch):
    for name, value in {
        "auth_mode": "both", "oidc_issuer": ISSUER, "public_url": ORIGIN,
        "oidc_client_id": "keywright", "oidc_client_secret": "test-client-secret",
        "oidc_admin_group": "keywright-admins", "oidc_session_ttl_s": 3600,
    }.items():
        monkeypatch.setattr(settings, name, value)
    auth._login_attempts.clear()
    auth._global_attempts.clear()
    yield
    auth._login_attempts.clear()
    auth._global_attempts.clear()


@pytest.fixture(scope="module")
def signing_key():
    return RSAKey.generate_key(2048, parameters={"kid": "test-key"})


@pytest.fixture
async def browser(db, oidc_settings, signing_key):
    await auth.set_password(db, "adminpass123")
    state = {"claims": {}, "token_calls": 0}
    metadata = {"issuer": ISSUER, "authorization_endpoint": "https://auth.test/authorize",
                "token_endpoint": "https://auth.test/token", "jwks_uri": "https://auth.test/jwks",
                "id_token_signing_alg_values_supported": ["RS256"]}

    def exchange(request):
        state["token_calls"] += 1
        form = parse_qs(request.content.decode())
        assert form["redirect_uri"] == [ORIGIN + "/ui/oidc/callback"]
        assert form["grant_type"] == ["authorization_code"]
        challenge = urlsafe_b64encode(hashlib.sha256(form["code_verifier"][0].encode()).digest()).rstrip(b"=").decode()
        assert challenge == state["authorize"]["code_challenge"][0]
        assert request.headers["authorization"].startswith("Basic ")
        claims = {"iss": ISSUER, "sub": "user-123", "aud": "keywright", "iat": int(time.time()),
                  "exp": int(time.time()) + 300, "nonce": state["authorize"]["nonce"][0],
                  "groups": ["keywright-admins"], "name": "Test Admin"}
        claims.update(state["claims"])
        for name in state.get("omit", []):
            claims.pop(name, None)
        body = {"access_token": "opaque-access-token", "token_type": "Bearer",
                "id_token": jwt.encode({"alg": "RS256", "kid": "test-key"}, claims,
                                       state.get("signing_key", signing_key))}
        if state.get("no_id_token"):
            body.pop("id_token")
        return httpx.Response(200, json=body)

    with respx.mock(assert_all_called=False) as mock:
        mock.get(ISSUER + ".well-known/openid-configuration").respond(200, json=metadata)
        mock.get("https://auth.test/jwks").respond(200, json={"keys": [signing_key.as_dict(private=False)]})
        mock.post("https://auth.test/token").mock(side_effect=exchange)
        async def provider_transport(request):
            response = await mock.async_handler(httpx.Request(
                request.method, str(request.url), headers=dict(request.headers), content=request.content,
            ))
            return httpx2.Response(response.status_code, headers=dict(response.headers), content=response.content)

        app = create_app()
        app.state.oidc.client_kwargs["transport"] = httpx2.MockTransport(provider_transport)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
            yield client, state, mock


async def begin(client, state, next="/ui"):
    response = await client.get("/ui/oidc/login", params={"next": next})
    assert response.status_code == 302
    params = parse_qs(urlsplit(response.headers["location"]).query)
    assert params["code_challenge_method"] == ["S256"]
    assert params["scope"] == ["openid profile email"]
    state["authorize"] = params
    return params["state"][0]


async def finish(client, state, next="/ui"):
    value = await begin(client, state, next)
    return await client.get("/ui/oidc/callback", params={"state": value, "code": "one-use-code"})


async def test_login_identity_revocation_and_replay(browser, db):
    client, state, _ = browser
    response = await finish(client, state, "/ui/requests")
    assert response.status_code == 303 and response.headers["location"] == "/ui/requests"
    raw = client.cookies.get(auth.COOKIE)
    assert raw.startswith("oidc:") and "Test Admin" not in raw
    assert all(flag in response.headers["set-cookie"] for flag in ("Secure", "HttpOnly", "SameSite=lax"))
    row = (await db.execute(select(AdminSession))).scalar_one()
    assert row.identity == {"method": "oidc", "issuer": ISSUER, "subject": "user-123", "name": "Test Admin"}
    assert row.token_hash == oidc.digest(raw[5:])
    assert (await client.get("/ui/live")).status_code == 200
    replay = await client.get("/ui/oidc/callback", params={"state": state["authorize"]["state"][0], "code": "again"})
    assert replay.status_code == 400 and state["token_calls"] == 1
    assert (await client.post("/ui/logout", headers={"Origin": ORIGIN})).status_code == 303
    client.cookies.set(auth.COOKIE, raw)
    assert (await client.get("/ui/live")).status_code == 303
    assert (await client.get("/ui/login?logged_out=1")).status_code == 200


@pytest.mark.parametrize("claims,omit,status", [
    ({"iss": "https://evil.test/"}, [], 400), ({"aud": "other-client"}, [], 400),
    ({"nonce": "wrong"}, [], 400), ({"exp": int(time.time()) - 3600}, [], 400),
    ({"iat": int(time.time()) + 3600}, [], 400), ({}, ["sub"], 400),
    ({}, ["nonce"], 400), ({}, ["exp"], 400),
    ({"groups": []}, [], 403), ({"groups": "keywright-admins"}, [], 403),
    ({}, ["groups"], 403), ({"groups": ["other-admins"]}, [], 403),
])
async def test_invalid_claims_and_unauthorized_users(browser, claims, omit, status):
    client, state, _ = browser
    state.update(claims=claims, omit=omit)
    assert (await finish(client, state)).status_code == status
    assert not client.cookies.get(auth.COOKIE)
    assert (await client.get("/ui/live")).status_code == 303


async def test_bad_signature_and_missing_id_token(browser):
    client, state, _ = browser
    state["signing_key"] = RSAKey.generate_key(2048)
    assert (await finish(client, state)).status_code == 400
    state["no_id_token"] = True
    assert (await finish(client, state)).status_code == 400


async def test_state_is_bound_to_browser_and_consumed_once(browser):
    client, state, _ = browser
    value = await begin(client, state)
    cookie = client.cookies.get(oidc.FLOW_COOKIE)
    client.cookies.clear()
    assert (await client.get("/ui/oidc/callback", params={"state": value, "code": "stolen"})).status_code == 400
    assert state["token_calls"] == 0
    client.cookies.set(oidc.FLOW_COOKIE, cookie)
    assert (await client.get("/ui/oidc/callback", params={"state": "wrong", "code": "bad"})).status_code == 400
    assert state["token_calls"] == 0
    client.cookies.set(oidc.FLOW_COOKIE, cookie)
    assert (await client.get("/ui/oidc/callback", params={"state": value, "error": "access_denied"})).status_code == 400
    client.cookies.set(oidc.FLOW_COOKIE, cookie)
    assert (await client.get("/ui/oidc/callback", params={"state": value, "code": "replay"})).status_code == 400
    assert state["token_calls"] == 0


async def test_flow_expiry(browser, db):
    client, state, _ = browser
    value = await begin(client, state)
    row = await db.get(AdminLoginFlow, oidc.digest(value))
    row.expires_at = now() - timedelta(seconds=1)
    await db.commit()
    assert (await client.get("/ui/oidc/callback", params={"state": value, "code": "expired"})).status_code == 400
    assert state["token_calls"] == 0


async def test_session_expiry_and_config_change(browser, db, monkeypatch):
    client, state, _ = browser
    await finish(client, state)
    monkeypatch.setattr(settings, "oidc_admin_group", "changed")
    assert (await client.get("/ui/live")).status_code == 303
    monkeypatch.setattr(settings, "oidc_admin_group", "keywright-admins")
    row = (await db.execute(select(AdminSession))).scalar_one()
    row.expires_at = now() - timedelta(seconds=1)
    await db.commit()
    assert (await client.get("/ui/live")).status_code == 303


async def test_password_fallback_and_sso_only_mode(browser, monkeypatch):
    client, state, _ = browser
    assert (await client.get("/ui/login")).headers["location"].startswith("/ui/oidc/login?")
    page = await client.get("/ui/login?local=1")
    assert 'name="password"' in page.text and "Sign in with Authentik" in page.text
    response = await client.post("/ui/login", data={"password": "adminpass123"}, headers={"Origin": ORIGIN})
    assert response.status_code == 303
    assert (await client.get("/ui/live")).status_code == 200
    monkeypatch.setattr(settings, "auth_mode", "oidc")
    assert (await client.get("/ui/live")).status_code == 303  # old password cookie is rejected
    assert (await client.post("/ui/login", data={"password": "adminpass123"}, headers={"Origin": ORIGIN})).status_code == 403
    assert 'name="password"' not in (await client.get("/ui/login?local=1")).text
    assert (await client.get("/ui/setup")).status_code == 303
    assert (await client.post("/ui/setup", data={"password": "newpassword", "repeat": "newpassword"},
                              headers={"Origin": ORIGIN})).status_code == 303
    from keywright_server import settings_store

    settings_store._cache.pop("admin", None)
    assert (await finish(client, state)).status_code == 303
    assert (await client.get("/ui/live")).status_code == 200  # no local password required


async def test_provider_outage_does_not_hide_password_fallback(browser):
    client, _, mock = browser
    mock.get(ISSUER + ".well-known/openid-configuration").respond(503)
    response = await client.get("/ui/oidc/login")
    assert response.status_code == 503
    assert (await client.get("/ui/login?local=1")).status_code == 200


async def test_discovery_issuer_mismatch(browser):
    client, _, mock = browser
    mock.get(ISSUER + ".well-known/openid-configuration").respond(200, json={"issuer": "https://wrong.test/"})
    assert (await client.get("/ui/oidc/login")).status_code == 503


async def test_alias_and_lan_login_start_on_callback_origin(browser):
    client, _, _ = browser
    for url in ("http://192.0.2.41:8700", "https://gatekeeper.test"):
        response = await client.get(url + "/ui/oidc/login", params={"next": "/ui/requests"})
        assert response.status_code == 303
        assert response.headers["location"] == ORIGIN + "/ui/oidc/login?next=%2Fui%2Frequests"


@pytest.mark.parametrize("next", ["https://evil.test", "//evil.test", "/%2fevil.test", "/\\evil.test"])
async def test_return_url_is_local(browser, next):
    client, state, _ = browser
    assert (await finish(client, state, next)).headers["location"] == "/ui"


async def test_browser_sso_cannot_authorize_agent_api(browser):
    client, state, _ = browser
    await finish(client, state)
    assert (await client.post("/mcp", json={})).status_code == 401
    assert (await client.post("/ui/logout")).status_code == 403


async def test_websocket_session_revoked_after_logout(browser, live_server, monkeypatch):
    from keywright_server.web import admin

    monkeypatch.setattr(admin, "HEARTBEAT_S", 0.02)
    client, state, _ = browser
    await finish(client, state)
    headers = {"Cookie": f"{auth.COOKIE}={client.cookies.get(auth.COOKIE)}", "Origin": live_server}
    async with websockets.connect(live_server.replace("http://", "ws://") + "/ui/events",
                                  additional_headers=headers) as ws:
        assert '"type":"hello"' in await ws.recv()
        await client.post("/ui/logout", headers={"Origin": ORIGIN})
        with pytest.raises(websockets.ConnectionClosedError) as error:
            while True:
                await ws.recv()
        assert error.value.rcvd.code == 1008


@pytest.mark.parametrize("name,value", [
    ("auth_mode", "typo"), ("oidc_client_secret", ""), ("oidc_admin_group", ""),
    ("oidc_issuer", "http://auth.test/"), ("public_url", "http://kw.test"),
    ("public_url", "https://kw.test/subpath"), ("oidc_session_ttl_s", 0),
])
def test_configuration_fails_closed(oidc_settings, monkeypatch, name, value):
    monkeypatch.setattr(settings, name, value)
    with pytest.raises(ValueError):
        create_app()


def test_callback_access_log_hides_authorization_code():
    record = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %s',
                               ("127.0.0.1", "GET", "/ui/oidc/callback?code=secret&state=secret", "1.1", 303), None)
    assert oidc.CallbackLogFilter().filter(record)
    assert "secret" not in record.getMessage()
