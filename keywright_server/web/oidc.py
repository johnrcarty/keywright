"""OIDC authorization code + PKCE login, with one-use flows and revocable local sessions."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
from datetime import timedelta
from urllib.parse import urlencode, urlsplit

import httpx2 as httpx
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from joserfc.errors import JoseError
from sqlalchemy import delete

from .. import audit
from ..config import settings
from ..db import session
from ..models import AdminLoginFlow, AdminSession, now
from . import auth
from .security import _origin, safe_redirect

router = APIRouter()
log = logging.getLogger("keywright.oidc")
FLOW_COOKIE = "kw_oidc_flow"
FLOW_PATH = "/ui/oidc"
FLOW_TTL = 300


class CallbackLogFilter(logging.Filter):
    """Uvicorn includes the query string in access logs; authorization codes stay out."""

    def filter(self, record):
        if isinstance(record.args, tuple) and len(record.args) == 5:
            address, method, target, version, status = record.args
            if isinstance(target, str) and target.split("?", 1)[0] in (
                "/ui/oidc/callback", "/ui/mcp-oauth/callback",
            ):
                record.args = (address, method, target.split("?", 1)[0], version, status)
        return True


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def config_key() -> str:
    return digest(json.dumps([settings.oidc_issuer, settings.oidc_client_id,
                              settings.oidc_client_secret, settings.oidc_admin_group,
                              settings.public_url, settings.oidc_session_ttl_s]))


def https_url(value: str) -> bool:
    try:
        url = urlsplit(value)
        return bool(url.scheme == "https" and url.hostname and url.port != 0
                    and not url.username and not url.password and not url.fragment
                    and not url.query and not any(c.isspace() for c in value))
    except ValueError:
        return False


def configure(app) -> None:
    access_log = logging.getLogger("uvicorn.access")
    if not any(isinstance(item, CallbackLogFilter) for item in access_log.filters):
        access_log.addFilter(CallbackLogFilter())
    if settings.auth_mode not in ("password", "both", "oidc"):
        raise ValueError("KW_AUTH_MODE must be password, both, or oidc")
    if not auth.oidc_enabled():
        app.state.oidc = None
        return
    if (not https_url(settings.oidc_issuer) or not https_url(settings.public_url)
            or urlsplit(settings.public_url).path not in ("", "/")):
        raise ValueError("OIDC requires an HTTPS KW_OIDC_ISSUER and an HTTPS origin in KW_PUBLIC_URL")
    if not all((settings.oidc_client_id, settings.oidc_client_secret, settings.oidc_admin_group)):
        raise ValueError("OIDC requires KW_OIDC_CLIENT_ID, KW_OIDC_CLIENT_SECRET, and KW_OIDC_ADMIN_GROUP")
    if not 300 <= settings.oidc_session_ttl_s <= 86400:
        raise ValueError("KW_OIDC_SESSION_TTL must be between 300 and 86400 seconds")
    # Authlib handles discovery, PKCE, code exchange, JWKS rotation and ID token validation.
    # Flow persistence is ours: no session middleware containing OAuth material in cookies.
    app.state.oidc = OAuth().register(
        "authentik", client_id=settings.oidc_client_id, client_secret=settings.oidc_client_secret,
        server_metadata_url=settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256",
                       "token_endpoint_auth_method": "client_secret_basic", "timeout": 10.0},
    )


def callback_url() -> str:
    # Fixed operator-configured origin, never derived from Host or forwarding headers.
    return settings.public_url.rstrip("/") + "/ui/oidc/callback"


async def provider(request: Request):
    if not auth.oidc_enabled():
        raise HTTPException(404)
    client = request.app.state.oidc
    metadata = await client.load_server_metadata()
    if metadata.get("issuer") != settings.oidc_issuer:
        raise ValueError("OIDC discovery issuer mismatch")
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not https_url(metadata.get(name, "")):
            raise ValueError("OIDC discovery requires HTTPS endpoints")
    # Only asymmetric ID token signatures, even if discovery advertises other algorithms.
    supported = metadata.get("id_token_signing_alg_values_supported", ["RS256"])
    algorithms = [alg for alg in supported if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")]
    if not algorithms:
        raise ValueError("OIDC provider has no supported signing algorithm")
    metadata["id_token_signing_alg_values_supported"] = algorithms
    return client


def failure(message: str, status: int = 400):
    # Deliberately do not reflect provider error strings, tokens, or exception messages.
    response = HTMLResponse(
        '<!doctype html><title>Keywright sign in</title><h1>Sign in unsuccessful</h1>'
        f'<p>{message}</p><p><a href="/ui/login?local=1">Return to sign in</a></p>', status_code=status,
    )
    response.delete_cookie(FLOW_COOKIE, path=FLOW_PATH, secure=True, httponly=True, samesite="lax")
    return response


@router.get("/ui/oidc/login")
async def login(request: Request, next: str = "/ui"):
    if not auth.oidc_enabled():
        raise HTTPException(404)
    if _origin(str(request.url)) != _origin(settings.public_url):
        # Aliases and direct LAN URLs must start on the callback's origin so its cookie arrives.
        return RedirectResponse(settings.public_url.rstrip("/") + "/ui/oidc/login?" +
                                urlencode({"next": safe_redirect(next)}), status_code=303)
    auth.limit_login(request)
    state, browser, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(4))
    try:
        client = await provider(request)
        result = await client.create_authorization_url(
            callback_url(), state=state, nonce=nonce, code_verifier=verifier,
        )
    except (httpx.HTTPError, OAuthError, ValueError, KeyError, TypeError) as exc:
        log.warning("OIDC login unavailable (%s)", type(exc).__name__)
        return failure("Authentik is unavailable. Try again shortly.", 503)
    async with session() as db:
        await db.execute(delete(AdminLoginFlow).where(AdminLoginFlow.expires_at <= now()))
        await db.execute(delete(AdminSession).where(AdminSession.expires_at <= now()))
        db.add(AdminLoginFlow(
            state_hash=digest(state), browser_hash=digest(browser), config_key=config_key(),
            data={"nonce": nonce, "verifier": verifier, "next": safe_redirect(next)},
            expires_at=now() + timedelta(seconds=FLOW_TTL),
        ))
        await db.commit()
    response = RedirectResponse(result["url"], status_code=302)
    response.set_cookie(FLOW_COOKIE, browser, max_age=FLOW_TTL, path=FLOW_PATH,
                        secure=True, httponly=True, samesite="lax")
    return response


@router.get("/ui/oidc/callback")
async def callback(request: Request):
    if not auth.oidc_enabled():
        raise HTTPException(404)
    state = request.query_params.get("state", "")
    browser = request.cookies.get(FLOW_COOKIE, "")
    if not state or not browser or len(state) > 256 or len(browser) > 256:
        return failure("Your sign-in attempt expired or could not be verified. Please start again.")
    # Atomic consumption prevents replay and concurrent exchanges, including across workers.
    async with session() as db:
        flow = (await db.execute(delete(AdminLoginFlow).where(
            AdminLoginFlow.state_hash == digest(state), AdminLoginFlow.browser_hash == digest(browser),
            AdminLoginFlow.config_key == config_key(), AdminLoginFlow.expires_at > now(),
        ).returning(AdminLoginFlow.data))).scalar_one_or_none()
        await db.commit()
    if flow is None:
        return failure("Your sign-in attempt expired or could not be verified. Please start again.")
    if request.query_params.get("error") or not request.query_params.get("code"):
        return failure("Sign in was cancelled or denied by Authentik.")
    try:
        client = await provider(request)
        token = await client.fetch_access_token(
            redirect_uri=callback_url(), code=request.query_params["code"], code_verifier=flow["verifier"],
        )
        claims = await client.parse_id_token(
            token, nonce=flow["nonce"], leeway=30,
            claims_options={"iss": {"essential": True, "value": settings.oidc_issuer}},
        )
        if not claims or not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise ValueError("Missing subject")
        groups = claims.get("groups")
        if not isinstance(groups, list) or settings.oidc_admin_group not in groups:
            return failure("Your Authentik account does not have Keywright administrator access.", 403)
    except (httpx.HTTPError, OAuthError, JoseError, ValueError, KeyError, TypeError) as exc:
        log.warning("OIDC callback rejected (%s)", type(exc).__name__)
        return failure("Authentik sign in could not be verified. Please start again.")
    identity = {"method": "oidc", "issuer": claims["iss"], "subject": claims["sub"],
                "name": str(claims.get("name") or claims.get("preferred_username") or claims["sub"])[:200]}
    raw = secrets.token_urlsafe(32)
    async with session() as db:
        await revoke_session(request, db)
        db.add(AdminSession(token_hash=digest(raw), config_key=config_key(), identity=identity,
                            expires_at=now() + timedelta(seconds=settings.oidc_session_ttl_s)))
        await audit.record(db, tool="admin.login", decision="allow", detail={"identity": identity})
    response = RedirectResponse(safe_redirect(flow["next"]), status_code=303)
    response.set_cookie(auth.COOKIE, "oidc:" + raw, max_age=settings.oidc_session_ttl_s,
                        secure=True, httponly=True, samesite="lax")
    response.delete_cookie(FLOW_COOKIE, path=FLOW_PATH, secure=True, httponly=True, samesite="lax")
    return response


async def session_identity(request) -> dict | None:
    raw = request.cookies.get(auth.COOKIE, "")
    if not raw.startswith("oidc:") or len(raw) > 256:
        return None
    async with session() as db:
        row = await db.get(AdminSession, digest(raw[5:]))
        if row and row.expires_at > now() and hmac.compare_digest(row.config_key, config_key()):
            return dict(row.identity)
    return None


async def revoke_session(request, db) -> None:
    raw = request.cookies.get(auth.COOKIE, "")
    if raw.startswith("oidc:") and len(raw) <= 256:
        await db.execute(delete(AdminSession).where(AdminSession.token_hash == digest(raw[5:])))


async def logout(request) -> None:
    async with session() as db:
        await revoke_session(request, db)
        await db.commit()
