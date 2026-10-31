"""Reusable authorization-code + PKCE connections for HTTP MCP resources.

Authlib handles OAuth requests; MCP SDK helpers implement discovery conventions.
Only an administrator can start consent. Tool calls can refresh but never start a
browser flow or replay an upstream operation. Credentials are encrypted separately
from resource config and refresh rotation uses a database lease across workers.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import time
from datetime import timedelta
from urllib.parse import urlsplit

import httpx2 as httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client, OAuthError
from cryptography.fernet import Fernet, InvalidToken
from mcp.client.auth.oauth2 import PKCEParameters, check_registration_usable
from mcp.client.auth.utils import (
    build_oauth_authorization_server_metadata_discovery_urls,
    build_protected_resource_metadata_discovery_urls,
    extract_resource_metadata_from_www_auth,
    extract_scope_from_www_auth,
)
from mcp.shared.auth import OAuthClientInformationFull
from mcp.shared.auth_utils import check_resource_allowed
from sqlalchemy import delete, or_, update

from .config import settings
from .db import session
from .models import MCPOAuthConnection, MCPOAuthFlow, new_id, now

CALLBACK_PATH = "/ui/mcp-oauth/callback"
FLOW_TTL = 600
AUTH_METHODS = ("none", "client_secret_basic", "client_secret_post")


class ConnectionError(ValueError):
    """Messages are fixed text safe for the UI, audit log, and agent context."""


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def cipher() -> Fernet:
    key = hashlib.sha256(b"keywright:mcp-oauth:v1\0" + settings.secret_key()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def seal(data: dict) -> str:
    return cipher().encrypt(json.dumps(data).encode()).decode()


def unseal(value: str) -> dict:
    try:
        return json.loads(cipher().decrypt(value.encode()))
    except (InvalidToken, ValueError):
        raise ConnectionError("OAuth credentials cannot be opened. Save the settings and reconnect this resource.") from None


def origin(value: str) -> str:
    try:
        url = urlsplit(value)
        if (url.scheme != "https" or not url.hostname or url.username or url.password
                or url.fragment or url.port == 0 or any(c.isspace() for c in value)):
            raise ValueError
        return f"https://{url.netloc.lower()}"
    except (ValueError, TypeError):
        raise ConnectionError("OAuth URLs must use HTTPS without credentials or fragments.") from None


def callback_url() -> str:
    value = settings.public_url.rstrip("/")
    if origin(value) != value or urlsplit(value).query:
        raise ConnectionError("Set KW_PUBLIC_URL to Keywright's public HTTPS origin before connecting OAuth.")
    return value + CALLBACK_PATH


def config_key(config: dict) -> str:
    return digest(json.dumps([config["url"], config.get("oauth", {}), settings.public_url], sort_keys=True))


def checked_url(value: str, config: dict) -> str:
    allowed = {origin(config["url"]), *config.get("oauth", {}).get("origins", [])}
    if origin(value) not in allowed:
        raise ConnectionError("The provider uses another OAuth origin. Add it under Additional OAuth origins.")
    return value


async def configure(db, resource, config: dict, *, secret: str = "") -> None:
    """Called inside the resource save transaction. Changes invalidate credentials and flows."""
    previous = resource.config or {}
    old_id = previous.get("oauth_id")
    row = await db.get(MCPOAuthConnection, old_id) if old_id else None
    if config.get("auth_type") != "oauth":
        if row:
            await db.execute(delete(MCPOAuthFlow).where(MCPOAuthFlow.connection_id == row.id))
            await db.delete(row)
        config.pop("oauth_id", None)
        config.pop("oauth", None)
        return
    origin(config["url"])
    opts = config["oauth"]
    for item in opts["origins"]:
        if origin(item) != item or urlsplit(item).query:
            raise ConnectionError("Additional OAuth origins must be HTTPS origins without paths.")
    method = opts["token_endpoint_auth_method"]
    if method not in AUTH_METHODS:
        raise ConnectionError("Unsupported OAuth client authentication method.")
    unreadable = False
    try:
        old_data = unseal(row.sealed_data) if row else {}
    except ConnectionError:
        old_data, unreadable = {}, True
    client_secret = old_data.get("client_secret", "") if secret in ("", "***") else secret
    if method != "none" and (not opts["client_id"] or not client_secret):
        raise ConnectionError("This authentication method requires a registered client ID and secret.")
    changed = (row is None or unreadable or row.config_key != config_key(config)
               or client_secret != old_data.get("client_secret", ""))
    if changed:
        if row:
            await db.execute(delete(MCPOAuthFlow).where(MCPOAuthFlow.connection_id == row.id))
            await db.delete(row)
            await db.flush()
        await db.flush()
        row = MCPOAuthConnection(resource_id=resource.id, config_key=config_key(config),
                                 sealed_data=seal({"client_secret": client_secret}))
        db.add(row)
        await db.flush()
    config["oauth_id"] = row.id


async def load(config: dict) -> MCPOAuthConnection:
    async with session() as db:
        row = await db.get(MCPOAuthConnection, config.get("oauth_id", ""))
    if row is None or row.config_key != config_key(config):
        raise ConnectionError("OAuth settings changed. Save and reconnect this resource.")
    return row


async def status(config: dict) -> str:
    try:
        return (await load(config)).status
    except ConnectionError:
        return "disconnected"


async def get_json(client, url: str, config: dict) -> dict | None:
    response = await client.get(checked_url(url, config))
    if response.status_code in (404, 405):
        return None
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict):
        raise ConnectionError("OAuth provider returned invalid metadata.")
    return value


async def discover(config: dict) -> dict:
    """Discovery sends no configured headers or tokens and never follows redirects.

    Discovered network destinations must belong to an origin the admin configured.
    This permits internal providers without trusting arbitrary metadata URLs.
    """
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        response = await client.get(checked_url(config["url"], config))
        hint = extract_resource_metadata_from_www_auth(response)
        scope = extract_scope_from_www_auth(response)
        resource = None
        for url in dict.fromkeys(build_protected_resource_metadata_discovery_urls(hint, config["url"])):
            resource = await get_json(client, url, config)
            if resource:
                break
        if not resource or not isinstance(resource.get("resource"), str):
            raise ConnectionError("The server did not publish OAuth protected-resource metadata.")
        if not check_resource_allowed(config["url"], resource["resource"]):
            raise ConnectionError("OAuth metadata does not match this MCP resource.")
        issuers = resource.get("authorization_servers")
        if not isinstance(issuers, list) or not issuers:
            raise ConnectionError("The server did not advertise an OAuth authorization server.")
        issuer = checked_url(issuers[0], config)
        metadata = None
        for url in build_oauth_authorization_server_metadata_discovery_urls(issuer, config["url"]):
            metadata = await get_json(client, url, config)
            if metadata:
                break
        if not metadata or metadata.get("issuer") != issuer:
            raise ConnectionError("OAuth discovery issuer mismatch.")
        for field in ("authorization_endpoint", "token_endpoint"):
            checked_url(metadata.get(field, ""), config)
        for field in ("registration_endpoint", "revocation_endpoint"):
            if metadata.get(field):
                checked_url(metadata[field], config)
        if "S256" not in metadata.get("code_challenge_methods_supported", []):
            raise ConnectionError("The OAuth provider must support PKCE with S256.")
        scope = config["oauth"].get("scope") or scope or " ".join(resource.get("scopes_supported", []))
        return {"metadata": metadata, "scope": scope, "resource": resource["resource"]}


def oauth_client(data: dict) -> AsyncOAuth2Client:
    info = data["client"]
    return AsyncOAuth2Client(
        client_id=info["client_id"], client_secret=info.get("client_secret"),
        token_endpoint_auth_method=info.get("token_endpoint_auth_method", "none"),
        redirect_uri=callback_url(), scope=data.get("scope") or None,
        code_challenge_method="S256", timeout=15, follow_redirects=False,
    )


async def begin(config: dict, browser: str, admin: str) -> str:
    row = await load(config)
    data = unseal(row.sealed_data)
    try:
        discovered = await discover(config)
        opts = config["oauth"]
        info = data.get("client") if data.get("metadata", {}).get("issuer") == discovered["metadata"]["issuer"] else None
        if opts.get("client_id"):
            info = {"client_id": opts["client_id"], "client_secret": data.get("client_secret", ""),
                    "token_endpoint_auth_method": opts["token_endpoint_auth_method"]}
        if not info:
            endpoint = discovered["metadata"].get("registration_endpoint")
            if not endpoint:
                raise ConnectionError("This provider requires a pre-registered OAuth client ID.")
            async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
                response = await client.post(checked_url(endpoint, config), json={
                    "client_name": "Keywright", "redirect_uris": [callback_url()],
                    "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                })
                response.raise_for_status()
                registration = OAuthClientInformationFull.model_validate(response.json())
                check_registration_usable(registration)
                if callback_url() not in [str(u) for u in registration.redirect_uris or []]:
                    raise ConnectionError("OAuth registration returned a different callback URL.")
                info = registration.model_dump(mode="json", exclude_none=True)
        data.update(discovered, client=info)
        data.pop("token", None)
        state = secrets.token_urlsafe(32)
        pkce = PKCEParameters.generate()
        async with oauth_client(data) as client:
            url, _ = client.create_authorization_url(
                data["metadata"]["authorization_endpoint"], state=state,
                code_verifier=pkce.code_verifier, resource=data["resource"],
            )
    except ConnectionError:
        raise
    except Exception:  # noqa: BLE001 - provider errors must not expose credentials
        raise ConnectionError("OAuth discovery or registration failed. Check the provider and client settings.") from None
    generation = new_id("gen")
    async with session() as db:
        changed = await db.execute(update(MCPOAuthConnection).where(
            MCPOAuthConnection.id == row.id, MCPOAuthConnection.generation == row.generation,
        ).values(generation=generation, sealed_data=seal(data), status="connecting", lease_owner=None, lease_until=None))
        if changed.rowcount != 1:
            raise ConnectionError("OAuth connection changed. Start connecting again.")
        await db.execute(delete(MCPOAuthFlow).where(or_(
            MCPOAuthFlow.connection_id == row.id, MCPOAuthFlow.expires_at <= now(),
        )))
        db.add(MCPOAuthFlow(state_hash=digest(state), connection_id=row.id, generation=generation,
                           browser_hash=digest(browser), admin_hash=digest(admin),
                           sealed_data=seal({"verifier": pkce.code_verifier, "redirect_uri": callback_url()}),
                           expires_at=now() + timedelta(seconds=FLOW_TTL)))
        await db.commit()
    return url


def normalize_token(token: dict, previous: dict | None = None) -> dict:
    if (not isinstance(token.get("access_token"), str) or not token["access_token"]
            or token.get("token_type", "").lower() != "bearer"):
        raise ConnectionError("OAuth provider did not return a usable bearer token.")
    result = {k: v for k, v in token.items() if k in
              ("access_token", "refresh_token", "token_type", "scope", "expires_at", "expires_in")}
    if previous and "refresh_token" not in result:
        result["refresh_token"] = previous.get("refresh_token")
    if "expires_in" in result:
        result["expires_at"] = time.time() + float(result["expires_in"])
    return result


async def finish(params, browser: str, admin: str) -> str:
    state = params.get("state", "")
    if not state or len(state) > 256 or not browser or not admin:
        raise ConnectionError("OAuth attempt expired or could not be verified. Connect again.")
    async with session() as db:
        flow = (await db.execute(delete(MCPOAuthFlow).where(
            MCPOAuthFlow.state_hash == digest(state), MCPOAuthFlow.browser_hash == digest(browser),
            MCPOAuthFlow.admin_hash == digest(admin), MCPOAuthFlow.expires_at > now(),
        ).returning(MCPOAuthFlow))).scalar_one_or_none()
        await db.commit()
        row = await db.get(MCPOAuthConnection, flow.connection_id) if flow else None
    if not row or row.generation != flow.generation:
        raise ConnectionError("OAuth attempt expired or could not be verified. Connect again.")
    from .models import Resource
    async with session() as db:
        resource = await db.get(Resource, row.resource_id)
    if not resource or row.config_key != config_key(resource.config):
        raise ConnectionError("OAuth settings changed. Save and reconnect this resource.")
    data = unseal(row.sealed_data)
    flow_data = unseal(flow.sealed_data)
    metadata = data["metadata"]
    try:
        if params.get("error") or not params.get("code"):
            raise ConnectionError("OAuth authorization was cancelled or denied. Connect again.")
        if (params.get("iss") is not None and params["iss"] != metadata["issuer"]
                or metadata.get("authorization_response_iss_parameter_supported") and not params.get("iss")):
            raise ConnectionError("OAuth callback issuer mismatch.")
        async with oauth_client(data) as client:
            token = await client.fetch_token(
                metadata["token_endpoint"], grant_type="authorization_code", code=params["code"],
                code_verifier=flow_data["verifier"], redirect_uri=flow_data["redirect_uri"], resource=data["resource"],
            )
        data["token"] = normalize_token(token)
        async with session() as db:
            result = await db.execute(update(MCPOAuthConnection).where(
                MCPOAuthConnection.id == row.id, MCPOAuthConnection.generation == flow.generation,
            ).values(sealed_data=seal(data), status="connected"))
            await db.commit()
        if result.rowcount != 1:
            raise ConnectionError("OAuth connection changed. Connect again.")
    except Exception as exc:
        await mark_reconnect(row.id, row.generation)
        if isinstance(exc, ConnectionError):
            raise
        raise ConnectionError("OAuth token exchange failed. Connect again.") from None
    return row.resource_id


async def mark_reconnect(connection_id: str, generation: str) -> None:
    async with session() as db:
        await db.execute(update(MCPOAuthConnection).where(
            MCPOAuthConnection.id == connection_id, MCPOAuthConnection.generation == generation,
        ).values(status="needs_reconnect"))
        await db.commit()


async def disconnect(config: dict) -> None:
    row = await load(config)
    data = unseal(row.sealed_data)
    data.pop("token", None)
    async with session() as db:
        await db.execute(update(MCPOAuthConnection).where(MCPOAuthConnection.id == row.id).values(
            generation=new_id("gen"), sealed_data=seal(data), status="disconnected", lease_owner=None, lease_until=None,
        ))
        await db.execute(delete(MCPOAuthFlow).where(MCPOAuthFlow.connection_id == row.id))
        await db.commit()


async def access_token(config: dict) -> str:
    """Refresh before expiry; a DB lease prevents rotating a refresh token twice."""
    deadline = time.monotonic() + 20
    while True:
        row = await load(config)
        if row.status != "connected":
            raise ConnectionError("OAuth is not connected. Connect this resource in the admin UI.")
        data = unseal(row.sealed_data)
        token = data.get("token", {})
        if token.get("access_token") and (not token.get("expires_at") or token["expires_at"] > time.time() + 60):
            return token["access_token"]
        if not token.get("refresh_token"):
            await mark_reconnect(row.id, row.generation)
            raise ConnectionError("OAuth authorization expired. Reconnect this resource.")
        owner = new_id("refresh")
        async with session() as db:
            result = await db.execute(update(MCPOAuthConnection).where(
                MCPOAuthConnection.id == row.id, MCPOAuthConnection.generation == row.generation,
                MCPOAuthConnection.sealed_data == row.sealed_data, MCPOAuthConnection.status == "connected",
                or_(MCPOAuthConnection.lease_until.is_(None), MCPOAuthConnection.lease_until < now()),
            ).values(lease_owner=owner, lease_until=now() + timedelta(seconds=60)))
            await db.commit()
        if result.rowcount:
            break
        if time.monotonic() > deadline:
            raise ConnectionError("OAuth refresh is busy. Try again shortly.")
        await asyncio.sleep(0.1)
    try:
        async with oauth_client(data) as client:
            fresh = await client.refresh_token(data["metadata"]["token_endpoint"],
                                               refresh_token=token["refresh_token"], resource=data["resource"])
        data["token"] = normalize_token(fresh, token)
        async with session() as db:
            result = await db.execute(update(MCPOAuthConnection).where(
                MCPOAuthConnection.id == row.id, MCPOAuthConnection.generation == row.generation,
                MCPOAuthConnection.lease_owner == owner,
            ).values(sealed_data=seal(data)))
            await db.commit()
        if result.rowcount != 1:
            raise ConnectionError("OAuth connection changed during refresh. Connect again.")
        return data["token"]["access_token"]
    except OAuthError as exc:
        if exc.error in ("invalid_grant", "invalid_client", "unauthorized_client"):
            await mark_reconnect(row.id, row.generation)
        raise ConnectionError("OAuth refresh failed. Check the connection in the admin UI.") from None
    except ConnectionError:
        raise
    except Exception:  # noqa: BLE001 - provider errors must not expose credentials
        raise ConnectionError("OAuth provider is unavailable. Try again shortly.") from None
    finally:
        async with session() as db:
            await db.execute(update(MCPOAuthConnection).where(
                MCPOAuthConnection.id == row.id, MCPOAuthConnection.lease_owner == owner,
            ).values(lease_owner=None, lease_until=None))
            await db.commit()


async def reject_token(config: dict, rejected: str) -> None:
    """Invalidate only the rejected token; never replay a potentially mutating MCP request."""
    row = await load(config)
    data = unseal(row.sealed_data)
    token = data.get("token", {})
    if token.get("access_token") != rejected:
        return
    token["expires_at"] = 1
    async with session() as db:
        await db.execute(update(MCPOAuthConnection).where(
            MCPOAuthConnection.id == row.id, MCPOAuthConnection.sealed_data == row.sealed_data,
        ).values(sealed_data=seal(data)))
        await db.commit()
