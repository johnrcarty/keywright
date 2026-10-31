"""Omada Open API tools, exposed through the existing MCP approval boundary.

Only the broker sees client credentials and access tokens. Endpoints are fixed:
tool arguments cannot select an origin, API path, HTTP method, or auth headers.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import time
from collections import OrderedDict
from typing import Annotated, Any
from urllib.parse import urlsplit

import httpx
import mcp_types as types
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class OmadaError(ValueError):
    """Safe to display or audit; never includes controller response bodies."""


Identifier = Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9_-]{1,128}$")]


class Page(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=100, ge=1, le=1000)


class SitePage(Page):
    site_id: Identifier


class APDetails(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    site_id: Identifier
    ap_mac: Annotated[str, Field(strict=True, pattern=r"^[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}$")]


OPERATIONS = {
    "omada_list_sites": (Page, "sites", "List accessible Omada sites, one page at a time."),
    "omada_list_devices": (SitePage, "sites/{site_id}/devices",
                           "List devices (including routers), status and inventory in an Omada site."),
    "omada_get_ap": (APDetails, "sites/{site_id}/aps/{ap_mac}",
                     "Read AP details, including its reported wireless mesh uplink."),
    "omada_list_clients": (SitePage, "sites/{site_id}/clients",
                           "List clients in an Omada site, one page at a time."),
}

# Short-lived bearer tokens stay in memory. The fingerprint includes the connection
# and credentials, so editing a resource never reuses the previous identity's token.
_tokens: OrderedDict[str, tuple[float, str]] = OrderedDict()


def validate_config(config: dict[str, Any]) -> None:
    url = config.get("url", "")
    try:
        parsed = urlsplit(url)
        valid = (parsed.scheme == "https" and parsed.hostname and parsed.port != 0
                 and not parsed.username and not parsed.password
                 and parsed.path in ("", "/") and not parsed.query and not parsed.fragment
                 and not any(c.isspace() for c in url) and "\\" not in url)
    except ValueError:
        valid = False
    if not valid:
        raise OmadaError("Use the HTTPS Interface Access Address, including its port, without an API path.")
    for key, label in (("omada_id", "Omada ID"), ("client_id", "Client ID")):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", config.get(key, "")):
            raise OmadaError(f"{label} must contain only letters, numbers, underscores and hyphens.")
    if not config.get("client_secret") or config["client_secret"] == "***":
        raise OmadaError("An Omada Client Secret is required.")
    if not isinstance(config.get("verify_tls", True), bool):
        raise OmadaError("TLS verification must be enabled or disabled explicitly.")


def list_tools() -> list[types.Tool]:
    return [types.Tool(name=name, description=description, input_schema=model.model_json_schema(),
                       annotations=types.ToolAnnotations(read_only_hint=True, destructive_hint=False,
                                                         idempotent_hint=True))
            for name, (model, _, description) in OPERATIONS.items()]


def _result(response: httpx.Response) -> Any:
    if not response.is_success:
        raise OmadaError(f"Omada returned HTTP {response.status_code}; check the address and app permissions.")
    try:
        payload = response.json()
    except ValueError:
        raise OmadaError("Omada returned invalid JSON; check the Interface Access Address.") from None
    if not isinstance(payload, dict) or type(payload.get("errorCode")) is not int:
        raise OmadaError("Omada returned an unexpected API response.")
    if payload["errorCode"] != 0:
        raise OmadaError(f"Omada API error {payload['errorCode']}; check app credentials, site privileges "
                         "and controller API compatibility.")
    if "result" not in payload:
        raise OmadaError("Omada response is missing its result.")
    return payload["result"]


async def _token(client: httpx.AsyncClient, config: dict[str, Any], key: str) -> str:
    cached = _tokens.get(key)
    if cached and time.monotonic() < cached[0]:
        _tokens.move_to_end(key)
        return cached[1]
    result = _result(await client.post(config["url"].rstrip("/") + "/openapi/authorize/token",
                                      params={"grant_type": "client_credentials"},
                                      json={"omadacId": config["omada_id"], "client_id": config["client_id"],
                                            "client_secret": config["client_secret"]}))
    if not isinstance(result, dict):
        raise OmadaError("Omada returned an invalid token response.")
    token, expires = result.get("accessToken"), result.get("expiresIn")
    if (not isinstance(token, str) or not token or not token.isascii()
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in token)
            or type(expires) is not int or expires <= 0):
        raise OmadaError("Omada returned an invalid access token or expiry.")
    _tokens[key] = (time.monotonic() + max(0, min(expires, 7200) - 30), token)
    _tokens.move_to_end(key)
    while len(_tokens) > 128:
        _tokens.popitem(last=False)
    return token


async def request(config: dict[str, Any], tool: str, arguments: dict[str, Any]) -> Any:
    if tool not in OPERATIONS:
        raise OmadaError("Unknown Omada tool.")
    model, path, _ = OPERATIONS[tool]
    try:
        args = model.model_validate(arguments)
    except ValidationError:
        raise OmadaError("Invalid Omada arguments; use the tool schema.") from None
    validate_config(config)
    verify: bool | ssl.SSLContext = config.get("verify_tls", True)
    if verify and config.get("ca_bundle"):
        try:
            verify = ssl.create_default_context(cafile=config["ca_bundle"])
        except (OSError, ssl.SSLError):
            raise OmadaError("Could not load the configured Omada CA certificate bundle.") from None
    key = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    path_args = args.model_dump()
    if isinstance(args, APDetails):
        path_args["ap_mac"] = args.ap_mac.replace(":", "-").upper()
    params = {"page": args.page, "pageSize": args.page_size} if isinstance(args, Page) else {}
    url = (config["url"].rstrip("/") + "/openapi/v1/" + config["omada_id"] + "/"
           + path.format(**path_args))
    try:
        async with httpx.AsyncClient(verify=verify, timeout=30, follow_redirects=False, trust_env=False) as client:
            for attempt in range(2):
                token = await _token(client, config, key)
                response = await client.get(url, params=params,
                                            headers={"Authorization": f"AccessToken={token}"})
                if response.status_code == 401:
                    _tokens.pop(key, None)
                    if attempt == 0:
                        continue
                return _result(response)
    except httpx.HTTPError:
        raise OmadaError("Could not reach the Omada API; check connectivity and TLS certificate settings.") from None


async def call_tool(config: dict[str, Any], tool: str, arguments: dict[str, Any]) -> types.CallToolResult:
    try:
        result = await request(config, tool, arguments)
    except OmadaError as e:
        return types.CallToolResult(is_error=True, content=[types.TextContent(type="text", text=str(e))])
    return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result))])


async def probe(config: dict[str, Any]) -> tuple[bool, str]:
    try:
        await request(config, "omada_list_sites", {"page_size": 1})
    except OmadaError as e:
        return False, str(e)
    return True, "Connected to Omada Open API; site listing succeeded."
