"""Small, fixed-endpoint API adapters behind the broker's MCP approval boundary.

Adding a connector means declaring its setup and reviewed operations here. Agents
cannot supply URLs, headers or arbitrary API paths. No upstream SDK is required.
"""
from __future__ import annotations

import json
import re
import ssl
from dataclasses import dataclass
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import httpx
import mcp_types as types
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ConnectorError(ValueError):
    """Safe for agent results and audit records; excludes upstream bodies."""


class Empty(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Node(Empty):
    node: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")]


class Guest(Node):
    guest_type: Literal["qemu", "lxc"]
    vmid: int = Field(ge=100, le=999999999)


class Entity(Empty):
    entity_id: Annotated[str, Field(pattern=r"^[a-z0-9_]+\.[a-z0-9_]+$", max_length=255)]


class Page(Empty):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=250)


class AuthentikPage(Empty):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=25, ge=1, le=100)
    search: str | None = Field(default=None, min_length=1, max_length=200)


@dataclass(frozen=True)
class Operation:
    path: str
    description: str
    arguments: type[BaseModel] = Empty


@dataclass(frozen=True)
class Connector:
    title: str
    description: str
    instructions: str
    example_url: str
    secret_label: str
    operations: dict[str, Operation]
    keywords: str = ""


CONNECTORS = {
    "proxmox": Connector(
        "Proxmox VE", "Cluster nodes, virtual machines, containers, and storage.",
        "Create an API token in Datacenter → Permissions → API Tokens. Grant the user and token "
        "PVEAuditor on the paths to expose (propagate from / for cluster-wide inventory).",
        "https://pve.example:8006", "API token secret",
        {
            "proxmox_list_nodes": Operation("/api2/json/nodes", "List Proxmox cluster nodes."),
            "proxmox_list_resources": Operation("/api2/json/cluster/resources",
                                                "List visible guests, nodes and storage across the cluster."),
            "proxmox_get_node_status": Operation("/api2/json/nodes/{node}/status", "Read node status.", Node),
            "proxmox_get_guest_status": Operation("/api2/json/nodes/{node}/{guest_type}/{vmid}/status/current",
                                                  "Read VM or container status.", Guest),
        }, "virtualization vm lxc hypervisor storage"),
    "pihole": Connector(
        "Pi-hole", "DNS statistics, blocking status, and version information.",
        "Requires Pi-hole v6. Create an application password in Settings → Web interface / API. "
        "Use the server base address, without /admin or /api.",
        "https://pihole.example", "Application password",
        {
            "pihole_get_summary": Operation("/api/stats/summary", "Read Pi-hole DNS query and blocking statistics."),
            "pihole_get_blocking": Operation("/api/dns/blocking", "Read DNS blocking status."),
            "pihole_get_version": Operation("/api/info/version", "Read installed Pi-hole versions."),
        }, "dns adblock network"),
    "homeassistant": Connector(
        "Home Assistant", "Entity states and available services.",
        "Create a long-lived access token in your Home Assistant profile's Security tab. "
        "Use the server base address, without /api.",
        "https://ha.example:8123", "Long-lived access token",
        {
            "ha_check_api": Operation("/api/", "Check Home Assistant API availability."),
            "ha_list_states": Operation("/api/states", "List entity states."),
            "ha_get_state": Operation("/api/states/{entity_id}", "Read one entity's state.", Entity),
            "ha_list_services": Operation("/api/services", "List available service descriptions."),
        }, "automation smart home sensors lights"),
    "jellyfin": Connector(
        "Jellyfin", "Server information, libraries, and active playback sessions.",
        "Create an API key in Dashboard → API Keys. Include your configured base path, if any.",
        "https://jellyfin.example", "API key",
        {
            "jellyfin_get_system_info": Operation("/System/Info", "Read Jellyfin server information."),
            "jellyfin_list_libraries": Operation("/Library/VirtualFolders", "List configured media libraries."),
            "jellyfin_list_sessions": Operation("/Sessions", "List active playback sessions."),
        }, "media streaming movies music"),
    "authentik": Connector(
        "authentik", "Users, groups, applications, providers, and recent events.",
        "Create a dedicated service account, then create a token in Directory → Tokens and App passwords "
        "with intent API Token (not App password). Grant only the View permissions needed for users, groups, "
        "applications, providers, and events. Enter the server root address without /api/v3 or /if/admin.",
        "https://authentik.example", "Service account API token",
        {
            "authentik_get_current_user": Operation("/api/v3/core/users/me/",
                "Check the token's identity. Returns basic account fields; omits settings and credentials."),
            "authentik_list_users": Operation("/api/v3/core/users/",
                "List one page of visible users and group IDs. Omits custom attributes and nested objects.",
                AuthentikPage),
            "authentik_list_groups": Operation("/api/v3/core/groups/",
                "List one page of visible groups and member IDs. Omits custom attributes and nested objects.",
                AuthentikPage),
            "authentik_list_applications": Operation("/api/v3/core/applications/",
                "List one page of applications with provider IDs and policy mode. Omits nested provider details.",
                AuthentikPage),
            "authentik_list_providers": Operation("/api/v3/providers/all/",
                "List one page of provider names, types, application links, and flow IDs. Omits credentials.",
                AuthentikPage),
            "authentik_list_events": Operation("/api/v3/events/events/",
                "List one page of recent events, newest first. Returns action, time, app, and actor summary; "
                "omits raw event context and arbitrary payloads.", AuthentikPage),
        }, "identity sso authentication oauth oidc saml ldap access users groups"),
}
for _id, _title, _port, _collection in (
    ("sonarr", "Sonarr", 8989, "series"), ("radarr", "Radarr", 7878, "movie"),
):
    CONNECTORS[_id] = Connector(
        _title, f"{_title} status, health checks, library, and download queue.",
        "Copy the API key from Settings → General → Security. Include the configured URL Base, if any. "
        "Uses API v3.",
        f"https://{_id}.example:{_port}", "API key",
        {
            f"{_id}_get_status": Operation("/api/v3/system/status", f"Read {_title} system status."),
            f"{_id}_get_health": Operation("/api/v3/health", f"Read {_title} health checks."),
            f"{_id}_list_library": Operation(f"/api/v3/{_collection}", f"List {_title} library entries."),
            f"{_id}_list_queue": Operation("/api/v3/queue", f"Read one page of the {_title} download queue.", Page),
        }, "media downloads television movies arr")


def validate_config(config: dict[str, Any]) -> None:
    if config.get("adapter") not in CONNECTORS:
        raise ConnectorError("Unknown homelab connector.")
    url = config.get("url", "")
    try:
        parsed = urlsplit(url)
        valid = (parsed.scheme in ("http", "https") and parsed.hostname and parsed.port != 0
                 and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
                 and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url)
                 and "\\" not in url and "%" not in parsed.path
                 and all(p not in (".", "..") for p in parsed.path.split("/")))
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ConnectorError("Use an HTTP or HTTPS base address, without credentials, query or fragment.")
    if config["adapter"] in ("proxmox", "pihole", "homeassistant", "authentik") and parsed.path not in ("", "/"):
        raise ConnectorError("Use the server base address without an API or admin path.")
    if config["adapter"] == "proxmox":
        if parsed.scheme != "https":
            raise ConnectorError("Proxmox requires an HTTPS address.")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+![A-Za-z0-9_.-]+", config.get("token_id", "")):
            raise ConnectorError("Proxmox token ID must be user@realm!token-name.")
    secret = config.get("api_secret")
    if (not isinstance(secret, str) or not secret or secret == "***" or not secret.isascii()
            or any(ord(c) < 32 or ord(c) == 127 for c in secret)):
        raise ConnectorError("A valid connector credential is required.")
    if config["adapter"] == "jellyfin" and any(c in secret for c in ('"', "\\", ",")):
        raise ConnectorError("Jellyfin API keys cannot contain quotes, backslashes or commas.")
    if type(config.get("verify_tls", True)) is not bool:
        raise ConnectorError("TLS verification must be enabled or disabled explicitly.")


def list_tools(adapter: str) -> list[types.Tool]:
    return [types.Tool(name=name, description=op.description, input_schema=op.arguments.model_json_schema(),
                       annotations=types.ToolAnnotations(read_only_hint=True, destructive_hint=False,
                                                         idempotent_hint=True))
            for name, op in CONNECTORS[adapter].operations.items()]


MAX_RESPONSE_BYTES = 2 * 1024 * 1024


_AUTHENTIK_FIELDS = {
    "authentik_get_current_user": ("pk", "uid", "username", "name", "email", "is_active", "is_superuser", "type"),
    "authentik_list_users": ("pk", "uuid", "uid", "username", "name", "email", "is_active", "is_superuser",
                             "type", "groups", "last_login", "date_joined"),
    "authentik_list_groups": ("pk", "name", "is_superuser", "parents", "users", "children"),
    "authentik_list_applications": ("pk", "name", "slug", "provider", "backchannel_providers",
                                    "policy_engine_mode", "group", "meta_description", "meta_publisher"),
    "authentik_list_providers": ("pk", "name", "verbose_name", "meta_model_name", "assigned_application_slug",
                                "assigned_application_name", "authentication_flow", "authorization_flow",
                                "invalidation_flow"),
    "authentik_list_events": ("pk", "action", "app", "created", "expires", "client_ip"),
}


def _authentik_summary(result: Any, tool: str) -> dict:
    """Do not pass arbitrary identity attributes, provider secrets, or event context to agents."""
    def pick(row, fields):
        if not isinstance(row, dict):
            raise ConnectorError("authentik returned an unexpected response shape; check the API version.")
        scalar = (str, int, float, bool, type(None))
        return {key: value for key, value in row.items() if key in fields
                and (type(value) in scalar or (isinstance(value, list)
                     and all(type(item) in scalar for item in value)))}

    if not isinstance(result, dict):
        raise ConnectorError("authentik returned an unexpected response shape; check the API version.")
    if tool == "authentik_get_current_user":
        return {"user": pick(result.get("user"), _AUTHENTIK_FIELDS[tool])}
    if not isinstance(result.get("results"), list) or not isinstance(result.get("pagination"), dict):
        raise ConnectorError("authentik returned an unexpected response shape; check the API version.")
    rows = []
    for row in result["results"]:
        summary = pick(row, _AUTHENTIK_FIELDS[tool])
        if tool == "authentik_list_events" and isinstance(row.get("user"), dict):
            summary["user"] = pick(row["user"], ("pk", "username"))
        rows.append(summary)
    pagination = {key: value for key, value in result["pagination"].items()
                  if key in ("next", "previous", "count", "current", "total_pages", "start_index", "end_index")
                  and (value is None or (type(value) is int and value >= 0))}
    return {"pagination": pagination, "results": rows}


async def _json(client: httpx.AsyncClient, method: str, url: str, **kwargs) -> Any:
    async with client.stream(method, url, **kwargs) as response:
        if not response.is_success:
            raise ConnectorError(f"Connector returned HTTP {response.status_code}; check credentials, "
                                 "permissions and the configured address.")
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ConnectorError("Connector response exceeds 2 MiB; narrow the request or use a smaller page.")
    try:
        return json.loads(body)
    except ValueError:
        raise ConnectorError("Connector returned invalid JSON; check the address and API version.") from None


async def request(config: dict[str, Any], tool: str, arguments: dict[str, Any]) -> Any:
    validate_config(config)
    adapter = config["adapter"]
    op = CONNECTORS[adapter].operations.get(tool)
    if op is None:
        raise ConnectorError("Unknown tool for this connector.")
    try:
        args = op.arguments.model_validate(arguments)
    except ValidationError:
        raise ConnectorError("Invalid connector arguments; use the tool schema.") from None
    verify: bool | ssl.SSLContext = config.get("verify_tls", True)
    if verify and config.get("ca_bundle"):
        try:
            verify = ssl.create_default_context(cafile=config["ca_bundle"])
        except (OSError, ssl.SSLError):
            raise ConnectorError("Could not load the configured CA certificate bundle.") from None
    base, secret = config["url"].rstrip("/"), config["api_secret"]
    headers = {}
    if adapter == "proxmox":
        headers["Authorization"] = f"PVEAPIToken={config['token_id']}={secret}"
    elif adapter in ("homeassistant", "authentik"):
        headers["Authorization"] = f"Bearer {secret}"
    elif adapter == "jellyfin":
        headers["Authorization"] = f'MediaBrowser Token="{secret}"'
    elif adapter in ("sonarr", "radarr"):
        headers["X-Api-Key"] = secret
    params = {"page": args.page, "pageSize": args.page_size} if isinstance(args, Page) else {}
    if isinstance(args, AuthentikPage):
        params = args.model_dump(exclude_none=True)
        params["ordering"] = "-created" if tool == "authentik_list_events" else "pk"
    sid = None
    try:
        async with httpx.AsyncClient(verify=verify, timeout=30, follow_redirects=False, trust_env=False) as client:
            if adapter == "pihole":
                auth = await _json(client, "POST", base + "/api/auth", json={"password": secret})
                session = auth.get("session") if isinstance(auth, dict) else None
                sid = session.get("sid") if isinstance(session, dict) else None
                if (not isinstance(sid, str) or not sid or not sid.isascii()
                        or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in sid)
                        or session.get("valid") is not True):
                    raise ConnectorError("Pi-hole authentication failed; use a v6 application password.")
                headers["X-FTL-SID"] = sid
            try:
                result = await _json(client, "GET", base + op.path.format(**args.model_dump()),
                                     headers=headers, params=params)
            finally:
                if sid:
                    # Release this call's session, including on API errors; do not exhaust Pi-hole's slots.
                    try:
                        await client.delete(base + "/api/auth", headers=headers)
                    except httpx.HTTPError:
                        pass
    except httpx.HTTPError:
        raise ConnectorError("Could not reach the connector API; check connectivity and TLS settings.") from None
    if adapter == "proxmox":
        if not isinstance(result, dict) or "data" not in result:
            raise ConnectorError("Proxmox response is missing its data field.")
        result = result["data"]
    if adapter == "authentik":
        result = _authentik_summary(result, tool)
    # Defense against an upstream reflecting the authentication value into a successful response.
    def redact(value):
        if isinstance(value, str):
            for credential in (secret, sid):
                if credential:
                    value = value.replace(credential, "[redacted]")
        elif isinstance(value, list):
            return [redact(item) for item in value]
        elif isinstance(value, dict):
            return {redact(key): redact(item) for key, item in value.items()}
        return value

    return redact(result)


async def call_tool(config: dict[str, Any], tool: str, arguments: dict[str, Any]) -> types.CallToolResult:
    try:
        result = await request(config, tool, arguments)
    except ConnectorError as e:
        return types.CallToolResult(is_error=True, content=[types.TextContent(type="text", text=str(e))])
    return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result))])


async def probe(config: dict[str, Any]) -> tuple[bool, str]:
    try:
        validate_config(config)
        connector = CONNECTORS[config["adapter"]]
        await request(config, next(iter(connector.operations)), {})
    except ConnectorError as e:
        return False, str(e)
    return True, f"Connected to {connector.title}; {len(connector.operations)} read-only tools available."
