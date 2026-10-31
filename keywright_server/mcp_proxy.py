"""Upstream MCP servers. Resource config for kind=mcp:
  {"url": "https://.../mcp", "headers": {"Authorization": "Bearer ..."}}
Only Keywright holds the headers; agents see tools re-exported as <server>__<tool>."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import Any

import mcp_types as types
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from . import inventory_mcp, knowledge_mcp, mcp_oauth, omada

TOOL_CACHE_TTL = 60.0
SEP = "__"

_tool_cache: dict[str, tuple[float, list[types.Tool]]] = {}
_oauth_tool_generations: dict[str, tuple[str, str]] = {}


@asynccontextmanager
async def _client(config: dict[str, Any]):
    headers = dict(config.get("headers") or {})
    token = None
    if config.get("auth_type") == "oauth":
        token = await mcp_oauth.access_token(config)
        headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
        headers["Authorization"] = "Bearer " + token
    hc = create_mcp_http_client(headers=headers)
    if token:
        async def auth_response(response):
            if response.status_code == 401:
                await mcp_oauth.reject_token(config, token)
        hc.event_hooks["response"].append(auth_response)
    try:
        async with (
            hc,
            Client(streamable_http_client(config["url"], http_client=hc)) as client,
        ):
            yield client
    except Exception:
        if token:
            # HTTP/SDK exceptions may include provider bodies. Never put OAuth material in audit logs.
            raise mcp_oauth.ConnectionError("OAuth MCP request failed. Check the connection in the admin UI.") from None
        raise


async def list_tools(resource_name: str, config: dict[str, Any], *, force: bool = False) -> list[types.Tool]:
    if config.get("adapter") == "knowledge":
        return knowledge_mcp.list_tools()
    if config.get("adapter") == "keywright":
        return inventory_mcp.list_tools()
    if config.get("adapter") == "omada":
        return omada.list_tools()
    if config.get("auth_type") == "oauth":
        connection = await mcp_oauth.load(config)
        generation = (connection.id, connection.generation)
        if connection.status != "connected":
            forget(resource_name)
            raise mcp_oauth.ConnectionError("OAuth is not connected. Connect this resource in the admin UI.")
        if _oauth_tool_generations.get(resource_name) != generation:
            forget(resource_name)
            _oauth_tool_generations[resource_name] = generation
    hit = _tool_cache.get(resource_name)
    if hit and not force and time.monotonic() - hit[0] < TOOL_CACHE_TTL:
        return hit[1]
    async with _client(config) as c:
        res = await c.list_tools()
    _tool_cache[resource_name] = (time.monotonic(), list(res.tools))
    return list(res.tools)


async def call_tool(config: dict[str, Any], tool: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
    if config.get("adapter") in ("keywright", "knowledge"):
        raise ValueError("Internal inventory calls require the broker's gated transaction.")
    if config.get("adapter") == "omada":
        return await omada.call_tool(config, tool, arguments or {})
    async with _client(config) as c:
        return await c.call_tool(tool, arguments or {})


async def probe(config: dict[str, Any]) -> tuple[bool, str]:
    if config.get("adapter") == "knowledge":
        return True, "Built-in knowledge collection: search, get, list and propose."
    if config.get("adapter") == "keywright":
        return True, f"Built-in Keywright inventory: {len(inventory_mcp.list_tools())} tools available."
    if config.get("adapter") == "omada":
        return await omada.probe(config)
    try:
        async with _client(config) as c:
            res = await c.list_tools()
            name = (c.server_info.name if c.server_info else "server")
        return True, f"Connected to {name}: {len(res.tools)} tools ({', '.join(t.name for t in res.tools[:8])}...)"
    except Exception as e:  # noqa: BLE001
        return False, describe(e)


def describe(e: BaseException) -> str:
    """The SDK fails inside task groups; the wrapper says nothing ("unhandled errors in a TaskGroup"),
    the leaves say what went wrong (a 404 on a mistyped URL, a refused connection)."""
    leaves = _leaves(e)
    return "; ".join(dict.fromkeys(f"{type(x).__name__}: {x}" for x in leaves))[:500]


def _leaves(e: BaseException) -> list[BaseException]:
    if isinstance(e, BaseExceptionGroup):
        return [leaf for sub in e.exceptions for leaf in _leaves(sub)]
    return [e]


def export_name(resource_name: str, tool: str) -> str:
    return f"{resource_name}{SEP}{tool}"


def split_name(name: str) -> tuple[str, str] | None:
    if SEP not in name:
        return None
    a, b = name.split(SEP, 1)
    return (a, b) if a and b else None


def forget(resource_name: str) -> None:
    _tool_cache.pop(resource_name, None)
    _oauth_tool_generations.pop(resource_name, None)
