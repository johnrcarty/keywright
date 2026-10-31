"""One MCP call to Keywright's own /mcp endpoint.

The SDK runs in a disposable child so a stuck handshake, DNS resolver or SDK cleanup cannot
hold the CLI open indefinitely. The child inherits the caller's sandbox; this grants no access.
Credentials and arguments travel over stdin, never command-line arguments or temporary files.
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Callable
from typing import Any

from . import __version__
from .config import Profile

CONNECT_TIMEOUT = 15.0
CLEANUP_TIMEOUT = 1.0
RESPONSE_GRACE = 30.0
NETWORK_HINT = ("check the broker URL, DNS, proxy and network access; if your agent sandbox blocks "
                "the broker, request narrowly scoped execution permission (see `kw guide`)")


class TransportError(Exception):
    """Could not complete the exchange: network, TLS, timeout, or a non-MCP HTTP failure."""


class AuthError(TransportError):
    """The server rejected the token."""


def _headers(profile: Profile, session: str | None) -> dict[str, str]:
    h = {"Authorization": f"Bearer {profile.token}", "User-Agent": f"keywright/{__version__}"}
    if session:
        h["X-Keywright-Session"] = session
    return h


async def _call(profile: Profile, session: str | None, tool: str, arguments: dict[str, Any],
                read_timeout: float, emit: Callable):
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    timeout = httpx2.Timeout(connect=10.0, read=read_timeout + 30.0, write=30.0, pool=10.0)
    try:
        async with (httpx2.AsyncClient(headers=_headers(profile, session), timeout=timeout) as http,
                    Client(streamable_http_client(profile.mcp_url, http_client=http)) as c):
            emit("ready", None)
            if tool == "tools/list":
                result = await c.list_tools()
            else:
                result = await c.call_tool(tool, arguments)
            # Deliver a confirmed result before SDK shutdown: cleanup failure must not turn a
            # completed mutation into an uncertain outcome that a caller might repeat.
            emit("result", result.model_dump(mode="json"))
    except Exception as e:
        leaves = _leaves(e)
        text = "; ".join(f"{type(x).__name__}: {x}" for x in leaves)[:400]
        if any(_is_401(x) for x in leaves) or (
                "Server returned an error response" in text and await _rejects_token(profile, session)):
            raise AuthError("broker rejected the token") from e
        # Exception messages can contain credential-bearing URLs and request data.
        kinds = ", ".join(sorted({type(x).__name__ for x in leaves}))
        raise TransportError(f"{kinds}; {NETWORK_HINT}") from e


async def _rejects_token(profile: Profile, session: str | None) -> bool:
    """Older servers answer 401 with a body the SDK cannot surface; one cheap POST tells them apart."""
    import httpx2

    try:
        async with httpx2.AsyncClient(headers=_headers(profile, session), timeout=10.0) as http:
            r = await http.post(profile.mcp_url, json={"jsonrpc": "2.0", "id": 0, "method": "ping"},
                                headers={"Accept": "application/json, text/event-stream"})
        return r.status_code == 401
    except Exception:  # noqa: BLE001 - a probe failure just means "not a 401 we can prove"
        return False


def _leaves(e: BaseException) -> list[BaseException]:
    """The SDK raises ExceptionGroups from its task groups; the useful error is a leaf."""
    if isinstance(e, BaseExceptionGroup):
        return [leaf for sub in e.exceptions for leaf in _leaves(sub)]
    return [e]


def _is_401(e: BaseException) -> bool:
    response = getattr(e, "response", None)
    if response is not None and getattr(response, "status_code", None) == 401:
        return True
    text = str(e).lower()
    return "401" in text or "unauthorized" in text


def call(profile: Profile, session: str | None, tool: str, arguments: dict[str, Any] | None = None, *,
         read_timeout: float = 60.0):
    """Run one tool call; returns the SDK CallToolResult."""
    return asyncio.run(acall(profile, session, tool, arguments, read_timeout=read_timeout))


async def acall(profile: Profile, session: str | None, tool: str, arguments: dict[str, Any] | None = None, *,
                read_timeout: float = 60.0):
    """One exchange, with separate handshake and operation deadlines; never retries a call."""
    from mcp import types

    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "keywright._transport_worker",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, limit=64 * 1024 * 1024,
        )
    except OSError as e:
        raise TransportError(f"cannot start broker worker ({type(e).__name__})") from None
    phase = "broker handshake"
    budget = CONNECT_TIMEOUT
    try:
        async with asyncio.timeout(budget):
            request = {"profile": {"name": profile.name, "url": profile.url, "token": profile.token},
                       "session": session, "tool": tool, "arguments": arguments or {},
                       "read_timeout": read_timeout}
            process.stdin.write(json.dumps(request).encode())
            await process.stdin.drain()
            process.stdin.close()
            kind, data = await _message(process)
        if kind == "ready":
            phase = "broker response"
            budget = read_timeout + RESPONSE_GRACE
            async with asyncio.timeout(budget):
                kind, data = await _message(process)
        if kind == "auth":
            raise AuthError(data)
        if kind == "error":
            raise TransportError(data)
        if kind != "result":
            raise TransportError("unexpected broker worker response")
        model = types.ListToolsResult if tool == "tools/list" else types.CallToolResult
        return model.model_validate(data)
    except TimeoutError:
        raise TransportError(f"{phase} timed out after {budget:g}s; {NETWORK_HINT}") from None
    except (OSError, ValueError) as e:
        raise TransportError(f"broker worker failed ({type(e).__name__}); {NETWORK_HINT}") from None
    finally:
        try:
            await asyncio.wait_for(process.wait(), timeout=CLEANUP_TIMEOUT)
        except TimeoutError:
            # SIGKILL also stops resolver threads and cancellation-resistant SDK cleanup.
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()


async def _message(process):
    line = await process.stdout.readline()
    if not line:
        raise TransportError(f"broker worker stopped without a result; {NETWORK_HINT}")
    return json.loads(line)


def list_tools(profile: Profile, session: str | None):
    return call(profile, session, "tools/list", read_timeout=30.0).tools


def payload(result) -> dict[str, Any]:
    """The structured payload of a result, falling back to its first text block."""
    if getattr(result, "structured_content", None):
        return dict(result.structured_content)
    for block in result.content or []:
        text = getattr(block, "text", None)
        if text:
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    return data
            except ValueError:
                pass
            return {"text": text}
    return {}
