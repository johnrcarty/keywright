"""Browser request boundaries and response headers for the admin UI."""
from __future__ import annotations

from urllib.parse import unquote, urlsplit

from fastapi import HTTPException, Request
from starlette.datastructures import MutableHeaders


def _origin(value: str) -> tuple[str, str, int] | None:
    try:
        url = urlsplit(value)
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password:
            return None
        return url.scheme, url.hostname.lower(), url.port or (443 if url.scheme == "https" else 80)
    except ValueError:
        return None


async def require_same_origin(request: Request) -> None:
    """All browser mutations need a matching Origin or Referer; absence fails closed.

    Native scripts using admin cookies must supply Origin explicitly. MCP uses bearer auth
    through its own ASGI route and does not use browser cookies or this dependency.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    source = request.headers.get("origin") or request.headers.get("referer")
    if request.headers.get("sec-fetch-site") in ("cross-site", "same-site"):
        raise HTTPException(403, "Cross-origin form submission rejected")
    if not source or _origin(source) is None or _origin(source) != _origin(str(request.url)):
        raise HTTPException(403, "A same-origin Origin or Referer header is required")


def websocket_same_origin(origin: str | None, url: str) -> bool:
    """A websocket handshake carries the admin cookie but never passes through require_same_origin,
    which only sees HTTP methods. Browsers always send Origin on a websocket, so a missing or
    mismatched one fails closed. ws:// and wss:// are normalised to the scheme they upgrade from,
    because that is what the browser puts in Origin."""
    scheme, _, rest = url.partition("://")
    upgraded = {"ws": "http", "wss": "https"}.get(scheme, scheme) + "://" + rest
    return bool(origin) and _origin(origin) is not None and _origin(origin) == _origin(upgraded)


def safe_redirect(value: str) -> str:
    decoded = unquote(value)
    if (not decoded.startswith("/") or decoded.startswith("//") or "\\" in decoded
            or any(ord(c) < 32 for c in decoded)):
        return "/ui"
    return value


class BrowserSecurityHeaders:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def secure_send(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "same-origin"
                headers["Content-Security-Policy"] = "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
                if scope["path"].startswith(("/ui", "/d/", "/enroll/", "/api/work")):
                    headers["Cache-Control"] = "no-store"
                if scope.get("scheme") == "https":
                    message["headers"] = [
                        (key, value + b"; Secure" if key.lower() == b"set-cookie" and b"; secure" not in value.lower()
                         else value) for key, value in message["headers"]
                    ]
            await send(message)

        await self.app(scope, receive, secure_send)
