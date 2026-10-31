from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.routing import Route

from .. import __version__, approvals, llm_proxy, mail, nudges, tool_access
from ..config import settings
from ..db import init_db, session
from ..mcp_server import build_server, resolve_agent
from ..notify.manager import manager
from ..settings_store import warm
from . import (
    admin,
    discovery_ui,
    friction_ui,
    inventory_ui,
    knowledge_ui,
    mail_ui,
    mcp_oauth_ui,
    network_map_ui,
    oidc,
    usage_ui,
)
from .auth import password_is_set, set_password
from .security import BrowserSecurityHeaders

log = logging.getLogger("keywright")


class MCPAuthASGI:
    """Rejects MCP traffic that doesn't carry a valid agent bearer token, then hands off to the SDK."""

    def __init__(self, session_manager: StreamableHTTPSessionManager):
        self.sm = session_manager

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b""})
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        async with session() as db:
            agent = await resolve_agent(db, headers)
        if agent is None:
            # A JSON-RPC error body: MCP SDK clients surface its message instead of a generic
            # "server returned an error", so an agent learns it is the token that is wrong.
            resp = JSONResponse({"jsonrpc": "2.0", "id": None,
                                 "error": {"code": -32001, "message": "unauthorized: Authorization: Bearer <agent token>",
                                           "data": {"error": "unauthorized"}}},
                                status_code=401, headers={"WWW-Authenticate": "Bearer"})
            await resp(scope, receive, send)
            return
        # Give the SDK a principal so GET/POST/DELETE sessions cannot be shared across agents/tokens.
        scope = dict(scope)
        scope["user"] = AuthenticatedUser(AccessToken(
            token=agent.token_hash, client_id=agent.id + ":" + agent.token_hash, scopes=[],
        ))
        await self.sm.handle_request(scope, receive, send)


async def _janitor() -> None:
    while True:
        await asyncio.sleep(60)
        try:
            async with session() as db:
                n = await approvals.expire_stale(db)
                if n:
                    log.info("expired %d stale requests", n)
                n = await nudges.expire_stale(db)
                if n:
                    log.info("cleared %d nudges nobody answered", n)
        except Exception:
            log.exception("janitor failed")


TOOL_WATCH_S = 3600


async def _tool_watch() -> None:
    """Hourly: what each MCP server offers, against the baseline the owner accepted."""
    await asyncio.sleep(30)
    while True:
        try:
            async with session() as db:
                await tool_access.watch_once(db)
        except Exception:
            log.exception("tool watch failed")
        await asyncio.sleep(TOOL_WATCH_S)


def create_app() -> FastAPI:
    server = build_server()
    sm = StreamableHTTPSessionManager(
        app=server,
        security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        await init_db()
        async with session() as db:
            await warm(db)
            if settings.auth_mode != "oidc" and settings.admin_password and not password_is_set():
                await set_password(db, settings.admin_password)
                log.info("admin password seeded from KW_ADMIN_PASSWORD")
        await manager.reload()
        janitor = asyncio.create_task(_janitor(), name="janitor")
        watch = asyncio.create_task(_tool_watch(), name="tool-watch")
        mail_worker = asyncio.create_task(mail.worker(), name="mail-inbox")
        async with sm.run():
            log.info("Keywright listening; MCP at /mcp, admin at /ui")
            try:
                yield
            finally:
                janitor.cancel()
                watch.cancel()
                mail_worker.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await mail_worker
                await manager.stop()

    app = FastAPI(title="Keywright", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
    oidc.configure(app)
    app.add_middleware(BrowserSecurityHeaders)
    app.include_router(admin.router)
    app.include_router(oidc.router)
    app.include_router(mcp_oauth_ui.router)
    app.include_router(inventory_ui.router)
    app.include_router(knowledge_ui.router)
    app.include_router(network_map_ui.router)
    app.include_router(discovery_ui.router)
    app.include_router(usage_ui.router)
    app.include_router(friction_ui.router)
    app.include_router(mail_ui.router)
    app.include_router(admin.ws_router)
    app.include_router(llm_proxy.router)
    app.router.routes.append(Route("/mcp", endpoint=MCPAuthASGI(sm), methods=["GET", "POST", "DELETE"]))

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "notifier": manager.driver_id, "version": __version__}

    return app
