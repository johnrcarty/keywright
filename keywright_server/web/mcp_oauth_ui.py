"""Administrator consent for broker-owned upstream OAuth connections."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import audit, mcp_oauth, mcp_proxy
from ..db import session
from ..models import Resource
from . import auth
from .security import _origin, require_same_origin

router = APIRouter(dependencies=[Depends(require_same_origin), Depends(auth.require_admin)])
COOKIE = "kw_mcp_oauth_flow"
COOKIE_PATH = "/ui/mcp-oauth"


def failure(message: str):
    # Only fixed local ConnectionError messages, never provider responses.
    from html import escape
    response = HTMLResponse(
        '<!doctype html><title>Connect MCP</title><h1>Connection unsuccessful</h1>'
        f'<p>{escape(message)}</p><p><a href="/ui/resources">Return to resources</a></p>', status_code=400,
    )
    response.delete_cookie(COOKIE, path=COOKIE_PATH, secure=True, httponly=True, samesite="lax")
    return response


async def resource(rid: str) -> Resource:
    async with session() as db:
        res = await db.get(Resource, rid)
    if not res or res.kind != "mcp" or res.config.get("auth_type") != "oauth":
        raise mcp_oauth.ConnectionError("Save an HTTP MCP resource with OAuth authentication first.")
    return res


@router.post("/ui/mcp-oauth/{rid}/connect")
async def connect(request: Request, rid: str):
    try:
        res = await resource(rid)
        if _origin(str(request.url)) != _origin(mcp_oauth.callback_url()):
            raise mcp_oauth.ConnectionError("Open Keywright at its configured public HTTPS URL to connect OAuth.")
        browser = secrets.token_urlsafe(32)
        url = await mcp_oauth.begin(res.config, browser, request.cookies.get(auth.COOKIE, ""))
        mcp_proxy.forget(res.name)
    except mcp_oauth.ConnectionError as exc:
        return failure(str(exc))
    # A cross-origin redirect after a form POST is blocked by form-action 'self'
    # in browsers such as Safari and Chromium. Finish the POST with a page that
    # starts a fresh navigation, retaining our same-origin form policy.
    from .admin import render
    response = render(request, "mcp_oauth_continue.html", authorization_url=url,
                      resource_name=res.name, resource_id=res.id)
    response.set_cookie(COOKIE, browser, max_age=mcp_oauth.FLOW_TTL, path=COOKIE_PATH,
                        secure=True, httponly=True, samesite="lax")
    return response


@router.get(mcp_oauth.CALLBACK_PATH)
async def callback(request: Request):
    try:
        rid = await mcp_oauth.finish(request.query_params, request.cookies.get(COOKIE, ""),
                                     request.cookies.get(auth.COOKIE, ""))
        res = await resource(rid)
    except mcp_oauth.ConnectionError as exc:
        return failure(str(exc))
    mcp_proxy.forget(res.name)
    async with session() as db:
        await audit.record(db, tool="admin.mcp_oauth.connect", decision="allow", detail={"resource_id": rid})
    response = RedirectResponse(f"/ui/resources/{rid}", status_code=303)
    response.delete_cookie(COOKIE, path=COOKIE_PATH, secure=True, httponly=True, samesite="lax")
    return response


@router.post("/ui/mcp-oauth/{rid}/disconnect")
async def disconnect(request: Request, rid: str):
    try:
        res = await resource(rid)
        await mcp_oauth.disconnect(res.config)
    except mcp_oauth.ConnectionError as exc:
        return failure(str(exc))
    mcp_proxy.forget(res.name)
    async with session() as db:
        await audit.record(db, tool="admin.mcp_oauth.disconnect", decision="allow", detail={"resource_id": rid})
    return RedirectResponse(f"/ui/resources/{rid}", status_code=303)
