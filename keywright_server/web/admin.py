"""Admin UI: server-rendered pages, plain forms, no JS dependencies."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import os
import secrets
import shlex
from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from keywright.hazards import SEVERITIES
from keywright.hazards import blocks as hazard_blocks
from keywright.patterns import validate
from sqlalchemy import String, cast, desc, func, or_, select
from starlette.concurrency import run_in_threadpool

from .. import (
    access_view,
    approvals,
    audit,
    bundles,
    events,
    homelab,
    integrations,
    inventory,
    inventory_mcp,
    knowledge,
    llm,
    mcp_oauth,
    mcp_proxy,
    nudges,
    omada,
    policy_preview,
    result_inspection,
    semantic,
    ssh,
    tool_access,
)
from ..access import (
    binds_exactly,
    constraint_label,
    hazard_level,
    hazards_of,
    operation_detail,
    operations,
    path_scoped,
)
from ..config import settings
from ..db import session
from ..mcp_server import hash_token
from ..models import AccessRequest, Agent, AuditEvent, Grant, Nudge, Policy, Resource, now
from ..notify.base import operation_line, registry
from ..notify.manager import DEFAULT_BUTTONS, manager
from ..settings_store import get as get_setting
from ..settings_store import put as put_setting
from . import auth, mcp_oauth_ui, oidc
from .security import require_same_origin, safe_redirect, websocket_same_origin

log = logging.getLogger("keywright.ui")

router = APIRouter(dependencies=[Depends(require_same_origin)])
# Websockets never carry a method require_same_origin could check, so they live on their own
# router and do the origin check themselves.
ws_router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.filters["shellquote"] = shlex.quote
templates.env.filters["redact"] = audit._scrub
templates.env.globals.update(scope_labels=approvals.SCOPE_LABELS, scopes=approvals.SCOPES,
                             bundles_text=bundles.format_text, operation_detail=operation_detail,
                             operations=operations, binds_exactly=binds_exactly, path_scoped=path_scoped,
                             constraint_label=constraint_label, remaining=access_view.remaining,
                             decision_label=approvals.decision_label, hazards_of=hazards_of,
                             hazard_level=hazard_level, hazard_blocks=hazard_blocks,
                             operation_line=operation_line, jev_line=semantic.describe,
                             jev_effect_words=semantic.EFFECT_WORDS,
                             session_cap_minutes=settings.session_grant_ttl_s // 60)


def render(request: Request, name: str, **ctx: Any) -> HTMLResponse:
    flash = request.cookies.get("kw_flash")
    resp = templates.TemplateResponse(request, name, {"request": request, "flash": flash, "now": now(), **ctx})
    if flash:
        resp.delete_cookie("kw_flash")
    return resp


def redirect(url: str, flash: str | None = None) -> RedirectResponse:
    resp = RedirectResponse(safe_redirect(url), status_code=303)
    if flash:
        resp.set_cookie("kw_flash", flash[:500], max_age=30, httponly=True, samesite="lax")
    return resp


# ---- auth pages ---------------------------------------------------------------------------------
@router.get("/", include_in_schema=False)
async def root():
    return RedirectResponse("/ui", status_code=302)


@router.get("/ui/setup", response_class=HTMLResponse)
async def setup_get(request: Request):
    if auth.password_is_set() or auth.oidc_enabled():
        return redirect("/ui/login")
    return render(request, "setup.html")


@router.post("/ui/setup")
async def setup_post(request: Request, password: str = Form(...), repeat: str = Form(...)):
    if auth.password_is_set() or auth.oidc_enabled():
        return redirect("/ui/login")
    if not 8 <= len(password) <= 1024 or password != repeat:
        return render(request, "setup.html", error="Passwords must match and be at least 8 characters.")
    async with session() as db:
        await auth.set_password(db, password)
    return auth.login_response("/ui")


@router.get("/ui/login", response_class=HTMLResponse)
async def login_get(request: Request, next: str = "/ui", local: bool = False, logged_out: bool = False):
    if await auth.authenticated(request):
        return redirect(next)
    if auth.oidc_enabled() and not local and not logged_out:
        from urllib.parse import urlencode

        return redirect("/ui/oidc/login?" + urlencode({"next": safe_redirect(next)}))
    if not auth.password_is_set() and not auth.oidc_enabled():
        return redirect("/ui/setup")
    return render(request, "login.html", next=safe_redirect(next), oidc_enabled=auth.oidc_enabled(),
                  password_enabled=settings.auth_mode != "oidc" and auth.password_is_set(), logged_out=logged_out)


@router.post("/ui/login")
async def login_post(request: Request, password: str = Form(...), next: str = Form("/ui")):
    if settings.auth_mode == "oidc":
        return oidc.failure("Password login is disabled. Sign in with Authentik.", 403)
    address = auth.limit_login(request)
    if await run_in_threadpool(auth.check_password, password):
        auth.login_succeeded(address)
        return auth.login_response(next if next.startswith("/") else "/ui")
    return render(request, "login.html", next=next, error="Wrong password.",
                  oidc_enabled=auth.oidc_enabled(), password_enabled=True)


@router.post("/ui/logout")
async def logout(request: Request):
    await oidc.logout(request)
    return auth.logout_response("/ui/login?logged_out=1")


# ---- dashboard & requests -----------------------------------------------------------------------
def _proposal_query():
    return (select(knowledge.Revision, knowledge.Document, Resource, Agent.name.label("agent_name"))
            .select_from(knowledge.Revision)
            .join(knowledge.Document, knowledge.Document.id == knowledge.Revision.document_id)
            .join(Resource, Resource.id == knowledge.Document.resource_id)
            .outerjoin(Agent, Agent.id == knowledge.Revision.proposed_by)
            .where(knowledge.Revision.status == "pending", Resource.kind == "mcp",
                   Resource.config["adapter"].as_string() == "knowledge"))


async def _pending_proposals(db, revision_id: str | None = None) -> list[dict[str, Any]]:
    query = _proposal_query().order_by(desc(knowledge.Revision.created_at))
    if revision_id is not None:
        query = query.where(knowledge.Revision.id == revision_id)
    return [{"revision": rev, "document": doc, "collection": res, "agent_name": agent_name}
            for rev, doc, res, agent_name in (await db.execute(query)).all()]


async def _waiting(db) -> dict[str, Any]:
    """What is waiting on the human right now: the live region of the dashboard."""
    pending = (await db.execute(
        select(AccessRequest).where(AccessRequest.status == "pending").order_by(desc(AccessRequest.created_at))
    )).scalars().all()
    return {"pending": list(pending), "proposals": await _pending_proposals(db),
            "nudges": await nudges.open_nudges(db)}


async def _counts(db) -> dict[str, int]:
    """The numbers on the stat tiles, cheap enough to recompute on every live event."""
    at = now()
    # Deliberately the same condition as _waiting: a request whose clock has run out but which the
    # janitor has not swept yet is still a tile on the page, so it is still a number on the tile.
    pending = await db.scalar(select(func.count()).select_from(AccessRequest).where(
        AccessRequest.status == "pending"))
    proposals = await db.scalar(select(func.count()).select_from(_proposal_query().subquery()))
    waiting = await db.scalar(select(func.count()).select_from(Nudge).where(Nudge.cleared_at.is_(None)))
    grants = (await db.execute(select(Grant).where(
        Grant.revoked_at.is_(None),
        (Grant.expires_at.is_(None)) | (Grant.expires_at > at),
        (Grant.uses_remaining.is_(None)) | (Grant.uses_remaining > 0),
    ))).scalars().all()
    # Grants from one approval are one lease to a human, exactly as the access overview groups them.
    leases = {(g.agent_id, g.request_id or g.id) for g in grants if g.is_active(at, g.session_id)}
    return {"pending": (pending or 0) + (proposals or 0), "nudges": waiting or 0, "leases": len(leases)}


@router.get("/ui", response_class=HTMLResponse, dependencies=[Depends(auth.require_admin)])
async def dashboard(request: Request):
    async with session() as db:
        await approvals.expire_stale(db)
        await nudges.expire_stale(db)
        waiting = await _waiting(db)
        access = await access_view.overview(db)
        recent = (await db.execute(select(AuditEvent).order_by(desc(AuditEvent.id)).limit(15))).scalars().all()
        drifted = [r for r in (await db.execute(select(Resource).where(Resource.kind == "mcp"))).scalars().all()
                   if r.config.get("tools_drift")]
    return render(request, "dashboard.html", recent=recent, notifier=manager, drifted=drifted, **waiting, **access)


@router.post("/ui/nudges/{nid}/dismiss", dependencies=[Depends(auth.require_admin)])
async def nudge_dismiss(nid: str, next: str = Form("/ui")):
    async with session() as db:
        nudge = await nudges.clear(db, nid, via="ui")
    if nudge is None:
        return redirect(next, "No such request for attention.")
    return redirect(next, f"Cleared: {nudge.agent.name} is no longer shown as waiting on you.")


# ---- live dashboard -----------------------------------------------------------------------------
def _render(name: str, **ctx: Any) -> str:
    """Render a partial outside any HTTP request, for delivery over the websocket. Partials used
    this way must not touch `request` or `flash`."""
    return templates.get_template(name).render(now=now(), **ctx)


async def _live_payload(db, event: dict[str, Any]) -> dict[str, Any] | None:
    """Turn a fact from the event hub into something a dashboard can apply. Markup is built here,
    not in the approval path, so the two stay independent and Jinja stays in the web layer."""
    kind = event["type"]
    if kind == "resync":
        return {**event, **await _live_state(db)}
    counts = await _counts(db)
    if kind == "knowledge.proposed":
        proposals = await _pending_proposals(db, event["id"])
        if not proposals:
            return None  # already reviewed or removed before this event was rendered
        return {**event, "counts": counts, "html": _render("_knowledge_card.html", proposal=proposals[0])}
    if kind == "request.created":
        req = await db.get(AccessRequest, event["id"])
        if req is None or req.status != "pending":
            return None  # decided or expired between the publish and here; its own event follows
        return {**event, "counts": counts, "html": _render("_request_card.html", req=req)}
    if kind == "nudge.created":
        nudge = await db.get(Nudge, event["id"])
        if nudge is None or not nudge.open:
            return None
        return {**event, "counts": counts, "html": _render("_nudge_card.html", n=nudge)}
    return {**event, "counts": counts}


async def _live_state(db) -> dict[str, Any]:
    return {"counts": await _counts(db), "html": _render("_live.html", **await _waiting(db))}


@router.get("/ui/live", response_class=JSONResponse, dependencies=[Depends(auth.require_admin)])
async def live_state(request: Request):
    """The whole live region, for a dashboard that has just reconnected or fallen behind."""
    async with session() as db:
        return JSONResponse({"type": "resync", **await _live_state(db)})


@ws_router.websocket("/ui/events")
async def live_events(ws: WebSocket) -> None:
    """One socket per open dashboard: new requests appear, decided ones resolve, including when the
    decision came from a phone. Read-only - nothing a browser sends here changes anything."""
    if not websocket_same_origin(ws.headers.get("origin"), str(ws.url)):
        log.warning("rejected dashboard websocket from origin %r", ws.headers.get("origin"))
        return await ws.close(code=1008)
    if not await auth.authenticated(ws):
        return await ws.close(code=1008)
    await ws.accept()
    async with events.subscribe() as subscriber:
        async with session() as db:
            await ws.send_json({"type": "hello", "counts": await _counts(db)})
        closed = asyncio.create_task(_until_closed(ws))
        pending: asyncio.Task | None = None
        try:
            while not closed.done():
                pending = asyncio.ensure_future(subscriber.get())
                done, _ = await asyncio.wait({closed, pending}, timeout=HEARTBEAT_S,
                                             return_when=asyncio.FIRST_COMPLETED)
                if closed in done:
                    break
                if not await auth.authenticated(ws):
                    await ws.close(code=1008)
                    break
                if pending not in done:
                    pending.cancel()
                    await ws.send_json({"type": "ping"})  # keeps idle proxies from closing us
                    continue
                async with session() as db:
                    payload = await _live_payload(db, pending.result())
                if payload is not None:
                    await ws.send_json(payload)
        except (WebSocketDisconnect, RuntimeError, ConnectionError):
            pass
        finally:
            closed.cancel()
            if pending is not None:
                pending.cancel()
            with contextlib.suppress(Exception):
                await ws.close()


HEARTBEAT_S = 25


async def _until_closed(ws: WebSocket) -> None:
    """Completes when the browser goes away. A dashboard sends nothing, so anything it does send
    is discarded."""
    with contextlib.suppress(Exception):
        while True:
            if (await ws.receive())["type"] == "websocket.disconnect":
                return


@router.get("/ui/requests", response_class=HTMLResponse, dependencies=[Depends(auth.require_admin)])
async def requests_list(request: Request):
    async with session() as db:
        rows = (await db.execute(select(AccessRequest).order_by(desc(AccessRequest.created_at)).limit(200))).scalars().all()
    return render(request, "requests.html", rows=rows)


@router.get("/ui/requests/{rid}", response_class=HTMLResponse, dependencies=[Depends(auth.require_admin)])
async def request_detail(request: Request, rid: str):
    async with session() as db:
        req = await db.get(AccessRequest, rid)
        if req is None:
            return redirect("/ui", "No such request.")
        grants = (await db.execute(select(Grant).where(Grant.request_id == rid))).scalars().all()
        grant_refs = {f"grant:{g.id}" for g in grants}
        rules = (await db.execute(select(Policy).where(Policy.request_id == rid))).scalars().all()
        refs = grant_refs | {f"policy:{p.id}" for p in rules}
        # Follow recorded authorization references, without inferring downstream effects.
        # The ts index bounds the scan; the text match only narrows it, the filter below decides.
        text = cast(AuditEvent.detail, String)
        events = (await db.execute(select(AuditEvent).where(
            AuditEvent.ts >= req.created_at,
            or_(*(text.contains(ref, autoescape=True) for ref in sorted({rid, *refs}))),
        ).order_by(AuditEvent.id))).scalars().all()
        timeline = [e for e in events if (e.detail or {}).get("request_id") == rid
                    or rid in ((e.detail or {}).get("request_ids") or [])
                    or refs.intersection(((e.detail or {}).get("matched") or {}).values())]
    return render(request, "request_detail.html", req=req, grants=grants, timeline=timeline, rules=rules)


@router.post("/ui/requests/{rid}/decide", dependencies=[Depends(auth.require_admin)])
async def request_decide(rid: str, scope: str = Form(...), deny_reason: str = Form(""), ttl_minutes: int = Form(60),
                         next: str = Form("/ui"), extent: str | None = Form(None)):
    started = now()
    async with session() as db:
        try:
            req = await approvals.decide(db, rid, scope, via="ui", deny_reason=deny_reason,
                                         ttl_s=ttl_minutes * 60, extent=extent)
        except (LookupError, ValueError) as e:
            return redirect(next, str(e))
    if req.status == "expired":
        return redirect(next, f"Request {req.id} expired before it was decided; nothing was granted.")
    if req.decided_at is None or req.decided_at < started:
        return redirect(next, f"Request {req.id} was already {req.status} ({approvals.decision_label(req)}) "
                              f"via {req.decided_via}; this choice was not applied.")
    return redirect(next, f"Request {req.id}: {req.status} ({approvals.decision_label(req)}).")


# ---- decision links (signed, no login) ----------------------------------------------------------
@router.get("/d/{token}", response_class=HTMLResponse)
async def decision_page(request: Request, token: str):
    parsed = approvals.parse_decision_token(token)
    if not parsed:
        return render(request, "decision.html", error="This link is invalid or has expired.")
    rid, scope = parsed
    async with session() as db:
        req = await db.get(AccessRequest, rid)
    if req is None:
        return render(request, "decision.html", error="No such request.")
    return render(request, "decision.html", req=req, scope=scope, token=token)


@router.post("/d/{token}")
async def decision_submit(request: Request, token: str, deny_reason: str = Form("")):
    parsed = approvals.parse_decision_token(token)
    if not parsed:
        return render(request, "decision.html", error="This link is invalid or has expired.")
    rid, scope = parsed
    async with session() as db:
        try:
            req = await approvals.decide(db, rid, scope, via="link", deny_reason=deny_reason)
        except (LookupError, ValueError) as e:
            return render(request, "decision.html", error=str(e))
    return render(request, "decision.html", req=req, scope=scope, done=True)


# ---- grants & policies --------------------------------------------------------------------------
@router.get("/ui/grants", response_class=HTMLResponse, dependencies=[Depends(auth.require_admin)])
async def grants_list(request: Request, show: str = ""):
    history = show == "all"
    async with session() as db:
        q = select(Grant).order_by(desc(Grant.created_at))
        live = q.where(Grant.revoked_at.is_(None), or_(Grant.expires_at.is_(None), Grant.expires_at > now()))
        rows = (await db.execute(q.limit(500) if history else live)).scalars().all()
        agents = {a.id: a for a in (await db.execute(select(Agent))).scalars().all()}
        ids = {g.request_id for g in rows if g.request_id}
        requests = {r.id: r for r in (await db.execute(select(AccessRequest).where(
            AccessRequest.id.in_(ids)))).scalars().all()} if ids else {}
    groups = access_view.grant_groups(rows, agents, requests, now(), include_inactive=history)
    return render(request, "grants.html", groups=groups, history=history,
                  active_total=sum(a["active"] for a in groups))


@router.post("/ui/grants/{gid}/revoke", dependencies=[Depends(auth.require_admin)])
async def grant_revoke(gid: str, next: str = Form("/ui/grants")):
    async with session() as db:
        await approvals.revoke_grant(db, gid)
    return redirect(next, "Grant revoked for future calls. Other grants, rules, or open defaults may still allow access. "
                          "Running operations are not stopped.")


@router.post("/ui/requests/{rid}/revoke", dependencies=[Depends(auth.require_admin)])
async def request_revoke(rid: str, next: str = Form("/ui")):
    async with session() as db:
        count = await approvals.revoke_request_grants(db, rid)
    return redirect(next, f"Revoked {count} grants from this approval. Other permissions may still allow access. "
                          "Running operations are not stopped.")


@router.post("/ui/grants/revoke-all", dependencies=[Depends(auth.require_admin)])
async def grants_revoke_all(agent_id: str = Form(""), next: str = Form("/ui/grants")):
    async with session() as db:
        q = select(Grant).where(Grant.revoked_at.is_(None))
        if agent_id:
            q = q.where(Grant.agent_id == agent_id)
        n = 0
        for g in (await db.execute(q)).scalars().all():
            await approvals.revoke_grant(db, g.id)
            n += 1
    return redirect(next, f"Revoked {n} grants. Standing rules and open defaults remain. Running operations continue.")


@router.get("/ui/policies", response_class=HTMLResponse, dependencies=[Depends(auth.require_admin)])
async def policies_list(request: Request):
    return await _policies_page(request)


async def _policies_page(request: Request, *, draft=None, preview=None, error=None):
    async with session() as db:
        rows = (await db.execute(select(Policy).order_by(Policy.effect, Policy.pattern))).scalars().all()
        agents = (await db.execute(select(Agent).order_by(Agent.name))).scalars().all()
    return render(request, "policies.html", rows=rows, agents=agents, agent_map={a.id: a for a in agents},
                  draft=draft or {}, preview=preview, error=error)


@router.post("/ui/policies", dependencies=[Depends(auth.require_admin)])
async def policy_create(request: Request, pattern: str = Form(...), effect: str = Form(...),
                        agent_id: str = Form(""), note: str = Form(""), action: str = Form("save")):
    draft = {"pattern": pattern, "effect": effect, "agent_id": agent_id, "note": note}
    try:
        pattern = validate(pattern)
    except ValueError as e:
        return await _policies_page(request, draft=draft, error=f"Invalid pattern: {e}")
    if effect not in ("allow", "deny"):
        return await _policies_page(request, draft=draft, error="Effect must be allow or deny.")
    if action not in ("save", "preview"):
        return await _policies_page(request, draft=draft, error="Unknown rule action.")
    async with session() as db:
        if agent_id and await db.get(Agent, agent_id) is None:
            return await _policies_page(request, draft=draft, error="No such agent.")
        candidate = Policy(id="preview" if action == "preview" else None, pattern=pattern, effect=effect,
                           agent_id=agent_id or None, note=note, created_by="ui")
        if action == "preview":
            report = await policy_preview.preview(db, candidate)
            return await _policies_page(request, draft=draft, preview=report)
        db.add(candidate)
        await db.commit()
    return redirect("/ui/policies", f"Rule added: {effect} {pattern}")


@router.post("/ui/policies/{pid}/delete", dependencies=[Depends(auth.require_admin)])
async def policy_delete(pid: str):
    async with session() as db:
        p = await db.get(Policy, pid)
        if p:
            await db.delete(p)
            await db.commit()
    return redirect("/ui/policies", "Rule deleted.")


# ---- agents -------------------------------------------------------------------------------------
# ---- access page: every tool (or model) of one resource, and one agent's standing on each ---------
@router.get("/ui/access", response_class=HTMLResponse, dependencies=[Depends(auth.require_admin)])
async def access_page(request: Request, resource: str = "", agent: str = "", scope: str | None = None,
                      refresh: str = ""):
    async with session() as db:
        resources = (await db.execute(select(Resource).where(Resource.kind.in_(("mcp", "llm")))
                                      .order_by(Resource.kind, Resource.name))).scalars().all()
        agents = (await db.execute(select(Agent).order_by(Agent.name))).scalars().all()
    res = next((r for r in resources if r.id == resource), resources[0] if resources else None)
    ag = next((a for a in agents if a.id == agent), None)
    ctx: dict[str, Any] = {"resources": resources, "agents": agents, "res": res, "ag": ag, "groups": {},
                           "error": None, "scope": "", "drift": None}
    if res is None:
        return render(request, "access.html", **ctx)
    try:
        rows, scope_text = await _access_rows(res, ag.id if ag else None, scope, force=bool(refresh))
    except ValueError as e:
        rows, scope_text, ctx["error"] = [], scope or "", str(e)
    except Exception as e:  # noqa: BLE001
        rows, scope_text, ctx["error"] = [], scope or "", f"Could not list upstream tools: {mcp_proxy.describe(e)}"
    for row in rows:
        ctx["groups"].setdefault(row.group, []).append(row)
    order = {g: i for i, g in enumerate((*tool_access.GROUPS, "models"))}
    ctx["groups"] = dict(sorted(ctx["groups"].items(), key=lambda kv: order.get(kv[0], 99)))
    ctx.update(scope=scope_text, drift=res.config.get("tools_drift"), arg_keys=res.config.get("arg_keys") or [])
    return render(request, "access.html", **ctx)


async def _access_rows(res: Resource, agent_id: str | None, scope: str | None, *, force: bool = False):
    """The page's rows, fresh from the upstream. `scope` None means the one last saved for this resource."""
    async with session() as db:
        policies = (await db.execute(select(Policy).where(
            (Policy.agent_id == agent_id) | Policy.agent_id.is_(None)))).scalars().all()
    if res.kind == "llm":
        return tool_access.llm_rows(res, llm.model_paths(res), policies, agent_id), ""
    scope_text = res.config.get("access_scope", "") if scope is None else scope
    parsed = tool_access.parse_scope(scope_text, res.config.get("arg_keys") or [])
    tools = await mcp_proxy.list_tools(res.name, res.config, force=force)
    return tool_access.mcp_rows(res, tools, policies, agent_id, parsed), scope_text


@router.post("/ui/access", dependencies=[Depends(auth.require_admin)])
async def access_save(request: Request):
    form = await request.form()
    rid, aid, scope = str(form.get("resource", "")), str(form.get("agent", "")), str(form.get("scope", ""))
    back = f"/ui/access?resource={rid}&agent={aid}"
    async with session() as db:
        res = await db.get(Resource, rid)
        ag = await db.get(Agent, aid) if aid else None
    if res is None or (aid and ag is None):
        return redirect("/ui/access", "No such resource or agent.")
    try:
        rows, _ = await _access_rows(res, ag.id if ag else None, scope)
    except ValueError as e:
        return redirect(back, f"Not saved: {e}")
    except Exception as e:  # noqa: BLE001
        return redirect(back, f"Not saved; could not list upstream tools: {mcp_proxy.describe(e)}")
    wanted = {k[2:]: str(v) for k, v in form.items() if k.startswith("s:")}
    async with session() as db:
        policies = (await db.execute(select(Policy).where(
            (Policy.agent_id == (ag.id if ag else None)) if ag else Policy.agent_id.is_(None)))).scalars().all()
        change = tool_access.plan(rows, wanted, policies, ag.id if ag else None)
        for p in change.delete:
            await db.delete(p)
        for pattern, effect in change.add:
            db.add(Policy(agent_id=ag.id if ag else None, pattern=pattern, effect=effect, created_by="ui",
                          note="access page"))
        fresh = await db.get(Resource, res.id)
        if fresh.kind == "mcp" and fresh.config.get("access_scope", "") != scope:
            fresh.config = {**fresh.config, "access_scope": scope}
        await db.commit()
        if change:
            await audit.record(db, tool="access.edit", decision="edit", agent=ag,
                               detail={"resource": res.name, "every_agent": ag is None,
                                       "added": [f"{e} {p}" for p, e in change.add],
                                       "removed": [f"{p.effect} {p.pattern}" for p in change.delete]})
    who = ag.name if ag else "every agent"
    if not change:
        return redirect(back, "No changes.")
    return redirect(back, f"{res.name} for {who}: {len(change.add)} rule(s) added, {len(change.delete)} removed.")


@router.post("/ui/resources/{rid}/tools/accept", dependencies=[Depends(auth.require_admin)])
async def resource_tools_accept(rid: str, agent: str = Form("")):
    """The owner has looked at the drift: today's tool list becomes the baseline."""
    async with session() as db:
        res = await db.get(Resource, rid)
        if res is None or res.kind != "mcp":
            return redirect("/ui/access", "No such MCP resource.")
        try:
            tools = await mcp_proxy.list_tools(res.name, res.config, force=True)
        except Exception as e:  # noqa: BLE001
            return redirect(f"/ui/access?resource={rid}&agent={agent}", f"Could not list tools: {mcp_proxy.describe(e)}")
        res.config = {**res.config, **tool_access.baseline(tools)}
        await db.commit()
        await audit.record(db, tool="tools.accept", decision="accept", detail={"resource": res.name,
                                                                                 "tools": len(tools)})
    return redirect(f"/ui/access?resource={rid}&agent={agent}", f"{res.name}: {len(tools)} tools are the new baseline.")


@router.get("/ui/agents", response_class=HTMLResponse, dependencies=[Depends(auth.require_admin)])
async def agents_list(request: Request):
    async with session() as db:
        rows = (await db.execute(select(Agent).order_by(Agent.name))).scalars().all()
        gateways = (await db.execute(select(Resource).where(Resource.kind == "llm").order_by(Resource.name))
                    ).scalars().all()
    new_token = request.cookies.get("kw_new_token")
    resp = render(request, "agents.html", rows=rows, new_token=new_token, mcp_url=_public_url() + "/mcp",
                  gateways=gateways, public_url=_public_url())
    if new_token:
        resp.delete_cookie("kw_new_token")
    return resp


@router.post("/ui/agents", dependencies=[Depends(auth.require_admin)])
async def agent_create(name: str = Form(...), note: str = Form("")):
    name = name.strip()
    if not name:
        return redirect("/ui/agents", "Name is required.")
    token = "kw_" + secrets.token_urlsafe(32)
    async with session() as db:
        if (await db.execute(select(Agent).where(Agent.name == name))).scalar_one_or_none():
            return redirect("/ui/agents", "An agent with that name exists.")
        db.add(Agent(name=name, token_hash=hash_token(token), token_prefix=token[:8], note=note))
        await db.commit()
    resp = redirect("/ui/agents", f"Agent {name} created. Copy the token now; it is not shown again.")
    resp.set_cookie("kw_new_token", token, max_age=120, httponly=True, samesite="lax")
    return resp


@router.post("/ui/agents/{aid}/{action}", dependencies=[Depends(auth.require_admin)])
async def agent_action(aid: str, action: str, next: str = Form("/ui/agents")):
    async with session() as db:
        a = await db.get(Agent, aid)
        if a is None:
            return redirect("/ui/agents", "No such agent.")
        token = None
        if action == "disable":
            a.disabled_at = now()
        elif action == "enable":
            a.disabled_at = None
        elif action == "rotate":
            token = "kw_" + secrets.token_urlsafe(32)
            a.token_hash, a.token_prefix = hash_token(token), token[:8]
        elif action == "delete":
            await db.delete(a)
        else:
            return redirect("/ui/agents", "Unknown action.")
        if action in ("disable", "delete"):
            # The agent's LLM keys are its authority to spend; they go before the row does.
            await llm.revoke_for_agent(db, a.id, via="ui")
        await db.commit()
        await audit.record(db, tool=f"agent.{action}", decision=action, agent=a,
                           detail={"via": "ui"})
    message = f"Agent {a.name}: {action}."
    if action == "disable":
        message += " New operations are blocked. Running operations are not stopped."
    resp = redirect(next, message)
    if token:
        resp.set_cookie("kw_new_token", token, max_age=120, httponly=True, samesite="lax")
    return resp


# ---- resources ----------------------------------------------------------------------------------
@router.get("/ui/resources", response_class=HTMLResponse, dependencies=[Depends(auth.require_admin)])
async def resources_list(request: Request, sort: str = "type", group: str = "none"):
    async with session() as db:
        data = await inventory.snapshot(db)
    return render(request, "resources.html", **inventory.resource_inventory(data, sort, group))


@router.get("/ui/resources/new", response_class=HTMLResponse, dependencies=[Depends(auth.require_admin)])
async def resource_new(request: Request, kind: str = "", adapter: str = "", integration: str = "", q: str = ""):
    preset = integrations.PRESET_BY_ID.get(integration or adapter)
    if integration and preset is None:
        return redirect("/ui/resources/new", "Choose an integration from the list.")
    if not kind and not preset:
        terms = q.lower().split()
        groups = [[{"item": item, "matches": all(term in item.search_text for term in terms)} for item in group]
                  for group in (integrations.PRESETS, integrations.GENERICS)]
        return render(request, "integration_picker.html", presets=groups[0], generics=groups[1], query=q,
                      matches=sum(entry["matches"] for group in groups for entry in group))
    if preset:
        kind, adapter = preset.kind, preset.adapter
    if kind not in ("ssh", "mcp", "llm"):
        return redirect("/ui/resources/new", "Choose a connection type from the list.")
    async with session() as db:
        ssh_hosts = list(await db.scalars(select(Resource).where(Resource.kind == "ssh").order_by(Resource.name)))
        ssh_hosts = [r for r in ssh_hosts if r.config.get("host") and r.config.get("key_path")]
    return render(request, "resource_form.html", res=None, kind=kind, keys_dir=settings.keys_dir,
                  preset=preset, ssh_hosts=ssh_hosts,
                  oauth_callback=settings.public_url.rstrip("/") + mcp_oauth.CALLBACK_PATH,
                  inventory_bundles=inventory_mcp.DEFAULT_BUNDLES,
                  connector=homelab.CONNECTORS.get(adapter),
                  adapter=adapter if kind == "mcp" and adapter in ("omada", "keywright", *homelab.CONNECTORS) else "")


@router.get("/ui/resources/{rid}", response_class=HTMLResponse, dependencies=[Depends(auth.require_admin)])
async def resource_edit(request: Request, rid: str):
    async with session() as db:
        res = await db.get(Resource, rid)
        link = await db.get(inventory.ResourceLink, rid)
        asset = await db.get(inventory.Asset, link.asset_id) if link else None
    if res is None:
        return redirect("/ui/resources", "No such resource.")
    if res.config.get("adapter") == "knowledge":
        return redirect("/ui/knowledge?collection=" + res.id)
    return render(request, "resource_form.html", res=res, kind=res.kind, keys_dir=settings.keys_dir,
                  preset=integrations.for_resource(res),
                  inventory_asset=asset,
                  oauth_callback=settings.public_url.rstrip("/") + mcp_oauth.CALLBACK_PATH,
                  oauth_status=await mcp_oauth.status(res.config) if res.config.get("auth_type") == "oauth" else None,
                  adapter=res.config.get("adapter", ""),
                  connector=homelab.CONNECTORS.get(res.config.get("adapter")),
                  key=key_info(res) if res.kind == "ssh" else None,
                  leases=await llm_leases(res) if res.kind == "llm" else None)


async def llm_leases(res: Resource) -> dict[str, Any]:
    """Active keys on a gateway with what they have spent, and the exposure they add up to."""
    async with session() as db:
        keys = await llm.active_keys(db, res)
        agents = {a.id: a.name for a in (await db.execute(select(Agent))).scalars().all()}
    spend = {k.id: await llm.key_spend(res.config, k.key) for k in keys}
    return {"leases": [{"row": k, "agent": agents.get(k.agent_id, "?"), "spend": spend[k.id],
                      "remaining": access_view.remaining(k.expires_at, now())} for k in keys],
            "exposure": llm.exposure(keys, spend), "health": res.config.get("health") or {},
            "enforced": llm.enforces_budgets(res.config.get("health"))}


@router.post("/ui/resources", dependencies=[Depends(auth.require_admin)])
async def resource_save(
    request: Request,
    rid: str = Form(""), kind: str = Form(...), name: str = Form(...), default_mode: str = Form("approval"),
    description: str = Form(""), host: str = Form(""), port: int = Form(22), user: str = Form("root"),
    key_path: str = Form(""), private_key: str = Form(""), url: str = Form(""), headers: str = Form(""),
    forget_host_key: str = Form(""), arg_keys: str = Form(""), audit_handle: str = Form(""),
    bundles_text: str = Form(""), hazard_tools_text: str = Form(""),
    result_inspection_mode: str = Form(""),
    master_key: str = Form(""), models_text: str = Form(""), max_budget: str = Form(""), rpm_limit: str = Form(""),
    tpm_limit: str = Form(""), max_parallel_requests: str = Form(""), agent_max_budget: str = Form(""),
    agent_budget_duration: str = Form("1d"),
    adapter: str = Form(""), omada_id: str = Form(""), client_id: str = Form(""),
    client_secret: str = Form(""), verify_tls: str = Form("1"), ca_bundle: str = Form(""),
    api_secret: str = Form(""), token_id: str = Form(""),
    auth_type: str = Form("headers"), oauth_client_id: str = Form(""), oauth_client_secret: str = Form(""),
    oauth_scope: str = Form(""), oauth_auth_method: str = Form("none"), oauth_origins: str = Form(""),
    integration: str = Form(""), setup_action: str = Form(""),
):
    preset = integrations.PRESET_BY_ID.get(integration)
    if integration and preset is None:
        return redirect("/ui/resources/new", "Choose an integration from the list.")
    if preset:
        kind, adapter = preset.kind, preset.adapter
        if preset.url:
            url, auth_type = preset.url, preset.auth_type
        if not oauth_origins.strip():
            oauth_origins = ",".join(preset.oauth_origins)
    if setup_action and (setup_action != "connect" or not preset or preset.auth_type != "oauth"):
        return redirect("/ui/resources/new", "Invalid integration setup action.")
    name = name.strip()
    if not name or not all(c.isalnum() or c in "_.-" for c in name):
        return redirect("/ui/resources", "Name must be alphanumeric with _ . - only.")
    if kind not in ("ssh", "mcp", "llm") or default_mode not in ("open", "approval", "locked"):
        return redirect("/ui/resources", "Invalid kind or mode.")
    if kind == "llm":
        try:
            limits = {"max_budget": _money(max_budget, required=True), "rpm_limit": _count(rpm_limit),
                      "tpm_limit": _count(tpm_limit), "max_parallel_requests": _count(max_parallel_requests)}
            agent_budget = {"max_budget": _money(agent_max_budget, required=True),
                            "budget_duration": agent_budget_duration}
        except ValueError as e:
            return redirect(f"/ui/resources/{rid}" if rid else "/ui/resources/new?kind=llm", f"Not saved: {e}")
        if agent_budget_duration not in llm.BUDGET_DURATIONS:
            return redirect("/ui/resources", "Agent budget window must be one of " + ", ".join(llm.BUDGET_DURATIONS))
    async with session() as db:
        res = await db.get(Resource, rid) if rid else None
        if res is None:
            if (await db.execute(select(Resource).where(Resource.name == name))).scalar_one_or_none():
                return redirect("/ui/resources", "A resource with that name exists.")
            res = Resource(kind=kind, name=name, config={})
            db.add(res)
        cfg = dict(res.config or {})
        if cfg.get("integration") and cfg["integration"] != integration:
            return redirect(f"/ui/resources/{res.id}", "Keep this resource's integration when saving its settings.")
        if preset:
            cfg["integration"] = preset.id
        if res.id and (kind != res.kind or adapter != cfg.get("adapter", "")):
            return redirect("/ui/resources", "Create a new resource to change its connection type.")
        if adapter not in ("", "omada", "keywright", *homelab.CONNECTORS) or (adapter and kind != "mcp"):
            return redirect("/ui/resources", "Invalid connection type.")
        if kind == "ssh":
            if (cfg.get("cli_setup") and
                    (host.strip() != cfg.get("host") or int(port or 22) != int(cfg.get("port") or 22)
                        or user.strip() != cfg.get("user") or private_key.strip() or forget_host_key
                        or (key_path.strip() and key_path.strip() != cfg.get("key_path")))):
                return redirect(f"/ui/resources/{res.id}", "Create a new CLI setup to use a different SSH connection.")
            if private_key.strip():
                settings.ensure_dirs()
                p = settings.keys_dir / name
                p.write_text(private_key.strip() + "\n")
                p.chmod(0o600)
                key_path = str(p)
            cfg.update({"host": host.strip(), "port": int(port or 22), "user": user.strip() or "root",
                        "key_path": key_path.strip() or cfg.get("key_path", "")})
            if forget_host_key:
                cfg.pop("host_key", None)
        elif kind == "llm":
            models = [m.strip() for m in models_text.replace("\n", ",").split(",") if m.strip()]
            cfg.update({"url": url.strip().rstrip("/"),
                        "master_key": cfg.get("master_key", "") if master_key.strip() in ("", "***")
                        else master_key.strip(),
                        "models": models, "limits": limits, "agent_budget": agent_budget})
        else:
            inspection_mode = result_inspection_mode or cfg.get("result_inspection", "off")
            if inspection_mode not in result_inspection.MODES:
                return redirect("/ui/resources", "Invalid result inspection mode.")
            hdrs: dict[str, str] = {}
            for line in headers.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdrs[k.strip()] = v.strip()
            existing = cfg.get("headers") or {}
            # keep a stored secret if the form shows the placeholder
            for k, v in hdrs.items():
                if v == "***" and k in existing:
                    hdrs[k] = existing[k]
            keys = [k.strip() for k in arg_keys.replace("\n", ",").split(",") if k.strip()]
            if any(not all(c.isalnum() or c in "_.-" for c in k) for k in keys):
                return redirect("/ui/resources", "Argument keys must be dotted names, e.g. service, data.entity_id.")
            try:
                parsed_bundles = bundles.parse(bundles_text, name)
            except ValueError as e:
                return redirect(f"/ui/resources/{res.id}" if res.id else "/ui/resources", f"Bundles not saved: {e}")
            try:
                parsed_hazards = bundles.parse(hazard_tools_text, name)
            except ValueError as e:
                return redirect(f"/ui/resources/{res.id}" if res.id else "/ui/resources", f"Hazard catalog not saved: {e}")
            if any(sev not in SEVERITIES for sev in parsed_hazards):
                return redirect(f"/ui/resources/{res.id}" if res.id else "/ui/resources",
                                f"Hazard catalog lines must start with one of {', '.join(SEVERITIES)}.")
            cfg.update({"url": url.strip(), "headers": hdrs, "arg_keys": keys, "audit_handle": audit_handle == "1",
                        "bundles": parsed_bundles, "hazard_tools": parsed_hazards,
                        "result_inspection": inspection_mode})
            if not adapter:
                if auth_type not in ("headers", "oauth"):
                    return redirect("/ui/resources", "Invalid MCP authentication method.")
                cfg["auth_type"] = auth_type
                if auth_type == "oauth":
                    cfg["headers"] = {k: v for k, v in hdrs.items() if k.lower() != "authorization"}
                    cfg["oauth"] = {"client_id": oauth_client_id.strip(), "scope": oauth_scope.strip(),
                                    "token_endpoint_auth_method": oauth_auth_method,
                                    "origins": [v.strip().rstrip("/") for v in
                                                oauth_origins.replace("\n", ",").split(",") if v.strip()]}
                try:
                    await mcp_oauth.configure(db, res, cfg, secret=oauth_client_secret.strip())
                except mcp_oauth.ConnectionError as exc:
                    return redirect(f"/ui/resources/{res.id}" if res.id else "/ui/resources", str(exc))
            if adapter == "keywright":
                cfg.update({"adapter": "keywright"})
                cfg.pop("url", None)
                cfg.pop("headers", None)
            if adapter == "omada":
                if verify_tls not in ("0", "1"):
                    return redirect("/ui/resources", "Invalid TLS verification setting.")
                cfg.update({"adapter": "omada", "url": url.strip().rstrip("/"),
                            "omada_id": omada_id.strip(), "client_id": client_id.strip(),
                            "client_secret": cfg.get("client_secret", "") if client_secret.strip() in ("", "***")
                            else client_secret.strip(), "verify_tls": verify_tls == "1",
                            "ca_bundle": ca_bundle.strip()})
                try:
                    omada.validate_config(cfg)
                except ValueError as e:
                    return redirect(f"/ui/resources/{res.id}" if res.id else
                                    "/ui/resources/new?kind=mcp&adapter=omada", f"Not saved: {e}")
            if adapter in homelab.CONNECTORS:
                if verify_tls not in ("0", "1"):
                    return redirect("/ui/resources", "Invalid TLS verification setting.")
                cfg.update({"adapter": adapter, "url": url.strip().rstrip("/"),
                            "token_id": token_id.strip(),
                            "api_secret": cfg.get("api_secret", "") if api_secret in ("", "***") else api_secret,
                            "verify_tls": verify_tls == "1", "ca_bundle": ca_bundle.strip()})
                cfg.pop("headers", None)
                try:
                    homelab.validate_config(cfg)
                except ValueError as e:
                    return redirect(f"/ui/resources/{res.id}" if res.id else
                                    f"/ui/resources/new?integration={adapter}", f"Not saved: {e}")
            mcp_proxy.forget(name)
        res.name, res.default_mode, res.description, res.config = name, default_mode, description, cfg
        await db.commit()
        rid = res.id
    if setup_action == "connect":
        return await mcp_oauth_ui.connect(request, rid)
    return redirect(f"/ui/resources/{rid}", "Saved.")


def _money(text: str, *, required: bool = False) -> float | None:
    text = text.strip().lstrip("$")
    if not text:
        if required:
            raise ValueError("a spend ceiling in USD is required; it is the whole point")
        return None
    try:
        value = float(text)
    except ValueError:
        raise ValueError(f"{text!r} is not an amount in USD") from None
    if value <= 0 or value > 100000:
        raise ValueError("a spend ceiling must be more than $0 and at most $100000")
    return round(value, 4)


def _count(text: str) -> int | None:
    text = text.strip()
    if not text:
        return None
    if not text.isdigit() or int(text) <= 0:
        raise ValueError(f"{text!r} is not a positive whole number")
    return int(text)


@router.post("/ui/resources/{rid}/suggest-bundles", dependencies=[Depends(auth.require_admin)])
async def resource_suggest_bundles(rid: str):
    async with session() as db:
        res = await db.get(Resource, rid)
        if res is None or res.kind != "mcp":
            return redirect("/ui/resources", "No such MCP resource.")
        try:
            tools = await mcp_proxy.list_tools(res.name, res.config, force=True)
        except Exception as e:  # noqa: BLE001
            return redirect(f"/ui/resources/{rid}", f"Could not list upstream tools: {type(e).__name__}: {e}")
        suggested = bundles.suggest([t.name for t in tools])
        existing = dict(res.config.get("bundles") or {})
        added = {n: es for n, es in suggested.items() if n not in existing}
        res.config = {**res.config, "bundles": {**existing, **added}}
        await db.commit()
    return redirect(f"/ui/resources/{rid}", f"Suggested {len(added)} bundle(s) from {len(tools)} tools by verb; "
                                             "review and edit them, they are a starting point, not a policy.")


@router.post("/ui/resources/{rid}/probe", dependencies=[Depends(auth.require_admin)])
async def resource_probe(rid: str):
    async with session() as db:
        res = await db.get(Resource, rid)
        if res is None:
            return redirect("/ui/resources", "No such resource.")
        if res.kind == "ssh":
            ok, msg, learned = await ssh.probe(res.config)
            if learned:
                res.config = {**res.config, "host_key": learned}
                await db.commit()
                msg += " Host key pinned."
        elif res.kind == "llm":
            ok, msg, health = await llm.probe(res.config)
            models = health.pop("models", None)
            cfg = {**res.config, "health": health}
            if models is not None:
                cfg["models"] = models
                msg += " Model list refreshed."
            res.config = cfg
            await db.commit()
        else:
            ok, msg = await mcp_proxy.probe(res.config)
    return redirect(f"/ui/resources/{rid}", ("OK: " if ok else "FAILED: ") + msg)


@router.post("/ui/resources/{rid}/delete", dependencies=[Depends(auth.require_admin)])
async def resource_delete(rid: str):
    async with session() as db:
        res = await db.get(Resource, rid)
        removed = False
        if res:
            kp = (res.config or {}).get("key_path") or ""
            if res.kind == "llm":
                await llm.revoke_for_resource(db, res, via="ui")
            if res.config.get("oauth_id"):
                await mcp_oauth.configure(db, res, {"auth_type": "headers"})
            if res.kind == "mcp":
                mcp_proxy.forget(res.name)
            await db.delete(res)
            await db.commit()
            # A key Keywright keeps for this resource goes with it, or the name can never be keyed
            # again. Keys outside keys_dir, or still used by another resource, are the admin's.
            others = (await db.execute(select(Resource))).scalars().all()
            if (kp and Path(kp).resolve().parent == settings.keys_dir.resolve()
                    and not any((o.config or {}).get("key_path") == kp for o in others)):
                for f in (Path(kp), Path(kp + ".pub")):
                    removed = removed or f.exists()
                    f.unlink(missing_ok=True)
    return redirect("/ui/resources", "Resource deleted, with its key on this Keywright." if removed
                    else "Resource deleted.")


# ---- SSH key generation & host enrolment --------------------------------------------------------
def _enroll_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.secret_key(), salt="enroll")


def key_info(res: Resource) -> dict[str, Any]:
    """What the resource form shows about the key: exists? public line? enrol one-liner."""
    kp = (res.config or {}).get("key_path") or ""
    info: dict[str, Any] = {"key_path": kp, "exists": bool(kp) and os.path.exists(kp), "pub": ""}
    if info["exists"]:
        pub = kp + ".pub"
        if os.path.exists(pub):
            info["pub"] = Path(pub).read_text().strip()
    if info["pub"]:
        tok = _enroll_serializer().dumps({"r": res.id})
        info["enroll_cmd"] = f"curl -fsSL {shlex.quote(_public_url() + '/enroll/' + tok)} | sh"
    return info


@router.post("/ui/resources/{rid}/keygen", dependencies=[Depends(auth.require_admin)])
async def resource_keygen(rid: str):
    async with session() as db:
        res = await db.get(Resource, rid)
        if res is None or res.kind != "ssh":
            return redirect("/ui/resources", "No such SSH resource.")
        try:
            priv, _ = ssh.generate_key(res.name, settings.keys_dir)
        except FileExistsError as e:
            return redirect(f"/ui/resources/{rid}", f"Not overwriting: {e}. Delete it on the container first.")
        res.config = {**res.config, "key_path": priv}
        await db.commit()
    return redirect(f"/ui/resources/{rid}", "Key generated on this Keywright. Now enrol it on the host.")


@router.post("/ui/resources/{rid}/enroll", dependencies=[Depends(auth.require_admin)])
async def resource_enroll(rid: str, password: str = Form(...), restrict: str = Form(""), login_user: str = Form(""),
                          escalate: str = Form(""), root_password: str = Form("")):
    async with session() as db:
        res = await db.get(Resource, rid)
        if res is None or res.kind != "ssh":
            return redirect("/ui/resources", "No such SSH resource.")
        info = key_info(res)
        if not info["pub"]:
            return redirect(f"/ui/resources/{rid}", "Generate a key first.")
        ok, msg, learned = await ssh.enroll_with_password(
            res.config, password, info["pub"], restrict=bool(restrict), login_user=login_user,
            escalate=escalate or None, root_password=root_password or None)
        if learned:
            res.config = {**res.config, "host_key": learned}
            await db.commit()
        await audit.record(db, tool="ssh.enroll", decision="allow" if ok else "error",
                           patterns=[f"ssh/{res.name}"], detail={"host": res.config.get("host"), "message": msg})
    return redirect(f"/ui/resources/{rid}", ("Enrolled: " if ok else "Enrol failed: ") + msg)


@router.get("/enroll/{token}", response_class=PlainTextResponse)
async def enroll_script(token: str):
    """Shell script that installs this resource's public key for the invoking user. The URL is a
    signed 30-minute token, so it can be pasted into a terminal without logging into the UI."""
    try:
        data = _enroll_serializer().loads(token, max_age=1800)
    except (BadSignature, SignatureExpired):
        return PlainTextResponse("echo 'keywright: enrol link invalid or expired' >&2; exit 1\n", status_code=404)
    async with session() as db:
        res = await db.get(Resource, data.get("r", ""))
        src = (await get_setting(db, "general", {})).get("outbound_ip") or None
    if res is None or res.kind != "ssh":
        return PlainTextResponse("echo 'keywright: unknown resource' >&2; exit 1\n", status_code=404)
    info = key_info(res)
    if not info["pub"]:
        return PlainTextResponse("echo 'keywright: no key generated yet' >&2; exit 1\n", status_code=404)
    return ssh.enroll_script(info["pub"], src)


# ---- settings -----------------------------------------------------------------------------------
def _public_url() -> str:
    return approvals.public_url()


@router.get("/ui/settings", response_class=HTMLResponse, dependencies=[Depends(auth.require_admin)])
async def settings_page(request: Request):
    async with session() as db:
        general = await get_setting(db, "general", {"public_url": settings.public_url})
        notif = await get_setting(db, "notifications", {"driver": "log", "config": {}, "buttons": DEFAULT_BUTTONS})
        jev = await semantic.config(db)
        jev_tally = await semantic.shadow_tally(db)
    driver = registry.get(notif.get("driver") or "log", registry["log"])
    return render(request, "settings.html", general=general, notif=notif, drivers=registry, driver=driver,
                  probe=request.cookies.get("kw_probe"), notifier=manager, default_buttons=DEFAULT_BUTTONS,
                  jev=jev, jev_tally=jev_tally, jev_configured=semantic.configured(),
                  jev_trust_selectable=semantic.TRUST_SELECTABLE)


@router.post("/ui/settings/semantic", dependencies=[Depends(auth.require_admin)])
async def settings_semantic(request: Request):
    form = await request.form()
    try:
        value = semantic.validate_config({k: form.get(k) for k in ("mode", "timeout_s", "daily_cap")})
    except ValueError as e:
        return redirect("/ui/settings", str(e))
    async with session() as db:
        await put_setting(db, "semantic", value)
    return redirect("/ui/settings", "Saved.")


@router.post("/ui/settings/general", dependencies=[Depends(auth.require_admin)])
async def settings_general(public_url: str = Form(""), outbound_ip: str = Form("")):
    if outbound_ip.strip():
        try:
            ipaddress.ip_address(outbound_ip.strip())
        except ValueError:
            return redirect("/ui/settings", "Outbound IP must be one IPv4 or IPv6 address.")
    async with session() as db:
        await put_setting(db, "general", {"public_url": public_url.strip().rstrip("/"), "outbound_ip": outbound_ip.strip()})
    return redirect("/ui/settings", "Saved.")


async def _read_notif_form(request: Request) -> dict[str, Any]:
    form = await request.form()
    driver_id = str(form.get("driver") or "log")
    cls = registry.get(driver_id, registry["log"])
    async with session() as db:
        current = await get_setting(db, "notifications", {})
    old_cfg = (current.get("config") or {}) if current.get("driver") == driver_id else {}
    cfg: dict[str, Any] = {}
    for f in cls.fields:
        if f.type == "multiselect":
            cfg[f.name] = [str(v) for v in form.getlist(f.name)]
        elif f.type == "checkbox":
            cfg[f.name] = form.get(f.name) == "on"
        else:
            val = str(form.get(f.name) or "").strip()
            if f.type == "password" and val == "***":
                val = old_cfg.get(f.name, "")
            cfg[f.name] = val
    buttons = [b for b in form.getlist("buttons") if b in approvals.PHONE_SCOPES] or DEFAULT_BUTTONS
    return {"driver": driver_id, "config": cfg, "buttons": buttons, "choices": current.get("choices") or {}}


@router.post("/ui/settings/notifications", dependencies=[Depends(auth.require_admin)])
async def settings_notifications(request: Request):
    cfg = await _read_notif_form(request)
    async with session() as db:
        await put_setting(db, "notifications", cfg)
    await manager.reload()
    return redirect("/ui/settings", f"Notifications saved: {registry[cfg['driver']].label}.")


@router.post("/ui/settings/notifications/probe", dependencies=[Depends(auth.require_admin)])
async def settings_notifications_probe(request: Request):
    cfg = await _read_notif_form(request)
    cls = registry[cfg["driver"]]
    result = await cls(cfg["config"]).probe()
    if result.ok:
        cfg["choices"] = {k: [list(x) for x in v] for k, v in result.choices.items()}
    async with session() as db:
        await put_setting(db, "notifications", cfg)
    await manager.reload()
    resp = redirect("/ui/settings", ("Probe OK: " if result.ok else "Probe failed: ") + result.message)
    return resp


@router.post("/ui/settings/notifications/test", dependencies=[Depends(auth.require_admin)])
async def settings_notifications_test():
    async with session() as db:
        agent = (await db.execute(select(Agent).order_by(Agent.created_at).limit(1))).scalar_one_or_none()
        if agent is None:
            return redirect("/ui/settings", "Create an agent first; the test sends a real request in its name.")
        req = await approvals.create(db, agent, None, ["ssh/example/exec/uptime"],
                                     "Test notification from Keywright settings", {"command": "uptime"})
        req.expires_at = now() + timedelta(minutes=10)
        await db.commit()
    err = manager.last_error
    return redirect("/ui/settings", f"Test request {req.id} sent via {manager.driver_id}." + (f" ERROR: {err}" if err else ""))


# ---- audit --------------------------------------------------------------------------------------
@router.get("/ui/audit", response_class=HTMLResponse, dependencies=[Depends(auth.require_admin)])
async def audit_list(request: Request, q: str = "", limit: int = 200):
    async with session() as db:
        stmt = select(AuditEvent).order_by(desc(AuditEvent.id)).limit(min(limit, 1000))
        if q.startswith("#") and q[1:].isdigit():
            # "audit #id" links must resolve however old the event is.
            stmt = select(AuditEvent).where(AuditEvent.id == int(q[1:]))
        rows = (await db.execute(stmt)).scalars().all()
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in (r.agent_name + r.tool + r.decision + " ".join(r.patterns) + str(r.detail)).lower()
                or ql.lstrip("#") == str(r.id)]
    return render(request, "audit.html", rows=rows, q=q)
