"""The LLM proxy: an agent talks to `/llm/<gateway>/v1/...` with its Keywright token, and the call
reaches LiteLLM carrying the virtual key of the lease that allows it.

    ANTHROPIC_BASE_URL=https://keywright.example/llm/anthropic   ANTHROPIC_AUTH_TOKEN=kw_...
    OPENAI_BASE_URL=https://keywright.example/llm/openai/v1      OPENAI_API_KEY=kw_...

Every call names a model, and the model is the permission path: `llm/<gateway>/model/<model>`.
The decision is the same as for a shell command (deny rule, active lease, allow rule, resource
default), and a call nobody has approved yet asks the human and waits, exactly like `ssh_run`.
The body and the response pass through untouched, streamed; only the credential changes hands.
A lease's key is the one minted at approval. Standing access (an allow rule or an open default)
gets a key too, minted on first use with the gateway's per-lease ceiling and renewed hourly, so
"always allow" still never means "unlimited"."""

from __future__ import annotations

import json
import logging
import time
from datetime import timedelta
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse
from keywright.patterns import model_segment
from sqlalchemy import select

from . import approvals, audit, llm, policy
from .config import settings
from .db import session
from .llm_usage import UsageObserver, numeric_usage
from .mcp_server import _request_or_reuse, resolve_agent
from .models import Agent, LlmKey, Resource, now

log = logging.getLogger(__name__)
router = APIRouter()

STANDING_TTL = timedelta(hours=1)
# Never forwarded upstream: identity and framing are ours to set.
DROP_REQUEST_HEADERS = {"host", "authorization", "x-api-key", "content-length", "connection",
                        "x-keywright-session", "x-keywright-reason", "x-keywright-wait"}
DROP_RESPONSE_HEADERS = {"content-length", "transfer-encoding", "connection", "keep-alive"}
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


def _error(status: int, kind: str, message: str, **extra: Any) -> JSONResponse:
    """One shape both the OpenAI and Anthropic SDKs surface verbatim: error.message, error.type."""
    return JSONResponse({"error": {"message": message, "type": f"keywright_{kind}", "code": kind, **extra}},
                        status_code=status)


def _model_of(body: bytes) -> tuple[str | None, dict | None]:
    try:
        data = json.loads(body) if body else None
    except ValueError:
        return None, None
    if isinstance(data, dict) and isinstance(data.get("model"), str):
        return data["model"], data
    return None, data if isinstance(data, dict) else None


@router.api_route("/llm/{gateway}/{path:path}", methods=METHODS)
async def proxy(request: Request, gateway: str, path: str):
    headers = {k.lower(): v for k, v in request.headers.items()}
    if "authorization" not in headers and headers.get("x-api-key"):
        headers["authorization"] = "Bearer " + headers["x-api-key"]  # the Anthropic SDK's spelling
    sid = next((headers[h][:128] for h in ("x-keywright-session",) if headers.get(h)), None)
    body = await request.body()
    model, _ = _model_of(body) if request.method in ("POST", "PUT", "PATCH") else (None, None)
    started = time.monotonic()
    async with session() as db:
        agent = await resolve_agent(db, headers)
        if agent is None:
            return _error(401, "unauthorized", "Missing or unknown Keywright agent token.")
        res = (await db.execute(select(Resource).where(Resource.kind == "llm", Resource.name == gateway))
               ).scalar_one_or_none()
        if res is None:
            return _error(404, "unknown_gateway", f"No LLM gateway named {gateway!r}.")
        if model is None and request.method != "GET":
            return _error(400, "no_model", "The request body must name a model.")
        if model is not None and model not in (res.config.get("models") or []):
            return _error(400, "unknown_model", f"{model!r} is not offered by this gateway.",
                          models=list(res.config.get("models") or []))
        key, denial = await _key_for(db, agent, res, sid, model, headers)
        if denial is not None:
            return denial
        assert key is not None
        upstream = f"{str(res.config.get('url') or '').rstrip('/')}/{path}"
        pattern = f"llm/{res.name}/model/{model_segment(model)}" if model else f"llm/{res.name}"
        detail = {"gateway": res.name, "model": model, "path": path, "method": request.method,
                  "resource_id": res.id, "gateway_key_id": key.id,
                  "key_alias": key.key_alias, "standing": not key.grant_ids}
        agent_id, agent_name = agent.id, agent.name
    out_headers = {k: v for k, v in headers.items() if k not in DROP_REQUEST_HEADERS}
    out_headers["authorization"] = f"Bearer {key.key}"
    client = httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=10.0))
    try:
        req = client.build_request(request.method, upstream, headers=out_headers, content=body,
                                   params=request.query_params)
        resp = await client.send(req, stream=True)
    except httpx.HTTPError as e:
        await client.aclose()
        async with session() as db:
            await audit.record(db, tool="llm.call", decision="error", agent=Agent(id=agent_id, name=agent_name),
                               session_id=sid, patterns=[pattern],
                               detail={**detail, "error": f"{type(e).__name__}: {e}"},
                               duration_ms=int((time.monotonic() - started) * 1000))
        return _error(502, "gateway_unreachable", f"The LLM gateway did not answer: {type(e).__name__}.")
    resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in DROP_RESPONSE_HEADERS}
    streaming = "text/event-stream" in resp.headers.get("content-type", "")
    detail["status"] = resp.status_code
    detail["stream"] = streaming

    async def relay():
        observer = UsageObserver(streaming)
        completed = False
        try:
            async for chunk in resp.aiter_raw():
                if not resp.headers.get("content-encoding"):
                    observer.feed(chunk)
                yield chunk
            completed = True
        finally:
            await resp.aclose()
            await client.aclose()
            observer.finish()
            usage = observer.usage
            failed = resp.status_code >= 400 or observer.failed or not completed
            async with session() as db:
                await audit.record(db, tool="llm.call", decision="error" if failed else "allow",
                                   agent=Agent(id=agent_id, name=agent_name), session_id=sid, patterns=[pattern],
                                   detail={**detail, "response_complete": completed and not observer.failed,
                                           **({"usage": usage} if usage else {})},
                                   exit_code=resp.status_code, duration_ms=int((time.monotonic() - started) * 1000))

    return StreamingResponse(relay(), status_code=resp.status_code, headers=resp_headers)


def _usage(usage: Any) -> dict[str, Any] | None:
    """Token counts as the audit log keeps them. The field names lose their `_tokens` suffix so the
    credential scrubber, which redacts anything called *token*, leaves the numbers alone."""
    return numeric_usage(usage)


async def _key_for(db, agent: Agent, res: Resource, sid: str | None, model: str | None,
                   headers: dict[str, str]) -> tuple[LlmKey | None, JSONResponse | None]:
    """The key this call goes upstream with, or the JSON error explaining why there is none."""
    if model is None:
        # /v1/models and friends: any active lease will do; LiteLLM answers for that key's models.
        # A chat UI lists models before its first call, so standing access mints its key here too.
        keys = await _active_keys(db, agent, res)
        if keys:
            return keys[0], None
        try:
            return await _standing_key(db, agent, res, sid, None), None
        except NoStandingAccess:
            return None, _error(403, "no_lease", f"No active lease on {res.name}; ask for a model first.")
        except llm.GatewayError as e:
            return None, _error(503, "gateway_refused", f"The gateway would not mint a key: {e}")
    pattern = f"llm/{res.name}/model/{model_segment(model)}"
    operation = {"resource_id": res.id, "gateway": res.name, "model": model}
    v = await policy.evaluate(db, agent, sid, [pattern], consume=False, operation=operation)
    if not v.allowed:
        if v.status == "deny":
            await audit.record(db, tool="llm.call", decision="deny", agent=agent, session_id=sid,
                               patterns=[pattern], detail={"gateway": res.name, "model": model})
            return None, _error(403, "denied", f"A standing deny rule covers {model}.")
        if v.status == "locked":
            await audit.record(db, tool="llm.call", decision="locked", agent=agent, session_id=sid,
                               patterns=[pattern], detail={"gateway": res.name, "model": model})
            return None, _error(403, "locked", f"{res.name} is locked; only a rule in the admin UI opens it.")
        reason = headers.get("x-keywright-reason") or f"LLM call: {model} via {res.name}"
        try:
            req, _ = await _request_or_reuse(db, agent, sid, v.missing, reason[:2000],
                                             {"gateway": res.name, "model": model})
        except ValueError as e:
            return None, _error(429, "too_many_requests", str(e))
        if req is None:
            await audit.record(db, tool="llm.call", decision="deny", agent=agent, session_id=sid,
                               patterns=[pattern], detail={"gateway": res.name, "model": model, "note": "recently denied"})
            return None, _error(403, "denied", "Recently denied by the human; do not retry blindly.", retry_after=600)
        wait_s = _wait_seconds(headers)
        if wait_s:
            await approvals.wait(req.id, wait_s)
            await db.refresh(req)
        if req.status == "approved":
            v = await policy.evaluate(db, agent, sid, [pattern], consume=False, operation=operation)
        if not v.allowed:
            await audit.record(db, tool="llm.call", decision=req.status if req.status != "approved" else "pending",
                               agent=agent, session_id=sid, patterns=[pattern],
                               detail={"gateway": res.name, "model": model, "request_id": req.id})
            if req.status == "pending":
                return None, _error(403, "approval_required",
                                    f"Approval for {model} is pending with the human (request {req.id}); "
                                    "retry once it is decided.", request_id=req.id)
            return None, _error(403, "denied", f"Request {req.id} was {req.status}.", request_id=req.id,
                                reason=req.deny_reason or None)
    matched = v.matched.get(pattern, "")
    if matched.startswith("grant:"):
        grant_id = matched[6:]
        for k in await _active_keys(db, agent, res):
            if grant_id in (k.grant_ids or []) and model in (k.models or []):
                return k, None
        # Every lease is minted with its key; a lease without one is a bug or a hand-inserted grant.
        log.error("grant %s allows %s but has no LiteLLM key", grant_id, pattern)
        return None, _error(503, "no_key", "This lease has no gateway key; revoke it and approve again.")
    try:
        return await _standing_key(db, agent, res, sid, model), None
    except llm.GatewayError as e:
        await audit.record(db, tool="llm.call", decision="error", agent=agent, session_id=sid,
                           patterns=[pattern], detail={"gateway": res.name, "model": model, "error": str(e)})
        return None, _error(503, "gateway_refused", f"The gateway would not mint a key: {e}")


def _wait_seconds(headers: dict[str, str]) -> int:
    raw = headers.get("x-keywright-wait")
    if raw and raw.isdigit():
        return min(int(raw), settings.request_timeout_s)
    return settings.llm_wait_s


async def _active_keys(db, agent: Agent, res: Resource) -> list[LlmKey]:
    at = now()
    rows = (await db.execute(select(LlmKey).where(
        LlmKey.agent_id == agent.id, LlmKey.resource_id == res.id, LlmKey.revoked_at.is_(None))
        .order_by(LlmKey.created_at.desc()))).scalars().all()
    return [k for k in rows if k.is_active(at)]


class NoStandingAccess(Exception):
    """No allow rule or open default reaches any model on this gateway for this agent."""


async def _standing_key(db, agent: Agent, res: Resource, sid: str | None, model: str | None) -> LlmKey:
    """The one key an agent's standing access on a gateway runs on: every model an allow rule or the
    open default reaches, the gateway's per-lease ceiling, an hour at a time. Reused while it has
    at least ten minutes left, so a long conversation does not mint a key per call."""
    at = now()
    for k in await _active_keys(db, agent, res):
        if (not k.grant_ids and (model is None or model in (k.models or [])) and k.expires_at
                and k.expires_at - at > timedelta(minutes=10)):
            return k
    models = []
    for m, path in llm.model_paths(res).items():
        v = await policy.evaluate(db, agent, sid, [path], consume=False,
                                  operation={"resource_id": res.id, "gateway": res.name, "model": m})
        if v.allowed and not v.matched.get(path, "").startswith("grant:"):
            models.append(m)
    if model is not None and model not in models:
        models.append(model)
    if not models:
        raise NoStandingAccess(res.name)
    health = await llm.readiness(res.config)
    if not llm.enforces_budgets(health):
        raise llm.GatewayError(f"LiteLLM reports its database {health['db']!r}; budgets would not be enforced")
    expires = at + STANDING_TTL
    limits = llm.limits_of(res.config)
    await llm.ensure_user(res.config, agent)
    alias = f"kw:{agent.name}:standing:{res.name}:{int(at.timestamp())}"[:100]
    key = await llm.generate_key(res.config, agent, models, expires, limits, alias,
                                 {"agent": agent.name, "standing": True, "models": models})
    row = LlmKey(resource_id=res.id, agent_id=agent.id, request_id=None, grant_ids=[], key=key, key_alias=alias,
                 models=models, limits=limits, expires_at=expires)
    db.add(row)
    await db.commit()
    await audit.record(db, tool="llm.key", decision="minted", agent=agent, session_id=sid,
                       patterns=[f"llm/{res.name}/model/{model_segment(m)}" for m in models],
                       detail={"key_alias": alias, "models": models, "limits": limits, "standing": True,
                               "expires_at": expires.isoformat()})
    return row
