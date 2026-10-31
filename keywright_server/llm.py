"""LLM gateways: LiteLLM as the data plane, Keywright as the control plane.

Resource config for kind=llm:
  {"url": "http://litellm:4000", "master_key": "sk-...",
   "models": ["claude-sonnet-5", "gpt-5.6"],            # what agents may ask for; refreshed by probe
   "limits": {"max_budget": 2.0, "rpm_limit": 30, "tpm_limit": null, "max_parallel_requests": 4},
   "agent_budget": {"max_budget": 10.0, "budget_duration": "1d"},
   "health": {"db": "connected", "version": "...", "checked_at": "..."}}

Only Keywright holds the master key and the real provider keys stay in LiteLLM's environment. An
approval on `llm/<gateway>/model/<model>` becomes a LiteLLM virtual key with exactly that model
list, the grant's lifetime as its `duration`, and the gateway's per-grant limits. The agent is a
LiteLLM internal user carrying the daily or monthly budget, so a key's ceiling and the agent's
ceiling are both enforced upstream (never a team: a key in a team ignores its own budget).

Budgets are enforced against spend LiteLLM reads from its database; without one the proxy serves
past every limit. A key is therefore never minted unless the gateway reports its database
connected, and the failure is the human's to see, not the agent's to slip through.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx
from keywright.patterns import model_segment
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import audit
from .models import Agent, Grant, LlmKey, Resource, now

log = logging.getLogger(__name__)

TIMEOUT = 15.0
LIMIT_KEYS = ("max_budget", "rpm_limit", "tpm_limit", "max_parallel_requests")
DEFAULT_LIMITS: dict[str, Any] = {"max_budget": 2.0, "rpm_limit": 30, "tpm_limit": None, "max_parallel_requests": 4}
DEFAULT_AGENT_BUDGET: dict[str, Any] = {"max_budget": 10.0, "budget_duration": "1d"}
BUDGET_DURATIONS = ("1h", "1d", "7d", "30d")


class GatewayError(RuntimeError):
    """The gateway refused, is unreachable, or cannot enforce budgets. Never silently allowed."""


def _client(config: dict[str, Any], timeout: float = TIMEOUT) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=str(config.get("url") or "").rstrip("/"), timeout=timeout,
                             headers={"Authorization": f"Bearer {config.get('master_key') or ''}"})


def limits_of(config: dict[str, Any]) -> dict[str, Any]:
    return {k: (config.get("limits") or {}).get(k, DEFAULT_LIMITS[k]) for k in LIMIT_KEYS}


def agent_budget_of(config: dict[str, Any]) -> dict[str, Any]:
    return {**DEFAULT_AGENT_BUDGET, **{k: v for k, v in (config.get("agent_budget") or {}).items() if v is not None}}


def model_paths(res: Resource) -> dict[str, str]:
    """model name -> permission path, for every model the gateway offers."""
    return {m: f"llm/{res.name}/model/{model_segment(m)}" for m in (res.config.get("models") or [])}


def models_for(res: Resource, patterns: list[str]) -> list[str]:
    """The gateway's models a set of approved patterns reaches. Patterns are matched by the model
    segment, so `llm/gw/model/*` or `llm/gw` reach every model and a literal reaches one."""
    from keywright.patterns import matches

    return [m for m, path in model_paths(res).items() if any(matches(p, path) for p in patterns)]


def user_id(agent: Agent) -> str:
    return f"kw-{agent.id}"


# ---- gateway calls ------------------------------------------------------------------------------
async def readiness(config: dict[str, Any]) -> dict[str, Any]:
    """{"db": "connected"|..., "version": ...}; raises GatewayError when unreachable."""
    try:
        async with _client(config) as c:
            r = await c.get("/health/readiness")
            data = r.json() if r.content else {}
    except (httpx.HTTPError, ValueError) as e:
        raise GatewayError(f"gateway unreachable: {type(e).__name__}: {e}") from e
    if not isinstance(data, dict):
        raise GatewayError("gateway readiness returned no JSON object")
    return {"db": str(data.get("db") or "unknown"), "version": str(data.get("litellm_version") or ""),
            "status": str(data.get("status") or r.status_code)}


def enforces_budgets(health: dict[str, Any] | None) -> bool:
    return bool(health) and str(health.get("db", "")).lower() == "connected"


async def _request(config: dict[str, Any], method: str, path: str, what: str, **kw: Any) -> httpx.Response:
    """One authenticated call to the gateway; transport failures and 4xx/5xx are GatewayErrors."""
    try:
        async with _client(config) as c:
            r = await c.request(method, path, **kw)
    except httpx.HTTPError as e:
        raise GatewayError(f"could not {what}: gateway unreachable: {type(e).__name__}: {e}") from e
    _raise_for(r, what)
    return r


async def list_models(config: dict[str, Any]) -> list[str]:
    r = await _request(config, "GET", "/v1/models", "list models")
    try:
        data = r.json().get("data") or []
    except ValueError as e:
        raise GatewayError("could not list models: no JSON") from e
    return sorted({str(m.get("id")) for m in data if isinstance(m, dict) and m.get("id")})


async def probe(config: dict[str, Any]) -> tuple[bool, str, dict[str, Any]]:
    """(ok, message, health). ok means reachable, authenticated and able to enforce budgets."""
    try:
        health = await readiness(config)
    except GatewayError as e:
        return False, str(e), {}
    health["checked_at"] = now().isoformat()
    try:
        models = await list_models(config)
    except (httpx.HTTPError, GatewayError, ValueError) as e:
        return False, f"reachable but the master key was refused or /v1/models failed: {e}", health
    health["models"] = models
    if not enforces_budgets(health):
        return False, (f"LiteLLM {health.get('version') or ''} reports its database {health['db']!r}. Budgets are "
                       "not enforced without a database; no key will be minted until it is connected."), health
    return True, f"LiteLLM {health.get('version') or ''}: database connected, {len(models)} models.", health


def _raise_for(r: httpx.Response, what: str) -> None:
    if r.status_code >= 400:
        try:
            body = r.json()
            msg = body.get("error", body) if isinstance(body, dict) else body
            if isinstance(msg, dict):
                msg = msg.get("message", msg)
        except ValueError:
            msg = r.text[:300]
        raise GatewayError(f"could not {what}: HTTP {r.status_code}: {msg}")


async def ensure_user(config: dict[str, Any], agent: Agent) -> None:
    """The agent as a LiteLLM internal user carrying the per-agent budget window. Idempotent: the
    budget is re-applied on every mint so a change on the resource page reaches upstream."""
    budget = agent_budget_of(config)
    body = {"user_id": user_id(agent), "user_alias": f"keywright:{agent.name}",
            "max_budget": budget["max_budget"], "budget_duration": budget["budget_duration"]}
    try:
        async with _client(config) as c:
            r = await c.get("/user/info", params={"user_id": user_id(agent)})
    except httpx.HTTPError as e:
        raise GatewayError(f"could not look the agent up: gateway unreachable: {type(e).__name__}: {e}") from e
    # A missing user is a 404 on current LiteLLM and a 200 with a null user_info on older ones.
    try:
        info = r.json() if r.status_code == 200 else {}
    except ValueError:
        info = {}
    exists = isinstance(info, dict) and info.get("user_info") is not None
    if exists:
        await _request(config, "POST", "/user/update", "update the agent's budget", json=body)
    else:
        await _request(config, "POST", "/user/new", "create the agent's budget",
                       json={**body, "user_role": "internal_user", "auto_create_key": False})


async def generate_key(config: dict[str, Any], agent: Agent, models: list[str], expires_at: datetime,
                       limits: dict[str, Any], alias: str, metadata: dict[str, Any]) -> str:
    seconds = max(60, int((expires_at - now()).total_seconds()))
    body: dict[str, Any] = {"key_alias": alias, "user_id": user_id(agent), "models": list(models),
                            "duration": f"{seconds}s", "metadata": {"keywright": metadata}}
    body.update({k: v for k, v in limits.items() if k in LIMIT_KEYS and v is not None})
    r = await _request(config, "POST", "/key/generate", "generate a key", json=body)
    try:
        key = r.json().get("key")
    except ValueError:
        key = None
    if not isinstance(key, str) or not key:
        raise GatewayError("gateway returned no key")
    return key


async def delete_key(config: dict[str, Any], key: str) -> None:
    try:
        await _request(config, "POST", "/key/delete", "delete a key", json={"keys": [key]})
    except GatewayError as e:
        if "HTTP 404" not in str(e):  # already gone upstream is the outcome wanted
            raise


async def update_key_models(config: dict[str, Any], key: str, models: list[str]) -> None:
    await _request(config, "POST", "/key/update", "narrow a key", json={"key": key, "models": list(models)})


async def key_spend(config: dict[str, Any], key: str) -> dict[str, Any] | None:
    """{"spend": float, "max_budget": float|None} from /key/info, or None when unavailable."""
    try:
        async with _client(config, timeout=5.0) as c:
            r = await c.get("/key/info", params={"key": key})
            if r.status_code != 200:
                return None
            info = r.json().get("info") or {}
        return {"spend": float(info.get("spend") or 0.0), "max_budget": info.get("max_budget")}
    except (httpx.HTTPError, ValueError, TypeError):
        return None


# ---- lifecycle around grants --------------------------------------------------------------------
def llm_grants(grants: list[Grant]) -> list[Grant]:
    return [g for g in grants if g.pattern.split("/", 1)[0] == "llm"]


async def mint_for_grants(db: AsyncSession, agent: Agent, grants: list[Grant], *, request_id: str | None,
                          reason: str = "") -> list[LlmKey]:
    """One virtual key per gateway for the LLM grants of one approval. Added to `db` but not
    committed: the caller commits the approval and the keys together, or rolls both back. Raises
    GatewayError when any gateway cannot mint; keys already minted upstream are deleted again."""
    by_gateway: dict[str, list[Grant]] = {}
    for g in llm_grants(grants):
        by_gateway.setdefault(g.pattern.split("/")[1], []).append(g)
    if not by_gateway:
        return []
    resources = {r.name: r for r in (await db.execute(
        select(Resource).where(Resource.kind == "llm", Resource.name.in_(by_gateway)))).scalars().all()}
    minted: list[tuple[LlmKey, Resource]] = []
    try:
        for name, members in by_gateway.items():
            res = resources.get(name)
            if res is None:
                raise GatewayError(f"no LLM gateway named {name}")
            health = await readiness(res.config)
            if not enforces_budgets(health):
                raise GatewayError(f"{name}: LiteLLM reports its database {health['db']!r}; budgets would not be "
                                   "enforced, so no key is minted. Connect the database and decide again.")
            models = models_for(res, [g.pattern for g in members])
            if not models:
                raise GatewayError(f"{name}: none of the gateway's models match; refresh the model list on the "
                                   "resource page (Test connection)")
            expires = min((g.expires_at for g in members if g.expires_at), default=None)
            if expires is None:
                raise GatewayError(f"{name}: an LLM grant needs a duration; choose timed or session access")
            limits = limits_of(res.config)
            await ensure_user(res.config, agent)
            alias = f"kw:{agent.name}:{request_id or members[0].id}:{name}"[:100]
            key = await generate_key(res.config, agent, models, expires, limits, alias,
                                     {"agent": agent.name, "request_id": request_id, "reason": reason[:200],
                                      "grant_ids": [g.id for g in members]})
            row = LlmKey(resource_id=res.id, agent_id=agent.id, request_id=request_id, grant_ids=[g.id for g in members],
                         key=key, key_alias=alias, models=models, limits=limits, expires_at=expires)
            db.add(row)
            minted.append((row, res))
    except GatewayError:
        for row, res in minted:
            try:
                await delete_key(res.config, row.key)
            except GatewayError as e:
                log.warning("could not clean up key %s after a failed mint: %s", row.key_alias, e)
            db.expunge(row)
        raise
    return [row for row, _ in minted]


async def revoke_for_grants(db: AsyncSession, grant_ids: list[str], *, via: str = "ui") -> int:
    """Grants are gone; take the keys with them. A key whose grants are only partly revoked is
    narrowed to the models still granted. Upstream failures are logged and audited, never hidden:
    the row is marked revoked regardless so the broker stops using it."""
    if not grant_ids:
        return 0
    wanted = set(grant_ids)
    rows = [k for k in (await db.execute(select(LlmKey).where(LlmKey.revoked_at.is_(None)))).scalars().all()
            if wanted & set(k.grant_ids or [])]
    n = 0
    for row in rows:
        res = await db.get(Resource, row.resource_id)
        remaining_ids = [g for g in (row.grant_ids or []) if g not in wanted]
        remaining = (await db.execute(select(Grant).where(Grant.id.in_(remaining_ids), Grant.revoked_at.is_(None)))
                     ).scalars().all() if remaining_ids else []
        outcome = "revoked"
        try:
            if remaining and res is not None:
                keep = models_for(res, [g.pattern for g in remaining])
                if keep:
                    await update_key_models(res.config, row.key, keep)
                    row.models, row.grant_ids = keep, [g.id for g in remaining]
                    outcome = "narrowed"
                else:
                    await delete_key(res.config, row.key)
            elif res is not None:
                await delete_key(res.config, row.key)
        except GatewayError as e:
            log.error("LiteLLM key %s could not be %s upstream: %s", row.key_alias, outcome, e)
            outcome = f"{outcome}_locally_only"
        if outcome != "narrowed":
            row.revoked_at = now()
        n += 1
        await audit.record(db, tool="llm.key", decision=outcome, patterns=[f"llm/{res.name}" if res else "llm"],
                           detail={"key_alias": row.key_alias, "agent_id": row.agent_id, "models": row.models,
                                   "via": via, "error": None if outcome in ("revoked", "narrowed") else "upstream"},
                           commit=False)
    return n


async def revoke_for_agent(db: AsyncSession, agent_id: str, *, via: str) -> int:
    rows = (await db.execute(select(LlmKey).where(LlmKey.agent_id == agent_id, LlmKey.revoked_at.is_(None)))
            ).scalars().all()
    ids = [g for k in rows for g in (k.grant_ids or [])]
    return await revoke_for_grants(db, ids, via=via) if ids else 0


async def revoke_for_resource(db: AsyncSession, res: Resource, *, via: str) -> int:
    rows = (await db.execute(select(LlmKey).where(LlmKey.resource_id == res.id, LlmKey.revoked_at.is_(None)))
            ).scalars().all()
    ids = [g for k in rows for g in (k.grant_ids or [])]
    return await revoke_for_grants(db, ids, via=via) if ids else 0


async def active_keys(db: AsyncSession, res: Resource) -> list[LlmKey]:
    at = now()
    rows = (await db.execute(select(LlmKey).where(LlmKey.resource_id == res.id, LlmKey.revoked_at.is_(None))
                             .order_by(LlmKey.created_at.desc()))).scalars().all()
    return [k for k in rows if k.is_active(at)]


def exposure(keys: list[LlmKey], spend: dict[str, dict[str, Any] | None]) -> float:
    """If every active key were spent to its ceiling right now, this much more could go: the
    number that matters more than what was spent."""
    total = 0.0
    for k in keys:
        cap = (k.limits or {}).get("max_budget")
        if cap is None:
            continue
        s = (spend.get(k.id) or {}).get("spend") or 0.0
        total += max(0.0, float(cap) - float(s))
    return total
