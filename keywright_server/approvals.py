"""Request lifecycle: create -> notify -> (human decides) -> grant/policy -> waiters wake up."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
from datetime import timedelta
from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from keywright.hazards import blocks
from keywright.patterns import overlaps, resource_of
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from . import actions, audit, events, llm
from .access import (
    binds_exactly,
    hazard_level,
    operation_constraints,
    operation_matches,
    operations,
    path_scoped,
    target_of,
)
from .config import settings
from .models import AccessRequest, Agent, Grant, Policy, Resource, now

log = logging.getLogger(__name__)

TTL_PRESETS = {"ttl15": 900, "ttl30": 1800, "ttl": 3600}
SCOPES = ("once", "session", "ttl15", "path15", "ttl30", "ttl", "always", "deny", "deny_always")
PHONE_SCOPES = ("once", "session", "ttl15", "path15", "ttl30", "ttl", "deny")
SCOPE_LABELS = {"once": "Allow once", "session": "This session", "ttl15": "15 minutes", "path15": "This path, 15 min",
                "ttl30": "30 minutes", "ttl": "1 hour", "always": "Always allow",
                "deny": "Deny", "deny_always": "Always deny"}


def decision_label(req: AccessRequest) -> str:
    if req.decision_scope == "ttl" and req.decision_options:
        minutes = req.decision_options["ttl_s"] // 60
        return "1 hour" if minutes == 60 else f"{minutes} minute{'' if minutes == 1 else 's'}"
    return SCOPE_LABELS.get(req.decision_scope, req.decision_scope or "Pending")


_waiters: dict[str, asyncio.Event] = {}
_waiter_counts: dict[str, int] = {}
_serializer: URLSafeTimedSerializer | None = None


def _ser() -> URLSafeTimedSerializer:
    global _serializer
    if _serializer is None:
        _serializer = URLSafeTimedSerializer(settings.secret_key(), salt="decision")
    return _serializer


def decision_token(request_id: str, scope: str) -> str:
    if scope not in PHONE_SCOPES:
        raise ValueError("Permanent approval requires the admin UI")
    return _ser().dumps({"r": request_id, "s": scope})


def parse_decision_token(token: str, max_age: int | None = None) -> tuple[str, str] | None:
    try:
        d = _ser().loads(token, max_age=max_age or settings.request_timeout_s)
    except (BadSignature, SignatureExpired):
        return None
    if not isinstance(d, dict) or not isinstance(d.get("r"), str) or d.get("s") not in PHONE_SCOPES:
        return None
    return d["r"], d["s"]


def notification_action(request_id: str, scope: str) -> str:
    """Compact authenticated phone action; the 128-bit MAC cannot be derived from a request ID."""
    if scope not in PHONE_SCOPES:
        raise ValueError("Permanent approval requires the admin UI")
    return _action("KW", request_id, scope)


def _action(prefix: str, request_id: str, scope: str) -> str:
    return actions.sign(f"{prefix}_{scope.upper()}_{request_id}")


def parse_notification_action(action: str) -> tuple[str, str] | None:
    """Accepts KW_ actions and, for one release, GK_ actions from notifications sent before the rename."""
    try:
        body, _ = action.rsplit(".", 1)
        prefix, scope, rid = body.split("_", 2)
        if prefix not in ("KW", "GK") or scope.lower() not in PHONE_SCOPES:
            return None
        if hmac.compare_digest(action, _action(prefix, rid, scope.lower())):
            return rid, scope.lower()
    except (ValueError, TypeError):
        pass
    return None


NO_SESSION_NOTE = ("No session id on this connection, so 'This session' cannot be granted. Send an "
                   "X-Keywright-Session header (one value per process) to enable it; until then the human "
                   "can choose Allow once or timed access (15 minutes, 30 minutes, or 1 hour).")


HAZARD_SCOPES = ("once", "deny", "deny_always")
# An LLM lease is a virtual key with a lifetime and a spend ceiling. "Once" has no lifetime to give
# it and "always" would be a key nobody minted; both wait for the LLM proxy, which meters calls.
LLM_SCOPES = ("session", "ttl15", "ttl30", "ttl", "deny", "deny_always")


def llm_only(patterns: list[str]) -> bool:
    return bool(patterns) and all(p.split("/", 1)[0] == "llm" for p in patterns)


def offered_scopes(req: AccessRequest, scopes: tuple[str, ...] = PHONE_SCOPES) -> tuple[str, ...]:
    """Scopes a human can pick for this request. A request made on a connection with no session
    id cannot be granted 'this session': there is nothing to bind the grant to, and an agent-wide
    grant would outlive the conversation that asked for it. A request flagged destructive can only
    be allowed once: nothing timed, nothing standing. An LLM lease is always timed."""
    if blocks(hazard_level(req.detail)):
        scopes = tuple(s for s in scopes if s in HAZARD_SCOPES)
    if llm_only(list(req.patterns)):
        scopes = tuple(s for s in scopes if s in LLM_SCOPES)
    scopes = tuple(s for s in scopes if s != "path15" or path_scoped(req.detail))
    return tuple(s for s in scopes if s != "session" or req.session_id)


def decision_links(request_id: str, scopes: tuple[str, ...] = PHONE_SCOPES) -> dict[str, str]:
    base = public_url()
    return {s: f"{base}/d/{decision_token(request_id, s)}" for s in scopes}


def public_url() -> str:
    from .settings_store import cached_public_url

    return (cached_public_url() or settings.public_url or f"http://localhost:{settings.port}").rstrip("/")


async def find_pending(db: AsyncSession, agent: Agent, patterns: list[str],
                       session_id: str | None = None, detail: dict | None = None) -> AccessRequest | None:
    """Reuse an identical pending request instead of spamming the phone."""
    q = select(AccessRequest).where(
        AccessRequest.agent_id == agent.id, AccessRequest.status == "pending",
        AccessRequest.expires_at > now(), AccessRequest.session_id == session_id
    ).order_by(AccessRequest.created_at.desc())
    for r in (await db.execute(q)).scalars().all():
        if list(r.patterns) == list(patterns) and r.detail == (detail or {}):
            return r
    return None


async def recently_denied(db: AsyncSession, agent: Agent, patterns: list[str], within_s: int = 600) -> AccessRequest | None:
    """The cooldown keys on patterns alone: a reworded command or a switch to access_request must
    not put a denied operation straight back in front of the human."""
    cutoff = now() - timedelta(seconds=within_s)
    q = select(AccessRequest).where(
        AccessRequest.agent_id == agent.id, AccessRequest.status == "denied", AccessRequest.decided_at >= cutoff
    )
    for r in (await db.execute(q)).scalars().all():
        if set(r.patterns) >= set(patterns):
            return r
    return None


async def create(
    db: AsyncSession,
    agent: Agent,
    session_id: str | None,
    patterns: list[str],
    reason: str,
    detail: dict[str, Any] | None = None,
    *,
    semantic: dict[str, Any] | None = None,
    notify: bool = True,
) -> AccessRequest:
    """`notify=False` is for a request that is decided in the same breath (Jev trust mode): the
    phone would otherwise get a prompt and its cancellation a moment apart."""
    req = AccessRequest(
        agent_id=agent.id,
        session_id=session_id,
        patterns=list(patterns),
        reason=reason[:2000],
        detail=detail or {},
        semantic=semantic,
        expires_at=now() + timedelta(seconds=settings.request_timeout_s),
    )
    db.add(req)
    await db.commit()
    await db.refresh(req)
    await audit.record(db, tool="access.request", decision="pending", agent=agent, session_id=session_id,
                       patterns=patterns, detail={"request_id": req.id, "reason": reason})
    from .notify.manager import manager

    if notify:
        await manager.notify_request(req, agent)
    events.publish("request.created", id=req.id)
    return req


async def wait(request_id: str, timeout_s: float) -> None:
    # Events accelerate local decisions; polling also observes another worker's decisions.
    # No events are allocated for requests nobody is waiting on.
    ev = _waiters.setdefault(request_id, asyncio.Event())
    _waiter_counts[request_id] = _waiter_counts.get(request_id, 0) + 1
    deadline = asyncio.get_running_loop().time() + max(0, timeout_s)
    from .db import session

    try:
        while True:
            async with session() as db:
                req = await db.get(AccessRequest, request_id)
                if req is None or req.status != "pending" or (req.expires_at and req.expires_at <= now()):
                    return
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return
            try:
                await asyncio.wait_for(ev.wait(), timeout=min(remaining, 1))
                return
            except TimeoutError:
                pass
    finally:
        _waiter_counts[request_id] -= 1
        if not _waiter_counts[request_id]:
            _waiter_counts.pop(request_id)
            _waiters.pop(request_id, None)


async def decide(
    db: AsyncSession,
    request_id: str,
    scope: str,
    *,
    via: str,
    deny_reason: str = "",
    ttl_s: int = 3600,
    extent: str | None = None,
) -> AccessRequest:
    if scope not in SCOPES:
        raise ValueError(f"unknown scope {scope!r}")
    # "This path, 15 min": the listed pattern (host and path) for 15 minutes, whatever the contents.
    # The one phone button that broadens beyond the exact operation, offered only where the
    # pattern is as narrow as a file path.
    path_grant = scope == "path15"
    if path_grant:
        scope = "ttl15"
    if scope in ("always", "deny_always") and via != "ui":
        raise ValueError("Permanent approval requires the admin UI")
    if extent not in (None, "exact", "patterns"):
        raise ValueError("Choose exact operation or permission patterns")
    if via != "ui" and extent is not None:
        raise ValueError("Changing operation scope requires the admin UI")
    if scope in TTL_PRESETS:
        ttl_s = TTL_PRESETS[scope] if scope != "ttl" else ttl_s
        if type(ttl_s) is not int or not 60 <= ttl_s <= 3600:
            raise ValueError("Temporary access must last between 1 minute and 1 hour")
        scope = "ttl"
    req = await db.get(AccessRequest, request_id)
    if req is None:
        raise LookupError("no such request")
    if req.status != "pending":
        return req
    if path_grant:
        if not path_scoped(req.detail):
            raise ValueError("Path access is only offered for a single file write")
        extent = "patterns"
    extent = extent or ("exact" if binds_exactly(req.detail) else "patterns")
    if extent == "exact" and not binds_exactly(req.detail):
        raise ValueError("This request specifies permission patterns, not an exact operation")
    if blocks(hazard_level(req.detail)):
        if scope not in HAZARD_SCOPES:
            raise ValueError("Flagged as destructive: it can be allowed once or denied, never for a duration")
        if extent != "exact":
            raise ValueError("Flagged as destructive: approval binds to the exact operation shown")
    # One (patterns, constraints) pair per operation; a pattern request is one pair with none.
    bound = [(pats if pats is not None else list(req.patterns), operation_constraints(op, extent), op)
             for pats, op in operations(req.detail)] or [(list(req.patterns), None, None)]
    if scope == "session" and not req.session_id:
        raise ValueError("This request has no session id; choose Allow once or 1 hour instead")
    if scope not in LLM_SCOPES and any(p.split("/", 1)[0] == "llm" for p in req.patterns):
        raise ValueError("LLM access is a timed lease: choose this session, 15 or 30 minutes, or 1 hour")
    if req.expires_at and req.expires_at <= now():
        await db.execute(update(AccessRequest).where(
            AccessRequest.id == request_id, AccessRequest.status == "pending",
        ).values(status="expired").execution_options(synchronize_session=False))
        await db.commit()
        await db.refresh(req)
        _wake(req.id)
        events.publish("request.decided", id=req.id, status=req.status)
        return req

    if scope not in ("deny", "deny_always"):
        identity = await db.get(Agent, req.agent_id, populate_existing=True)
        if identity is None or identity.disabled:
            raise ValueError("Agent is disabled or deleted")
        resources = {r.path_prefix: r for r in (await db.execute(select(Resource))).scalars().all()}
        policies = (await db.execute(select(Policy).where(
            (Policy.agent_id == req.agent_id) | Policy.agent_id.is_(None)))).scalars().all()
        for pats, _, op in bound:
            for pattern in pats:
                rp = resource_of(pattern)
                res = resources.get("/".join(rp)) if rp else None
                if res is None or (res.default_mode == "locked" and scope != "always"):
                    raise ValueError("Resource is missing or locked; update its rules in the admin UI")
                if any(p.effect == "deny" and overlaps(p.pattern, pattern)
                       and operation_matches(p.constraints, op or target_of(res))
                       for p in policies):
                    raise ValueError("A standing deny rule now covers this request")
    decided_at = now()
    changed = await db.execute(update(AccessRequest).where(
        AccessRequest.id == request_id, AccessRequest.status == "pending",
        (AccessRequest.expires_at.is_(None)) | (AccessRequest.expires_at > decided_at),
    ).values(status="denied" if scope in ("deny", "deny_always") else "approved", decided_at=decided_at,
             decision_scope=scope, decided_via=via,
             decision_options={"extent": extent, "ttl_s": ttl_s if scope == "ttl" else None}
             ).execution_options(synchronize_session=False))
    if changed.rowcount != 1:
        await db.rollback()
        await db.refresh(req)
        return req
    await db.refresh(req)
    if scope in ("deny", "deny_always"):
        req.status = "denied"
        req.deny_reason = deny_reason[:500]
        if scope == "deny_always":
            for pats, constraints, _ in bound:
                for p in pats:
                    db.add(Policy(agent_id=req.agent_id, pattern=p, effect="deny", constraints=constraints,
                                  request_id=req.id,
                                  created_by=via, note=f"from request {req.id}: {req.reason[:120]}"))
    else:
        req.status = "approved"
        new_grants: list[Grant] = []
        for pats, constraints, _ in bound:
            for p in pats:
                if scope == "always":
                    db.add(Policy(agent_id=req.agent_id, pattern=p, effect="allow", constraints=constraints,
                                  request_id=req.id, created_by=via,
                                  note=f"from request {req.id}: {req.reason[:120]}"))
                    continue
                g = Grant(
                    agent_id=req.agent_id,
                    pattern=p,
                    constraints=constraints,
                    scope=scope,
                    session_id=req.session_id if scope == "session" else None,
                    expires_at=(decided_at + timedelta(seconds=ttl_s)) if scope == "ttl"
                    else (decided_at + timedelta(seconds=settings.session_grant_ttl_s)) if scope == "session"
                    else None,
                    uses_remaining=1 if scope == "once" else None,
                    request_id=req.id,
                )
                db.add(g)
                new_grants.append(g)
        await db.flush()
        # The lease and its key are one decision: a gateway that cannot mint (unreachable, or no
        # database to enforce budgets against) leaves the request pending for the human to see.
        try:
            keys = await llm.mint_for_grants(db, identity, new_grants, request_id=req.id, reason=req.reason)
        except llm.GatewayError as e:
            await db.rollback()  # the request stays pending; whoever is waiting keeps waiting
            raise ValueError(f"Not approved. {e}") from e
        for k in keys:
            await audit.record(db, tool="llm.key", decision="minted", agent=identity, session_id=req.session_id,
                               patterns=[g.pattern for g in new_grants if g.id in k.grant_ids],
                               detail={"request_id": req.id, "key_alias": k.key_alias, "models": k.models,
                                       "limits": k.limits, "expires_at": k.expires_at.isoformat()}, commit=False)
    await db.commit()
    await audit.record(db, tool="access.decide", decision=req.status, agent=req.agent, session_id=req.session_id,
                       patterns=list(req.patterns), detail={"request_id": req.id, "scope": scope, "via": via,
                                                            "deny_reason": deny_reason,
                                                            **req.decision_options})
    _wake(req.id)
    from .notify.manager import manager

    await manager.request_decided(req)
    events.publish("request.decided", id=req.id, status=req.status, via=via, label=decision_label(req))
    return req


def _wake(request_id: str) -> None:
    ev = _waiters.pop(request_id, None)
    if ev:
        ev.set()


async def expire_stale(db: AsyncSession) -> int:
    expired = list((await db.execute(update(AccessRequest).where(
        AccessRequest.status == "pending", AccessRequest.expires_at <= now(),
    ).values(status="expired").returning(AccessRequest.id))).scalars())
    await db.commit()
    if expired:
        # Take the dead buttons off the phone: an expired request can no longer be decided.
        from .notify.manager import manager

        for req in (await db.execute(select(AccessRequest).where(AccessRequest.id.in_(expired)))).scalars():
            with contextlib.suppress(Exception):
                await manager.request_decided(req)
    for rid in expired:
        _wake(rid)
        events.publish("request.decided", id=rid, status="expired")
    return len(expired)


async def revoke_grant(db: AsyncSession, grant_id: str, via: str = "ui") -> Grant | None:
    g = await db.get(Grant, grant_id)
    if g and g.revoked_at is None:
        g.revoked_at = now()
        await db.commit()
        await audit.record(db, tool="grant.revoke", decision="revoked", patterns=[g.pattern],
                           detail={"grant_id": g.id, "agent_id": g.agent_id, "via": via})
        if g.pattern.startswith("llm/"):
            await llm.revoke_for_grants(db, [g.id], via=via)
            await db.commit()
    return g


async def revoke_request_grants(db: AsyncSession, request_id: str) -> int:
    """Revoke all remaining grants from one approval in a single transaction."""
    grants = (await db.execute(select(Grant).where(
        Grant.request_id == request_id, Grant.revoked_at.is_(None)))).scalars().all()
    at = now()
    for g in grants:
        g.revoked_at = at
        await audit.record(db, tool="grant.revoke", decision="revoked", patterns=[g.pattern],
                           detail={"grant_id": g.id, "agent_id": g.agent_id,
                                   "request_id": request_id, "via": "ui"}, commit=False)
    await db.commit()
    if any(g.pattern.startswith("llm/") for g in grants):
        await llm.revoke_for_grants(db, [g.id for g in grants], via="ui")
        await db.commit()
    return len(grants)
