"""The decision engine.

For every required pattern, in order:
  1. a matching `deny` policy            -> denied
  2. an active grant for this agent      -> allowed (once-grants are consumed in the same transaction)
  3. a matching `allow` policy           -> allowed
  4. the resource's default mode         -> open: allowed / locked: locked / approval: needs a request

An operation flagged high or critical by `hazards` skips 3 and 4 and, in 2, accepts only a once
grant bound to this exact operation: whatever standing access exists, a human has to approve that
command line, and the approval is used up by it. Critical operations never reach here; the tool
layer refuses them before asking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from keywright import patterns as pat
from keywright.hazards import blocks, worst
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from . import llm
from .access import binds_operation, constraint_label, grant_constraints, operation_matches, target_of
from .models import AccessRequest, Agent, Grant, Policy, Resource, now


@dataclass
class Verdict:
    allowed: bool = False
    status: str = "pending"  # allow | deny | locked | pending | unknown
    missing: list[str] = field(default_factory=list)  # patterns needing approval
    denied: list[str] = field(default_factory=list)
    locked: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)  # no such resource
    consumed_grants: list[str] = field(default_factory=list)
    matched: dict[str, str] = field(default_factory=dict)  # pattern -> what allowed it
    bound: dict[str, str] = field(default_factory=dict)  # pattern -> how far that grant or rule reaches
    request_ids: list[str] = field(default_factory=list)
    hazard: str | None = None  # worst hazard level of the operation, if any


async def evaluate(
    db: AsyncSession,
    agent: Agent,
    session_id: str | None,
    required: list[str],
    *,
    consume: bool = True,
    operation: dict | None = None,
    discovery: bool = False,
) -> Verdict:
    """Evaluate `required` for `agent`. With consume=True, matching once-grants are decremented
    and the transaction is committed when everything is allowed."""
    at = now()
    if discovery and consume:
        raise ValueError("Discovery cannot consume grants")
    expected_hash = agent.token_hash
    current = await db.get(Agent, agent.id, populate_existing=True)
    if current is None or current.disabled or current.token_hash != expected_hash:
        return Verdict(status="deny", denied=list(required))
    policies = (
        await db.execute(select(Policy).execution_options(populate_existing=True).where(
            (Policy.agent_id == agent.id) | Policy.agent_id.is_(None)))
    ).scalars().all()
    grants = (
        await db.execute(select(Grant).execution_options(populate_existing=True).where(
            Grant.agent_id == agent.id, Grant.revoked_at.is_(None)))
    ).scalars().all()
    resources = {r.path_prefix: r for r in (await db.execute(
        select(Resource).execution_options(populate_existing=True))).scalars().all()}
    request_ids = {g.request_id for g in grants if g.scope == "once" and g.request_id}
    requests = {r.id: r for r in (await db.execute(
        select(AccessRequest).where(AccessRequest.id.in_(request_ids)))).scalars().all()} if request_ids else {}

    v, to_consume = decide(
        agent, session_id, required, policies=policies, grants=grants, resources=resources,
        requests=requests, at=at, operation=operation, discovery=discovery,
    )
    if v.allowed and consume and to_consume:
        # Conditional updates serialize competing calls in the database, across workers too.
        # Consume each grant once per operation, even if it covers multiple required paths.
        for gid in sorted({g.id for g in to_consume}):
            changed = await db.execute(update(Grant).where(
                Grant.id == gid, Grant.revoked_at.is_(None), Grant.uses_remaining > 0,
                (Grant.expires_at.is_(None)) | (Grant.expires_at > now()),
            ).values(uses_remaining=Grant.uses_remaining - 1).execution_options(synchronize_session=False))
            if changed.rowcount != 1:
                await db.rollback()
                await db.refresh(agent)
                return Verdict(status="pending", missing=list(required))
            v.consumed_grants.append(gid)
        await db.commit()
    return v


def decide(
    agent: Agent,
    session_id: str | None,
    required: list[str],
    *,
    policies: list[Policy],
    grants: list[Grant],
    resources: dict[str, Resource],
    requests: dict[str, AccessRequest],
    at: datetime,
    operation: dict | None = None,
    discovery: bool = False,
) -> tuple[Verdict, list[Grant]]:
    """Pure decision shared by live enforcement and history previews.

    Inputs are the current agent's applicable policies/grants and a resource snapshot.
    The returned grant list is a consumption plan; only evaluate() can spend it.
    """
    if agent.disabled:
        return Verdict(status="deny", denied=list(required)), []
    v = Verdict(hazard=worst(operation.get("hazards")) if operation else None)
    checkout = bool(operation and operation.get("checkout"))
    fresh_only = blocks(v.hazard) or checkout

    def eligible(g: Grant, op: dict) -> bool:
        req = requests.get(g.request_id)
        if checkout and (not req or req.decided_via == "jev" or not (g.constraints or {}).get("checkout")):
            return False
        if req and req.session_id and req.session_id != session_id:
            return False
        return discovery or operation_matches(grant_constraints(g, req), op)

    to_consume: list[Grant] = []
    for path in required:
        rp = pat.resource_of(path)
        res = resources.get(f"{rp[0]}/{rp[1]}") if rp else None
        if res is None:
            v.unknown.append(path)
            continue
        # Without an operation, rules bound to this target still apply; exact-operation rules do not.
        op = operation if operation is not None else target_of(res)
        deny_matches = pat.overlaps if "*" in path else pat.matches
        allow_matches = pat.covers if "*" in path else pat.matches
        if any(p.effect == "deny" and deny_matches(p.pattern, path)
               and operation_matches(p.constraints, op) for p in policies):
            v.denied.append(path)
            continue
        active = [g for g in grants if g.is_active(at, session_id)
                  and allow_matches(g.pattern, path) and eligible(g, op)
                  and (not fresh_only or (g.scope == "once" and binds_operation(grant_constraints(g, requests.get(g.request_id)))))]
        if active:
            # prefer grants that don't get used up, then the most specific one
            active.sort(key=lambda g: (g.scope == "once", -pat.specificity(g.pattern)))
            g = active[0]
            v.matched[path] = f"grant:{g.id}"
            v.bound[path] = constraint_label(grant_constraints(g, requests.get(g.request_id)))
            if g.request_id and g.request_id not in v.request_ids:
                v.request_ids.append(g.request_id)
            if g.scope == "once":
                to_consume.append(g)
            continue
        if fresh_only:
            v.missing.append(path)
            continue
        allow = [p for p in policies if p.effect == "allow" and allow_matches(p.pattern, path)
                 and (discovery or operation_matches(p.constraints, op))]
        if allow:
            v.matched[path] = f"policy:{allow[0].id}"
            v.bound[path] = constraint_label(allow[0].constraints)
            if allow[0].request_id and allow[0].request_id not in v.request_ids:
                v.request_ids.append(allow[0].request_id)
            continue
        if res.default_mode == "open":
            v.matched[path] = "resource:open"
        elif res.default_mode == "locked":
            v.locked.append(path)
        else:
            v.missing.append(path)

    if v.denied:
        v.status = "deny"
    elif v.unknown:
        v.status = "unknown"
    elif v.locked:
        v.status = "locked"
    elif v.missing:
        v.status = "pending"
    else:
        v.status = "allow"
        v.allowed = True
    return v, to_consume


async def effective_access(db: AsyncSession, agent: Agent, session_id: str | None) -> list[dict]:
    """What `access_list_resources` shows: per resource, the agent's current standing."""
    at = now()
    out = []
    resources = (await db.execute(select(Resource).order_by(Resource.kind, Resource.name))).scalars().all()
    policies = (
        await db.execute(select(Policy).execution_options(populate_existing=True).where(
            (Policy.agent_id == agent.id) | Policy.agent_id.is_(None)))
    ).scalars().all()
    grants = (
        await db.execute(select(Grant).execution_options(populate_existing=True).where(
            Grant.agent_id == agent.id, Grant.revoked_at.is_(None)))
    ).scalars().all()
    legacy_ids = {g.request_id for g in grants if g.scope == "once" and not g.constraints and g.request_id}
    legacy_requests = {r.id: r for r in (await db.execute(select(AccessRequest).where(
        AccessRequest.id.in_(legacy_ids)))).scalars().all()} if legacy_ids else {}
    for r in resources:
        if r.config.get("adapter") == "knowledge":
            # Collection names/descriptions are knowledge metadata too. Discover only collections
            # with an available tool; every actual call is still gated independently.
            from .knowledge_mcp import OPERATIONS
            visible = False
            for tool in OPERATIONS:
                verdict = await evaluate(db, agent, session_id, [f"mcp/{r.name}/tools/{tool}"],
                                         consume=False, discovery=True)
                if verdict.status not in ("deny", "locked", "unknown"):
                    visible = True
                    break
            if not visible:
                continue
        prefix = r.path_prefix
        entry = {
            "resource": prefix,
            "kind": r.kind,
            "default": r.default_mode,
            "description": r.description,
            **({"argument_keys": list(r.config.get("arg_keys") or []),
                "bundles": {n: [f"mcp/{r.name}/{e}" for e in es] for n, es in (r.config.get("bundles") or {}).items()}}
               if r.kind == "mcp" else {}),
            **({"models": llm.model_paths(r), "limits_per_lease": llm.limits_of(r.config),
                "agent_budget": llm.agent_budget_of(r.config),
                "budgets_enforced": llm.enforces_budgets(r.config.get("health")),
                "note": "Ask for llm/<gateway>/model/<model> patterns with access_request; an approval is a timed "
                        "lease with a spend ceiling, never once or always."}
               if r.kind == "llm" else {}),
            "allow_rules": sorted({p.pattern for p in policies if p.effect == "allow" and not p.constraints
                                   and _touches(p.pattern, prefix)}),
            "deny_rules": sorted({p.pattern for p in policies if p.effect == "deny" and not p.constraints
                                  and _touches(p.pattern, prefix)}),
            "constrained_rules": [
                {"pattern": p.pattern, "effect": p.effect, "constraints": p.constraints}
                for p in policies if p.constraints and _touches(p.pattern, prefix)
            ],
            "grants": [
                {
                    "pattern": g.pattern,
                    "scope": g.scope,
                    "expires_at": _iso(g.expires_at),
                    "uses_remaining": g.uses_remaining,
                    "constraints": grant_constraints(g, legacy_requests.get(g.request_id)),
                }
                for g in grants
                if g.is_active(at, session_id) and _touches(g.pattern, prefix)
            ],
        }
        out.append(entry)
    return out


def _touches(pattern: str, prefix: str) -> bool:
    p = pattern.split("/")
    q = prefix.split("/")
    return all(a in ("*", "**") or a == b for a, b in zip(p[:2], q, strict=False)) or p[0] == "**"


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None
