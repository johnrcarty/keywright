"""Human-readable access inventory, including all authorization sources and restrictions."""

from __future__ import annotations

import math
from collections import defaultdict

from keywright.patterns import covers, overlaps
from sqlalchemy import select

from .access import constraint_label, grant_constraints
from .models import AccessRequest, Agent, Grant, Policy, Resource, now


def remaining(expires_at, at) -> str:
    if expires_at is None:
        return "Until used or revoked"
    seconds = (expires_at - at).total_seconds()
    return "Expired" if seconds <= 0 else f"{max(1, math.ceil(seconds / 60))}m remaining"


async def overview(db) -> dict:
    at = now()
    agents = (await db.execute(select(Agent).order_by(Agent.name))).scalars().all()
    resources = (await db.execute(select(Resource).order_by(Resource.kind, Resource.name))).scalars().all()
    policies = (await db.execute(select(Policy).order_by(Policy.pattern))).scalars().all()
    # Spent and expired grants are never revoked, so they pile up; leave them in the database.
    grants = (await db.execute(select(Grant).where(
        Grant.revoked_at.is_(None),
        (Grant.expires_at.is_(None)) | (Grant.expires_at > at),
        (Grant.uses_remaining.is_(None)) | (Grant.uses_remaining > 0),
    ).order_by(Grant.created_at.desc()))).scalars().all()
    grants = [g for g in grants if g.is_active(at, g.session_id)]
    request_ids = {g.request_id for g in grants if g.request_id}
    requests = {r.id: r for r in (await db.execute(select(AccessRequest).where(
        AccessRequest.id.in_(request_ids)))).scalars().all()} if request_ids else {}
    groups = defaultdict(list)
    for g in grants:
        groups[(g.agent_id, g.request_id or g.id)].append(g)
    leases = []
    for (agent_id, _), members in groups.items():
        first = members[0]
        req = requests.get(first.request_id)
        leases.append({"agent_id": agent_id, "request": req, "grants": members,
                       "constraints": grant_constraints(first, req),
                       "label": constraint_label(grant_constraints(first, req)),
                       "remaining": remaining(first.expires_at, at), "scope": first.scope,
                       "session_id": first.session_id})
    # Match every rule and grant against every target once, not once per agent.
    scopes = {res.id: res.path_prefix + "/**" for res in resources}
    rules_on = {rid: [p for p in policies if overlaps(p.pattern, scope)] for rid, scope in scopes.items()}
    grants_on = {rid: [g for g in grants if overlaps(g.pattern, scope)] for rid, scope in scopes.items()}
    by_agent = []
    for agent in agents:
        targets = []
        for res in resources:
            scope = scopes[res.id]
            relevant = [p for p in rules_on[res.id] if p.agent_id in (None, agent.id)]
            allows = [p for p in relevant if p.effect == "allow"]
            denies = [p for p in relevant if p.effect == "deny"]
            temporary = [g for g in grants_on[res.id] if g.agent_id == agent.id]
            if agent.disabled:
                state = "Suspended · new operations blocked"
            elif any(not p.constraints and covers(p.pattern, scope) for p in denies):
                state = "Denied for this target"
            elif res.default_mode == "open":
                state = "Allowed by default"
            elif allows or temporary:
                state = "Scoped access"
            elif res.default_mode == "locked":
                state = "Locked · standing rule required"
            else:
                state = "Approval required"
            targets.append({"resource": res, "state": state, "allows": allows, "denies": denies,
                            "temporary": len(temporary), "has_restrictions": bool(denies)})
        by_agent.append({"agent": agent, "targets": targets,
                         "leases": [g for g in leases if g["agent_id"] == agent.id]})
    return {"access_agents": by_agent, "lease_count": len(leases), "target_count": len(resources),
            "agent_count": len(agents)}


# ---- the Grants page: agent -> resource -> approval, newest first ---------------------------------
def grant_groups(grants: list[Grant], agents: dict[str, Agent], requests: dict[str, AccessRequest], at,
                 *, include_inactive: bool = False) -> list[dict]:
    """Grants grouped the way a human reads them: by agent, then by the host or server they reach,
    then by the approval that made them (one decision can grant several paths). Every level is
    ordered by its most recent approval. Inactive grants are left out unless asked for."""
    from keywright.patterns import resource_of

    from . import approvals

    def state(g: Grant) -> str:
        if g.is_active(at, g.session_id):
            return "active"
        return "revoked" if g.revoked_at else "ended"

    kept = [g for g in grants if include_inactive or state(g) == "active"]
    request_resources: dict[str, set[str]] = defaultdict(set)
    for g in grants:
        if g.request_id and state(g) == "active":
            request_resources[g.request_id].add("/".join(resource_of(g.pattern) or ("?", "?")))

    tree: dict[str, dict[str, dict[str, list[Grant]]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for g in kept:
        res = "/".join(resource_of(g.pattern) or ("?", g.pattern))
        tree[g.agent_id][res][g.request_id or f"grant:{g.id}"].append(g)

    def latest(gs):
        return max(g.created_at for g in gs)

    out = []
    for agent_id, by_res in tree.items():
        hosts = []
        for res, by_req in by_res.items():
            approvals_ = []
            for key, gs in by_req.items():
                gs.sort(key=lambda g: g.pattern)
                req = requests.get(gs[0].request_id) if gs[0].request_id else None
                states = {state(g) for g in gs}
                st = "active" if "active" in states else ("revoked" if states == {"revoked"} else "ended")
                expiry = max((g.expires_at for g in gs if g.expires_at), default=None)
                elsewhere = len(request_resources.get(gs[0].request_id or "", set()) - {res})
                approvals_.append({
                    "key": key, "grants": gs, "request": req, "approved_at": latest(gs), "state": st,
                    "label": approvals.decision_label(req) if req else approvals.SCOPE_LABELS.get(gs[0].scope, gs[0].scope),
                    "remaining": remaining(expiry, at) if st == "active" else None,
                    "uses": [g.uses_remaining for g in gs if g.uses_remaining is not None],
                    "session": next((g.session_id for g in gs if g.session_id), None),
                    "constraints": [(g, grant_constraints(g, req)) for g in gs],
                    "revoke": (f"/ui/requests/{req.id}/revoke" if req else f"/ui/grants/{gs[0].id}/revoke")
                    if st == "active" else None,
                    "elsewhere": elsewhere,
                })
            approvals_.sort(key=lambda a: a["approved_at"], reverse=True)
            kind, _, name = res.partition("/")
            hosts.append({"resource": res, "kind": kind, "name": name, "approvals": approvals_,
                          "latest": approvals_[0]["approved_at"],
                          "active": sum(1 for a in approvals_ if a["state"] == "active")})
        hosts.sort(key=lambda h: h["latest"], reverse=True)
        agent = agents.get(agent_id)
        out.append({"agent": agent, "agent_id": agent_id, "name": agent.name if agent else "?", "hosts": hosts,
                    "latest": hosts[0]["latest"], "active": sum(h["active"] for h in hosts)})
    out.sort(key=lambda a: a["latest"], reverse=True)
    return out
