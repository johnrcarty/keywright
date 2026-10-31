"""Approval friction from request identities and terminal call evidence, with exact-rule proposals."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import timedelta
from statistics import median

from keywright.patterns import validate
from sqlalchemy import select

from . import audit, policy, policy_preview
from .access import operation_matches
from .models import AccessRequest, Agent, AuditEvent, Policy, Resource, now
from .semantic import SECRET_TEXT

ROW_LIMIT = 2000
MIN_APPROVALS = 3
HUMAN_CHANNELS = frozenset({"ui", "link", "homeassistant", "webhook", "log"})
TOOL_LABELS = {"ssh_run": "SSH command", "ssh_get": "File read", "ssh_put": "File write",
               "ssh_capture": "Host-to-host transfer", "mcp_call": "MCP tool", "llm.call": "LLM call",
               "request": "Access request"}


def fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def request_tool(detail) -> str:
    if not isinstance(detail, dict) or "operations" in detail:
        return "request"
    if "server" in detail:
        return "mcp_call"
    if "gateway" in detail:
        return "llm.call"
    if "host" in detail:
        if "to_host" in detail:
            return "ssh_capture"
        if "command" in detail:
            return "ssh_run"
        if "sha256" in detail:
            return "ssh_put"
        if "path" in detail:
            return "ssh_get"
    return "request"


def evidence(tool, detail, resources):
    """Never recover scrubbed fields or expose operation inputs in report projections."""
    try:
        paths, op = policy_preview._operation(AuditEvent(tool=tool, detail=audit._scrub(detail)), resources)
        if not paths or SECRET_TEXT.search(json.dumps(op, sort_keys=True, allow_nan=False)):
            return None
        return paths, op
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def outcome(event):
    """A permission decision is separate from a result, including allowed calls that failed."""
    detail = event.detail if isinstance(event.detail, dict) else {}
    if event.decision in {"deny", "locked", "refused"}:
        return "blocked"
    if event.decision == "error":
        return "failed"
    if event.decision != "allow":
        return "lifecycle"
    if event.tool == "mcp_call":
        return ("failed" if detail["is_error"] else "succeeded") if type(detail.get("is_error")) is bool else "unknown"
    if type(event.exit_code) is int:
        failed = event.exit_code >= 400 or detail.get("response_complete") is False if event.tool == "llm.call" \
            else event.exit_code != 0
        return "failed" if failed else "succeeded"
    return "unknown"


def _group_key(agent_id, tool, detail, resources, fallback):
    ev = evidence(tool, detail, resources)
    # Missing or scrubbed arguments cannot establish that two operations were identical.
    return (agent_id, tool, fingerprint(ev) if ev else fallback), ev


def _new_group(agent_id, tool, detail, agents, resources):
    detail = detail if isinstance(detail, dict) else {}
    resource = resources.get(detail.get("resource_id")) if isinstance(detail.get("resource_id"), str) else None
    agent = agents.get(agent_id)
    return {"agent_id": agent_id, "agent": agent.name if agent else "Deleted / unknown agent",
            "resource": resource.name if resource else "Unrecorded / removed target",
            "tool": TOOL_LABELS.get(tool, "Access request"), "requests": [], "events": [],
            "statuses": Counter(), "waits": [], "failures": 0, "blocked": 0, "eligible": [],
            "evidence": None, "suggestion": None, "hazard_history": False}


def _eligible(req, ev, at):
    if req.status != "approved" or req.decided_via not in HUMAN_CHANNELS or req.decided_at is None:
        return False
    if not req.created_at <= req.decided_at <= at or req.decision_scope not in {"once", "ttl", "session"}:
        return False
    if not isinstance(req.decision_options, dict) or req.decision_options.get("extent") != "exact" or ev is None:
        return False
    paths, op = ev
    # Keep recorded hazards too, even when the current catalog no longer flags the operation.
    if (req.detail or {}).get("hazards") or op.get("hazards") or any("*" in p for p in paths):
        return False
    # A partially approved request may omit paths; don't broaden it to the whole operation.
    return (isinstance(req.patterns, list) and all(isinstance(p, str) for p in req.patterns)
            and set(req.patterns) == set(paths))


def _proposal(group, agents, resources, policies, at):
    if (len(group["eligible"]) < MIN_APPROVALS or group["statuses"]["denied"]
            or group["failures"] or group["blocked"] or group["hazard_history"]):
        return None
    agent = agents.get(group["agent_id"])
    if agent is None or agent.disabled:
        return None
    paths, op = group["evidence"]
    constraints = {k: v for k, v in op.items() if k != "hazards"}
    applicable = [p for p in policies if p.agent_id in (None, agent.id)]
    state = {"resources": {r.path_prefix: r for r in resources.values()}, "requests": {},
             "grants": [], "at": at, "operation": op}
    # Ignore temporary grants here: an existing lease must not hide whether standing access asks.
    before, _ = policy.decide(agent, None, paths, policies=applicable, **state)
    if before.status != "pending":
        return None
    source = group["eligible"][0]
    try:
        paths = [validate(p) for p in paths]
    except ValueError:
        return None
    rules = [Policy(id=f"preview-{i}", agent_id=agent.id, pattern=p, effect="allow",
                    constraints=constraints, request_id=source.id, created_by="ui",
                    note="Exact operation reviewed in approval friction report") for i, p in enumerate(paths)]
    after, _ = policy.decide(agent, None, paths, policies=[*applicable, *rules], **state)
    if not after.allowed:
        return None
    return {"request_id": source.id, "agent": agent.name, "resource": group["resource"],
            "tool": group["tool"], "support": len(group["eligible"]),
            "examples": [r.id for r in group["eligible"][:5]], "rules": rules,
            # Digest only: raw constraints and resource credentials never enter the review token.
            "fingerprint": fingerprint({"agent": agent.id, "paths": paths, "operation": constraints,
                                        "support": [r.id for r in group["eligible"]],
                                        "targets": [(r.id, r.kind, r.name, r.config) for r in resources.values()
                                                    if r.id in (op.get("resource_id"), op.get("to_resource_id"))],
                                        "policies": [(p.id, p.pattern, p.effect, p.constraints) for p in applicable]})}


async def report(db, start, end, *, agent_id=""):
    at = now()
    if end <= start or end - start > timedelta(days=90):
        raise ValueError("Choose a date range of 1 to 90 days.")
    req_query = select(AccessRequest).where(AccessRequest.created_at >= start, AccessRequest.created_at < end)
    ev_query = select(AuditEvent).where(AuditEvent.ts >= start, AuditEvent.ts < end,
                                      AuditEvent.tool.in_(policy_preview.CALL_TOOLS))
    if agent_id:
        req_query = req_query.where(AccessRequest.agent_id == agent_id)
        ev_query = ev_query.where(AuditEvent.agent_id == agent_id)
    requests = list((await db.scalars(req_query.order_by(AccessRequest.created_at.desc(), AccessRequest.id)
                                     .limit(ROW_LIMIT + 1))).all())
    events = list((await db.scalars(ev_query.order_by(AuditEvent.ts.desc(), AuditEvent.id.desc())
                                   .limit(ROW_LIMIT + 1))).all())
    limited = len(requests) > ROW_LIMIT or len(events) > ROW_LIMIT
    agents = {a.id: a for a in (await db.scalars(select(Agent).order_by(Agent.name))).all()}
    resources = {r.id: r for r in (await db.scalars(select(Resource))).all()}
    policies = list((await db.scalars(select(Policy).order_by(Policy.id))).all())
    groups, totals, coverage = {}, Counter(), Counter()
    waits = []
    for req in requests[:ROW_LIMIT]:
        tool = request_tool(req.detail)
        key, ev = _group_key(req.agent_id, tool, req.detail, resources, "request:" + req.id)
        group = groups.setdefault(key, _new_group(req.agent_id, tool, req.detail, agents, resources))
        group["evidence"] = ev
        if isinstance(req.detail, dict) and req.detail.get("hazards"):
            group["hazard_history"] = True
        status = req.status
        if status == "pending" and req.expires_at is not None and req.expires_at <= at:
            status = "expired"
        if status == "approved":
            status = "human_approved" if req.decided_via in HUMAN_CHANNELS else "other_approved"
        group["statuses"][status] += 1
        totals[status] += 1
        totals["requests"] += 1
        group["requests"].append({"id": req.id, "status": status, "at": req.created_at})
        if req.status in {"approved", "denied"} and req.decided_via in HUMAN_CHANNELS:
            if req.decided_at is not None and req.created_at <= req.decided_at <= at:
                seconds = (req.decided_at - req.created_at).total_seconds()
                group["waits"].append(seconds); waits.append(seconds)
            else:
                coverage["missing_wait"] += 1
        if ev is None:
            coverage["incomplete_requests"] += 1
        if _eligible(req, ev, at):
            group["eligible"].append(req)
    for event in events[:ROW_LIMIT]:
        result = outcome(event)
        totals[result] += 1
        totals["call_records"] += 1
        if result not in {"failed", "blocked"}:
            continue
        key, ev = _group_key(event.agent_id, event.tool, event.detail, resources, "audit:" + str(event.id))
        group = groups.setdefault(key, _new_group(event.agent_id, event.tool, event.detail, agents, resources))
        group["failures" if result == "failed" else "blocked"] += 1
        group["events"].append({"id": event.id, "status": result, "at": event.ts})
        if ev is None:
            coverage["incomplete_events"] += 1
    proposals = {}
    for group in groups.values():
        group["median_wait"] = round(median(group["waits"]), 1) if group["waits"] else None
        if not limited and group["evidence"] is not None:
            proposal = _proposal(group, agents, resources, policies, at)
            if proposal:
                proposals[proposal["request_id"]] = proposal
                group["suggestion"] = {k: proposal[k] for k in ("request_id", "support", "examples")}
        # Strip private inputs before returning report data to templates.
        del group["evidence"], group["eligible"], group["waits"]
    rows = sorted(groups.values(), key=lambda g: (len(g["requests"]) + g["failures"] + g["blocked"]), reverse=True)
    return {"rows": rows, "totals": totals, "coverage": coverage, "proposals": proposals,
            "agents": list(agents.values()), "median_wait": round(median(waits), 1) if waits else None,
            "wait_samples": len(waits), "limited": limited, "limit": ROW_LIMIT,
            "at": at, "start": start, "end": end}


async def save_proposal(db, proposal):
    """Persist only the freshly reconstructed exact rules; caller must verify its review token."""
    added = 0
    for candidate in proposal["rules"]:
        current = list((await db.scalars(select(Policy).where(
            Policy.agent_id == candidate.agent_id, Policy.pattern == candidate.pattern,
            Policy.effect == "allow"))).all())
        if any(operation_matches(p.constraints, candidate.constraints) for p in current):
            continue
        db.add(Policy(agent_id=candidate.agent_id, pattern=candidate.pattern, effect="allow",
                      constraints=candidate.constraints, request_id=candidate.request_id,
                      created_by="ui", note=candidate.note))
        added += 1
    await audit.record(db, tool="policy.suggestion", decision="created",
                       detail={"source_request_id": proposal["request_id"], "rules_added": added,
                               "agent_id": proposal["rules"][0].agent_id,
                               "support": proposal["support"], "extent": "exact"}, commit=False)
    await db.commit()
    return added
