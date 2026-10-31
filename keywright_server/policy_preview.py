"""Read-only policy comparisons over bounded, already-scrubbed audit evidence."""

from __future__ import annotations

import re
from collections import Counter
from datetime import timedelta

from keywright import hazards
from keywright.classify import classify_mcp
from sqlalchemy import select

from . import policy
from .models import AccessRequest, Agent, AuditEvent, Grant, Policy, Resource, now

WINDOW_DAYS = 30
SAMPLE_LIMIT = 200
CALL_TOOLS = ("ssh_run", "ssh_put", "ssh_get", "ssh_capture", "mcp_call", "llm.call")
LABELS = {"allow": "Allowed", "deny": "Denied", "pending": "Needs approval", "locked": "Locked",
          "unknown": "Unknown resource", "refused": "Refused", "inconclusive": "Inconclusive"}


class Inconclusive(ValueError):
    """A fixed, safe explanation that never includes recorded input."""


def _incomplete(value) -> bool:
    if isinstance(value, dict):
        return any(_incomplete(v) for v in value.values())
    if isinstance(value, list):
        return any(_incomplete(v) for v in value)
    return isinstance(value, str) and (value == "***" or bool(re.search(r"\.\.\. \[\d+ more\]$", value)))


def _operation(event: AuditEvent, resources: dict[str, Resource]) -> tuple[list[str], dict]:
    # These are the same pure operation builders the live SSH gate uses. No execution,
    # upstream discovery, approval lookup for missing evidence, or semantic evaluation.
    from .mcp_server import _capture_operation, _get_operation, _run_operation, _user_patterns

    d = event.detail
    if not isinstance(d, dict):
        raise Inconclusive("Operation details are missing.")
    if event.tool == "llm.call":
        raise Inconclusive("LLM lease and budget checks are not replayed in this preview.")
    res = resources.get(d.get("resource_id"))
    if res is None:
        raise Inconclusive("Recorded target identity is missing or no longer exists.")
    if event.tool == "mcp_call":
        if res.kind != "mcp" or d.get("server") != res.name:
            raise Inconclusive("Recorded target no longer matches the resource.")
        if not isinstance(d.get("tool"), str) or not d["tool"] or not isinstance(d.get("arguments"), dict):
            raise Inconclusive("Tool name or arguments are missing.")
        op = {k: d[k] for k in ("resource_id", "server", "tool", "arguments")}
        if _incomplete(op):
            raise Inconclusive("Operation evidence was redacted or truncated.")
        required = classify_mcp(res.name, d["tool"], d["arguments"], res.config.get("arg_keys"))
        prefix = f"mcp/{res.name}/"
        op["hazards"] = hazards.as_dicts(hazards.scan_mcp(
            d["tool"], [p[len(prefix):] for p in required], res.config.get("hazard_tools")))
        return required, op
    if res.kind != "ssh" or d.get("host") != res.name:
        raise Inconclusive("Recorded target no longer matches the resource.")
    keys = ["resource_id", "host", "user"]
    keys += ["command"] if event.tool in ("ssh_run", "ssh_capture") else ["path"]
    if event.tool == "ssh_capture":
        keys += ["to_resource_id", "to_host", "to_user", "to_path", "append"]
    if event.tool == "ssh_put":
        keys += ["sha256", "bytes"]
    if any(k not in d for k in keys):
        raise Inconclusive("Recorded operation is missing required fields.")
    op = {k: d[k] for k in keys}
    if _incomplete(op):
        raise Inconclusive("Operation evidence was redacted or truncated.")
    if any(not isinstance(op[k], str) or not op[k] for k in keys if k not in ("bytes", "append")):
        raise Inconclusive("Recorded operation has invalid fields.")
    if event.tool == "ssh_run":
        return _run_operation(res, op["command"], op["user"])
    if event.tool == "ssh_get":
        return _get_operation(res, op["path"], op["user"])
    if event.tool == "ssh_capture":
        dst = resources.get(op["to_resource_id"])
        if dst is None or dst.kind != "ssh" or dst.name != op["to_host"]:
            raise Inconclusive("Recorded destination is missing or has changed.")
        if type(op["append"]) is not bool:
            raise Inconclusive("Recorded append mode is invalid.")
        return _capture_operation(res, op["command"], op["user"], dst, op["to_path"],
                                  op["to_user"], op["append"])
    if event.tool == "ssh_put":
        from .ssh import remote_path

        if not re.fullmatch(r"[a-f0-9]{64}", op["sha256"]) or type(op["bytes"]) is not int or op["bytes"] < 0:
            raise Inconclusive("Recorded file digest or size is invalid.")
        op["path"] = remote_path(op["path"])
        required = [f"ssh/{res.name}/put{op['path']}", *_user_patterns(res, op["user"])]
        op["hazards"] = hazards.as_dicts(hazards.scan(op))
        return required, op
    raise Inconclusive("This operation type is not supported.")


async def preview(db, candidate: Policy, *, additional: tuple[Policy, ...] = ()) -> dict:
    """Compare independent calls at one fixed time; never attach the candidate to db."""
    at = now()
    since = at - timedelta(days=WINDOW_DAYS)
    q = select(AuditEvent).where(AuditEvent.ts >= since, AuditEvent.ts <= at,
                                AuditEvent.tool.in_(CALL_TOOLS))
    if candidate.agent_id:
        q = q.where(AuditEvent.agent_id == candidate.agent_id)
    events = list((await db.execute(q.order_by(AuditEvent.ts.desc(), AuditEvent.id.desc())
                                   .limit(SAMPLE_LIMIT + 1))).scalars())
    agents = {a.id: a for a in (await db.execute(select(Agent))).scalars()}
    resources = {r.id: r for r in (await db.execute(select(Resource))).scalars()}
    by_path = {r.path_prefix: r for r in resources.values()}
    policies = list((await db.execute(select(Policy))).scalars())
    grants = list((await db.execute(select(Grant).where(Grant.revoked_at.is_(None)))).scalars())
    request_ids = {g.request_id for g in grants if g.scope == "once" and g.request_id}
    requests = {r.id: r for r in (await db.execute(select(AccessRequest).where(
        AccessRequest.id.in_(request_ids)))).scalars()} if request_ids else {}
    rows, counts = [], Counter(changed=0, unchanged=0, inconclusive=0)
    for event in events[:SAMPLE_LIMIT]:
        row = {"id": event.id, "ts": event.ts, "agent": event.agent_name, "tool": event.tool,
               "before": "inconclusive", "after": "inconclusive", "reason": "", "changed": False}
        try:
            agent = agents.get(event.agent_id)
            if agent is None:
                raise Inconclusive("Recorded agent no longer exists.")
            required, operation = _operation(event, resources)
            if not required:
                raise Inconclusive("No permission paths could be reconstructed.")
            applicable = [p for p in policies if p.agent_id in (None, agent.id)]
            if hazards.worst(operation.get("hazards")) == "critical":
                # The live tool gate refuses these before policy evaluation.
                row.update(before="refused", after="refused", reason="Critical operation guard.")
            else:
                kwargs = {"grants": [g for g in grants if g.agent_id == agent.id], "resources": by_path,
                          "requests": requests, "at": at, "operation": operation}
                before, _ = policy.decide(agent, event.session_id, required, policies=applicable, **kwargs)
                after, _ = policy.decide(agent, event.session_id, required,
                                         policies=[*applicable, candidate, *additional], **kwargs)
                row.update(before=before.status, after=after.status)
            row["changed"] = row["before"] != row["after"]
            counts["changed" if row["changed"] else "unchanged"] += 1
        except Inconclusive as exc:
            row["reason"] = str(exc)
            counts["inconclusive"] += 1
        except (ValueError, TypeError, KeyError):
            # Exception text from classifiers can contain the original input. Do not echo it.
            row["reason"] = "Missing, redacted, truncated, changed-target or unsupported operation evidence."
            counts["inconclusive"] += 1
        rows.append(row)
    return {"rows": rows, "counts": counts, "at": at, "since": since,
            "limited": len(events) > SAMPLE_LIMIT, "limit": SAMPLE_LIMIT, "labels": LABELS}
