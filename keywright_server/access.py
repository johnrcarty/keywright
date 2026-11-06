"""Operation constraints shared by decisions, enforcement, and presentation."""

from __future__ import annotations

import json
from typing import Any


def operation_detail(detail: dict | None) -> dict:
    """The single operation an automatic request was made for; empty for pattern requests and for
    batched requests, whose operations come from `operations()`."""
    if "operations" in (detail or {}):
        return {}
    # Requests from before constraints recorded user=None for the default account; a non-default
    # account always carries its own ssh/<host>/user/<name> pattern, so dropping the key is safe.
    return {k: v for k, v in (detail or {}).items()
            if k not in ("bundles", "hazards") and not (k == "user" and v is None)}


def operations(detail: dict | None) -> list[tuple[list[str] | None, dict]]:
    """(patterns, operation) pairs a decision binds to. A batched access_request stores one entry
    per operation with the patterns it needs; an automatic request has one operation and the
    request's own patterns (None here). Hazard flags travel with the operation for display but are
    never part of what a grant binds to."""
    if "operations" in (detail or {}):
        return [(list(o["patterns"]), {k: v for k, v in o["operation"].items() if k != "hazards"})
                for o in detail["operations"]]
    op = operation_detail(detail)
    return [(None, op)] if op else []


def binds_exactly(detail: dict | None) -> bool:
    return bool(operations(detail))


def path_scoped(detail: dict | None) -> bool:
    """A single file write. Its pattern already names host and path, so approving the patterns for
    a short time means "any contents at this path, briefly": bounded in time instead of pinned to
    a hash, which is what iterating on a script needs."""
    return bool(detail) and "sha256" in detail and "operations" not in detail


def hazards_of(detail: dict | None) -> list[dict]:
    """Every hazard flag on a request or operation, whichever shape it has."""
    if not detail:
        return []
    if "operations" in detail:
        out: list[dict] = []
        for o in detail["operations"]:
            for h in (o.get("operation") or {}).get("hazards") or []:
                if h not in out:
                    out.append(h)
        return out
    return list(detail.get("hazards") or [])


def hazard_level(detail: dict | None) -> str | None:
    from keywright.hazards import worst

    return worst(hazards_of(detail))


def binds_operation(constraints: dict | None) -> bool:
    """Whether constraints pin one exact operation (command, file digest, path or tool arguments),
    as opposed to only the target identity."""
    return bool(constraints) and any(k not in TARGET_KEYS for k in constraints)


TARGET_KEYS = ("resource_id", "host", "user", "server", "gateway", "to_resource_id", "to_host", "to_user")


def target_of(resource) -> dict:
    """What a call with no operation (access_request, tools/list) is compared against: rules bound
    only to this target apply, rules bound to an exact command or arguments do not."""
    if resource.kind == "ssh":
        return {"resource_id": resource.id, "host": resource.name, "user": resource.config.get("user") or "root"}
    if resource.kind == "llm":
        return {"resource_id": resource.id, "gateway": resource.name}
    return {"resource_id": resource.id, "server": resource.name}


def constraints_for(detail: dict | None, extent: str) -> dict | None:
    return operation_constraints(operation_detail(detail), extent)


def operation_constraints(operation: dict | None, extent: str) -> dict | None:
    if not operation:
        return None
    if extent == "exact":
        return operation
    # Broader command/tool patterns still bind to the target identity and SSH account.
    return {k: v for k, v in operation.items() if k in TARGET_KEYS} or None


def operation_matches(constraints: dict | None, operation: dict | None) -> bool:
    if not constraints:
        return True
    if operation is None or not constraints.keys() <= operation.keys():
        return False
    # JSON equality must distinguish true from 1, unlike Python container equality.
    try:
        return json.dumps(constraints, sort_keys=True, allow_nan=False) == json.dumps(
            {k: operation[k] for k in constraints}, sort_keys=True, allow_nan=False)
    except ValueError:
        # NaN and Infinity are not JSON and never equal themselves, so they match nothing.
        return False


def constraint_label(constraints: dict[str, Any] | None) -> str:
    if not constraints:
        return "Permission patterns · any matching arguments"
    if constraints.get("shopping") and not constraints.get("command"):
        return "Shopping session · browsing and cart preparation"
    if "command" in constraints:
        return "Exact command"
    if "arguments" in constraints:
        return "Exact tool arguments"
    if "sha256" in constraints:
        return "Exact file contents"
    if "path" in constraints:
        return "Exact path"
    if "user" in constraints:
        return f"Permission patterns · as {constraints['user']}"
    return "Permission patterns · bound to this target"


def grant_constraints(grant, request=None) -> dict | None:
    """Legacy automatic once grants bind through their request rather than a stored constraint."""
    if grant.constraints:
        return grant.constraints
    if grant.scope == "once" and request and request.decision_options is None:
        return operation_detail(request.detail) or None
    return None
