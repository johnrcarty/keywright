"""The Access page and the tool watch: what an MCP server offers, what each agent may do with it,
and what changed upstream since the owner last looked.

Rows are built from the live tool list (or a gateway's models). Each row has one rule path, the
tool's path narrowed by an optional scope such as `account_name=agents` where the tool takes that
argument, and a state per agent: allow, ask (no rule; the resource default decides) or deny.
Saving writes only the difference, as ordinary standing rules, and touches no rule it did not
make the exact shape of: qualified or constrained rules made elsewhere are shown, not edited.

The watch keeps a fingerprint per tool (its input schema and annotations) in the resource
config. A new tool is harmless on its own (no rule covers it, so it asks); a changed one can
matter: an argument added to an allowed tool is not qualified by any argument key the owner set,
so it passes on the tool's rule until the owner looks. Drift is recorded and shown, never acted on.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from keywright.patterns import matches, qualifier

from . import bundles

GROUPS = ("read-only", "write", "destructive", "gone")
STATES = ("allow", "ask", "deny")


# ---- tools -------------------------------------------------------------------------------------
def group_of(tool: Any) -> str:
    """The server's own annotations first (MCP readOnlyHint / destructiveHint), the verb in the
    name when it says nothing."""
    ann = getattr(tool, "annotations", None)
    if ann is not None:
        if getattr(ann, "read_only_hint", None) is True:
            return "read-only"
        if getattr(ann, "destructive_hint", None) is True:
            return "destructive"
        if getattr(ann, "read_only_hint", None) is False and getattr(ann, "destructive_hint", None) is False:
            return "write"
    bucket = next(iter(bundles.suggest([tool.name])))
    return {"read-only": "read-only", "destructive": "destructive"}.get(bucket, "write")


def _schema(tool: Any) -> dict[str, Any]:
    return dict(getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", None) or {})


def arguments(tool: Any) -> list[str]:
    return sorted((_schema(tool).get("properties") or {}).keys())


def takes(tool: Any, key: str) -> bool:
    """Whether a dotted argument key exists in the tool's input schema."""
    node: Any = _schema(tool)
    for part in key.split("."):
        props = node.get("properties") if isinstance(node, dict) else None
        if not isinstance(props, dict) or part not in props:
            return False
        node = props[part]
    return True


def fingerprint(tool: Any) -> dict[str, Any]:
    ann = getattr(tool, "annotations", None)
    body = json.dumps({"schema": _schema(tool), "annotations": ann.model_dump(exclude_none=True) if ann else None},
                      sort_keys=True, default=str)
    return {"hash": hashlib.sha256(body.encode()).hexdigest()[:16], "args": arguments(tool)}


@dataclass
class Drift:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[dict[str, Any]] = field(default_factory=list)  # {tool, new_args, dropped_args}

    def __bool__(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def as_dict(self) -> dict[str, Any]:
        return {"added": self.added, "removed": self.removed, "changed": self.changed}


def diff(seen: dict[str, dict[str, Any]], tools: list[Any]) -> Drift:
    now_fp = {t.name: fingerprint(t) for t in tools}
    d = Drift(added=sorted(set(now_fp) - set(seen)), removed=sorted(set(seen) - set(now_fp)))
    for name in sorted(set(now_fp) & set(seen)):
        old, new = seen[name], now_fp[name]
        if old.get("hash") != new["hash"]:
            d.changed.append({"tool": name,
                              "new_args": sorted(set(new["args"]) - set(old.get("args") or [])),
                              "dropped_args": sorted(set(old.get("args") or []) - set(new["args"]))})
    return d


def baseline(tools: list[Any]) -> dict[str, Any]:
    return {"tools_seen": {t.name: fingerprint(t) for t in tools},
            "tools_seen_at": datetime.now(UTC).isoformat(timespec="seconds"), "tools_drift": None}


def record(config: dict[str, Any], tools: list[Any]) -> tuple[dict[str, Any], Drift | None]:
    """The resource config after a watch pass: the first pass takes a baseline silently; later ones
    store the drift against it (or clear it) and leave the baseline for the owner to accept."""
    seen = config.get("tools_seen")
    if seen is None:
        return {**config, **baseline(tools)}, None
    d = diff(seen, tools)
    stored = {**d.as_dict(), "at": datetime.now(UTC).isoformat(timespec="seconds")} if d else None
    return {**config, "tools_drift": stored}, d


# ---- rows and rules ----------------------------------------------------------------------------
@dataclass
class Row:
    name: str
    group: str
    pattern: str
    description: str = ""
    state: str = "ask"
    everyone: str | None = None           # an every-agent rule on the same path, when viewing one agent
    other_rules: int = 0                  # rules on this tool of another shape (qualified, constrained)
    covered_by: list[str] = field(default_factory=list)  # broader rules that already decide this row
    flag: str | None = None               # new | changed | gone
    new_args: list[str] = field(default_factory=list)


def scoped(base: str, scope: tuple[str, str] | None, tool: Any | None) -> str:
    if scope and tool is not None and takes(tool, scope[0]):
        return f"{base}/{qualifier(scope[0], scope[1])}"
    return base


def parse_scope(text: str, arg_keys: list[str]) -> tuple[str, str] | None:
    text = (text or "").strip()
    if not text:
        return None
    if "=" not in text:
        raise ValueError("Scope is key=value, e.g. account_name=agents")
    key, value = (s.strip() for s in text.split("=", 1))
    if key not in arg_keys:
        raise ValueError(f"{key!r} is not one of this server's argument keys ({', '.join(arg_keys) or 'none set'}); "
                         "add it on the resource first, or rules on it would never match")
    if not value or "*" in value:
        raise ValueError("Scope needs a literal value")
    return key, value


def state_of(policies: list[Any], pattern: str, agent_id: str | None) -> str:
    exact = [p for p in policies if p.pattern == pattern and not p.constraints and p.agent_id == agent_id]
    if any(p.effect == "deny" for p in exact):
        return "deny"
    return "allow" if exact else "ask"


def touches(policy_pattern: str, tool_path: str) -> bool:
    return policy_pattern == tool_path or policy_pattern.startswith(tool_path + "/")


def mcp_rows(res: Any, tools: list[Any], policies: list[Any], agent_id: str | None,
             scope: tuple[str, str] | None) -> list[Row]:
    seen = res.config.get("tools_seen") or {}
    drift = res.config.get("tools_drift") or {}
    changed = {c["tool"]: c for c in drift.get("changed") or []}
    rows = []
    for t in sorted(tools, key=lambda t: t.name):
        base = f"mcp/{res.name}/tools/{t.name}"
        rows.append(_row(t.name, group_of(t), scoped(base, scope, t), base, policies, agent_id,
                         (t.description or "").strip().splitlines()[0][:160] if t.description else "",
                         flag="new" if seen and t.name not in seen else "changed" if t.name in changed else None,
                         new_args=(changed.get(t.name) or {}).get("new_args") or []))
    # Rules on tools the server no longer offers: one row per rule, on its exact path, so Ask
    # removes it whatever its shape.
    live = {t.name for t in tools}
    prefix = f"mcp/{res.name}/tools/"
    stale = sorted({p.pattern for p in policies if p.agent_id == agent_id and not p.constraints
                    and p.pattern.startswith(prefix)
                    and p.pattern[len(prefix):].split("/", 1)[0] not in live | {"*", "**"}})
    for pattern in stale:
        rows.append(_row(pattern[len(prefix):], "gone", pattern, pattern, policies, agent_id,
                         "No longer offered by the server; this rule can go.", flag="gone"))
    return rows


def llm_rows(res: Any, model_paths: dict[str, str], policies: list[Any], agent_id: str | None) -> list[Row]:
    return [_row(m, "models", path, path, policies, agent_id, "") for m, path in model_paths.items()]


def _row(name, group, pattern, base, policies, agent_id, description, flag=None, new_args=None) -> Row:
    mine = [p for p in policies if p.agent_id == agent_id]
    # Rules that match this row's path without being its own: a wildcard or a shorter prefix. They
    # decide the call whatever this row says (a deny anywhere wins), so the page says so.
    covered = [f"{p.effect} {p.pattern}{'' if p.agent_id else ' (every agent)'}" for p in policies
               if (p.agent_id in (agent_id, None)) and not p.constraints and p.pattern != pattern
               and matches(p.pattern, pattern)]
    return Row(covered_by=covered, name=name, group=group, pattern=pattern, description=description,
               state=state_of(policies, pattern, agent_id),
               everyone=(state_of(policies, pattern, None) if agent_id else None),
               other_rules=sum(1 for p in mine if touches(p.pattern, base) and (p.pattern != pattern or p.constraints)),
               flag=flag, new_args=new_args or [])


@dataclass
class Plan:
    add: list[tuple[str, str]] = field(default_factory=list)      # (pattern, effect)
    delete: list[Any] = field(default_factory=list)               # Policy rows

    def __bool__(self) -> bool:
        return bool(self.add or self.delete)


def plan(rows: list[Row], wanted: dict[str, str], policies: list[Any], agent_id: str | None) -> Plan:
    """The rule changes that take each row from its state to the wanted one. Rows not in `wanted`
    (not on the submitted form) are left alone."""
    out = Plan()
    for row in rows:
        want = wanted.get(row.name)
        if want not in STATES or want == row.state:
            continue
        out.delete += [p for p in policies if p.pattern == row.pattern and not p.constraints
                       and p.agent_id == agent_id]
        if want != "ask":
            out.add.append((row.pattern, want))
    return out


# ---- the watch -----------------------------------------------------------------------------------
async def watch_once(db) -> list[tuple[str, Drift]]:
    """One pass over every MCP server: baseline the new ones, record drift on the rest. A server
    that cannot be reached is skipped (its last drift stands). Returns the servers whose drift is
    new since the last pass, which are also written to the audit log."""
    import logging

    from sqlalchemy import select

    from . import audit, mcp_proxy
    from .models import Resource

    log = logging.getLogger("keywright.tools")
    fresh: list[tuple[str, Drift]] = []
    for res in (await db.execute(select(Resource).where(Resource.kind == "mcp"))).scalars().all():
        try:
            tools = await mcp_proxy.list_tools(res.name, res.config, force=True)
        except Exception as e:  # noqa: BLE001
            log.info("tool watch: %s unreachable: %s", res.name, mcp_proxy.describe(e))
            continue
        before = (res.config.get("tools_drift") or {})
        config, d = record(res.config, tools)
        if config == res.config:
            continue
        res.config = config
        await db.commit()
        if d and {k: before.get(k) for k in ("added", "removed", "changed")} != d.as_dict():
            fresh.append((res.name, d))
            log.warning("tool watch: %s changed: %s", res.name, d.as_dict())
            await audit.record(db, tool="tools.drift", decision="changed",
                               detail={"resource": res.name, **d.as_dict()})
    return fresh
