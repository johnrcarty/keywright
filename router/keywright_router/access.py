"""The standing access the rules need, asked for in one request instead of rule by rule.

The paths are built the way Keywright qualifies the calls themselves (the same `classify_mcp`,
the resource's own argument keys), so an "Always allow" on the request is exactly as wide as the
rules file and no wider. Two things are left out on purpose:

- a send or forward whose resource does not qualify calls by `recipients`: allowing the tool
  would allow any recipient, so those calls keep asking one by one;
- replies (the recipient is the sender of each message) and templated argument values (they
  differ per message): the paths that would name them are dropped, so the human sees them per call.

Model access is never part of it: an LLM approval is a timed lease with a spend ceiling, and a
standing model rule is made in the UI.
"""

from __future__ import annotations

import logging
from typing import Any

from keywright.classify import classify_mcp

from .config import PLACEHOLDER, Config
from .kw import Keywright

log = logging.getLogger("keywright_router")

RECIPIENT_KEYS = ("recipients", "cc", "bcc")


def needed(cfg: Config, arg_keys: dict[str, list[str]]) -> list[str]:
    """Every path the rules will call with fixed arguments, qualified by each server's argument keys."""
    acct = {"account_name": cfg.account}
    calls: list[tuple[str, str, dict[str, Any]]] = [
        (cfg.server, "list_emails_metadata", acct),
        (cfg.server, "get_emails_content", acct),
    ]
    actions = [a for r in cfg.rules for a in r.do] + list(cfg.unmatched)
    if actions:
        calls.append((cfg.server, "mark_emails_as_read", acct))
    if cfg.done_folder or any("move" in a for a in actions):
        calls.append((cfg.server, "move_emails", acct))
    email_keys = set(arg_keys.get(cfg.server) or [])
    for action in actions:
        kind, spec = next(iter(action.items()))
        if kind in ("forward", "send"):
            if "recipients" not in email_keys:
                log.info("%s is not qualified by recipients on %s: %s calls will ask each time",
                         kind, cfg.server, kind)
                continue
            tool = "forward_email" if kind == "forward" else "send_email"
            calls.append((cfg.server, tool, {**acct, "recipients": list(spec["to"])}))
        elif kind == "mcp":
            server, tool = spec["tool"].split("__", 1)
            raw, fixed = spec.get("args", {}), _literal(spec.get("args", {})) or {}
            for key in arg_keys.get(server) or []:
                if _lookup(raw, key) is not None and _lookup(fixed, key) is None:
                    log.warning("%s qualifies %s by %s, which this rule fills from the message: "
                                "that call will ask every time", server, tool, key)
            calls.append((server, tool, fixed))
    out: list[str] = []
    for server, tool, args in calls:
        keys = arg_keys.get(server)
        if keys is None:
            log.warning("no MCP resource named %r in Keywright; skipping %s", server, tool)
            continue
        for p in classify_mcp(server, tool, args, keys):
            if p not in out:
                out.append(p)
    return out


def _lookup(args: dict[str, Any], key: str) -> Any:
    cur: Any = args
    for part in key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _literal(value: Any) -> Any:
    """Arguments as the human can pre-approve them: a templated value is unknown until a message
    arrives, so it is removed and never qualifies the path."""
    if isinstance(value, str):
        return None if PLACEHOLDER.search(value) else value
    if isinstance(value, dict):
        return {k: v for k, v in ((k, _literal(v)) for k, v in value.items()) if v is not None}
    if isinstance(value, list):
        return [v for v in (_literal(v) for v in value) if v is not None] or None
    return value


async def argument_keys(kw: Keywright) -> dict[str, list[str]]:
    data = await kw.call_access("access_list_resources", {})
    out = {}
    for r in data.get("resources") or []:
        if r.get("kind") == "mcp":
            out[str(r["resource"]).split("/", 1)[1]] = list(r.get("argument_keys") or [])
    return out


async def ensure(kw: Keywright, cfg: Config) -> tuple[str, str | None, list[str]]:
    """Ask once for whatever the rules need that is not yet allowed. Returns (status, request_id, patterns):
    approved when nothing is missing, pending with the request to watch, or denied."""
    patterns = needed(cfg, await argument_keys(kw))
    if not patterns:
        return "approved", None, []
    data = await kw.call_access("access_request", {
        "patterns": patterns, "wait_seconds": 0,
        "reason": f"mail router: standing access for its {len(cfg.rules)} rule(s). Choose Always allow "
                  "to make these rules; anything else it does keeps asking per call.",
    })
    return str(data.get("status") or data.get("error") or "unknown"), data.get("request_id"), patterns
