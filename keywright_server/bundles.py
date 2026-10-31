"""Named sets of patterns an MCP resource owner defines, e.g. read-only / control / destructive.

Stored in the resource config as {"bundles": {name: ["tools/ha_get_*", ...]}} with entries relative
to the resource. An agent asks for `mcp/<server>/bundle/<name>` and Keywright expands it before
evaluation; the human sees the request grouped by bundle. Bundles are a request-time convenience:
rules and grants are always on the expanded patterns.
"""
from __future__ import annotations

import re

from keywright.patterns import validate

NAME = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
MAX_BUNDLES = 32
MAX_ENTRIES = 64

# Verb heuristics for "suggest bundles" from an upstream tool list. Generic, not server-specific.
_VERBS = {
    "read-only": ("get", "list", "search", "find", "read", "describe", "show", "query", "check", "status", "history",
                  "render", "export", "fetch", "lookup"),
    "control": ("call", "run", "execute", "trigger", "manage", "start", "stop", "toggle", "turn", "send", "notify",
                "play", "press", "enable", "disable"),
    "destructive": ("remove", "delete", "restart", "reboot", "reset", "wipe", "purge", "uninstall", "shutdown"),
    "config-write": ("set", "config", "create", "update", "write", "add", "edit", "rename", "install", "upload",
                     "import", "apply", "assign", "patch", "put", "save"),
}


def parse(text: str, resource_name: str) -> dict[str, list[str]]:
    """`name: entry, entry` per line -> {name: [entry, ...]}; entries are validated as full paths."""
    out: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"expected 'name: pattern, pattern' but got {line!r}")
        name, rest = (s.strip() for s in line.split(":", 1))
        if not NAME.match(name) or name in out:
            raise ValueError(f"bad or duplicate bundle name {name!r}")
        entries: list[str] = []
        for e in (x.strip() for x in rest.replace("\t", ",").split(",")):
            if not e:
                continue
            e = e.strip("/")
            e = e.removeprefix(f"mcp/{resource_name}/")
            full = validate(f"mcp/{resource_name}/{e}")
            rel = full[len(f"mcp/{resource_name}/"):]
            if not rel.startswith("tools/") or len(rel.split("/")) < 2:
                raise ValueError(f"bundle entry {e!r} must be tools/<tool>[/<key>=<value>]")
            if rel not in entries:
                entries.append(rel)
        if not entries:
            raise ValueError(f"bundle {name!r} is empty")
        if len(entries) > MAX_ENTRIES:
            raise ValueError(f"bundle {name!r} has more than {MAX_ENTRIES} entries")
        out[name] = entries
    if len(out) > MAX_BUNDLES:
        raise ValueError(f"more than {MAX_BUNDLES} bundles")
    return out


def format_text(bundles: dict[str, list[str]] | None) -> str:
    return "\n".join(f"{name}: {', '.join(entries)}" for name, entries in (bundles or {}).items())


def expand(resource_name: str, bundles: dict[str, list[str]] | None, name: str) -> list[str] | None:
    entries = (bundles or {}).get(name)
    if entries is None:
        return None
    return [f"mcp/{resource_name}/{e}" for e in entries]


def suggest(tool_names: list[str]) -> dict[str, list[str]]:
    """Group upstream tools by the verb in their name. A starting point for the owner to edit."""
    out: dict[str, list[str]] = {}
    for tool in sorted(set(tool_names)):
        words = [w for w in re.split(r"[_\-.]+|(?<=[a-z])(?=[A-Z])", tool) if w]
        lowered = [w.lower() for w in words]
        chosen = None
        for bucket, verbs in _VERBS.items():
            if any(w in verbs or any(w.startswith(v) for v in verbs if len(v) >= 4) for w in lowered):
                chosen = bucket
                break
        out.setdefault(chosen or "other", []).append(f"tools/{tool}")
    return {k: v for k, v in out.items() if v}
