"""Permission paths and glob patterns.

Paths are slash-separated:  ssh/<host>/exec/<bin>[/<sub>...]   mcp/<server>/tools/<tool>
                            llm/<gateway>/model/<model>

Pattern rules:
  *   matches exactly one segment
  **  matches zero or more segments (only meaningful as the last segment)
  a pattern without wildcards also matches any path it is a segment-prefix of,
  so granting `ssh/nvr/exec/docker` covers `ssh/nvr/exec/docker/ps`.
  a segment may end in * to match a prefix: `entity_id=light.*` matches `entity_id=light.kitchen`.

MCP calls are qualified by argument values when the resource names argument keys:
  mcp/<server>/tools/<tool>/<key>=<value>   one path per configured key present in the call
so `mcp/ha/tools/call_service` (a literal prefix) still covers every call, while a deny on
`mcp/ha/tools/call_service/service=automation.turn_off` blocks only that service.
"""

from __future__ import annotations

import re

PATTERN_HELP = (
    "Pattern syntax: slash-separated segments, ssh/<host>/exec/<command>[/<sub>], "
    "mcp/<server>/tools/<tool>[/<key>=<value>] or llm/<gateway>/model/<model>. `*` alone matches one whole segment; `**` matches "
    "everything below and must be last; a segment may END in `*` to match a prefix (tools/ha_get_*, "
    "entity_id=light.*) but `*` cannot appear elsewhere in a segment. A literal pattern also covers "
    "everything under it. Allowed characters: letters, digits and _ . : @ + = , - (no spaces). Each pattern "
    "must name one concrete resource: the first two segments cannot be wildcards."
)

KINDS = ("ssh", "mcp", "llm")

_SEGMENT = re.compile(r"^[A-Za-z0-9_.:@+=,-]+\*?$|^\*$|^\*\*$")
_VALUE_CHARS = re.compile(r"[^A-Za-z0-9_.:@+=,-]")


def validate(pattern: str) -> str:
    pattern = pattern.strip().strip("/")
    if not pattern:
        raise ValueError("empty pattern")
    parts = pattern.split("/")
    for i, seg in enumerate(parts):
        if not _SEGMENT.match(seg):
            raise ValueError(f"invalid segment {seg!r} in {pattern!r}")
        if seg == "**" and i != len(parts) - 1:
            raise ValueError("** is only allowed as the last segment")
    if parts[0] not in KINDS and parts[0] not in ("*", "**"):
        raise ValueError("pattern must start with ssh/, mcp/ or llm/")
    return pattern


def matches(pattern: str, path: str) -> bool:
    p = pattern.strip("/").split("/")
    t = path.strip("/").split("/")
    if p and p[-1] == "**":
        head = p[:-1]
        return len(t) >= len(head) and all(_seg(a, b) for a, b in zip(head, t, strict=False))
    if len(t) == len(p):
        return all(_seg(a, b) for a, b in zip(p, t, strict=True))
    # implicit prefix rule for literal (and value-glob) patterns
    if len(t) > len(p) and not any(s in ("*", "**") for s in p):
        return all(_seg(a, b) for a, b in zip(p, t, strict=False))
    return False


def _seg(pat: str, seg: str) -> bool:
    if pat == "*" or pat == seg:
        return True
    return pat.endswith("*") and len(pat) > 1 and seg.startswith(pat[:-1])


def _is_glob(seg: str) -> bool:
    return seg.endswith("*") and len(seg) > 1 and seg != "**"


def _seg_covers(allowed: str, required: str) -> bool:
    """Every concrete segment matched by `required` is matched by `allowed`."""
    if allowed == "*" or allowed == required:
        return True
    if _is_glob(allowed):
        base = allowed[:-1]
        return required.startswith(base) if not _is_glob(required) else required[:-1].startswith(base)
    return False


def _seg_overlaps(a: str, b: str) -> bool:
    if a == "*" or b == "*" or a == b:
        return True
    pa, pb = (a[:-1] if _is_glob(a) else None), (b[:-1] if _is_glob(b) else None)
    if pa is not None and pb is not None:
        return pa.startswith(pb) or pb.startswith(pa)
    if pa is not None:
        return b.startswith(pa)
    if pb is not None:
        return a.startswith(pb)
    return False


def qualifier(key: str, value: object) -> str:
    """`key=value` segment for an MCP argument. Characters outside the segment alphabet become `_`,
    so a value can never smuggle a wildcard or a path separator into a required path."""
    text = _VALUE_CHARS.sub("_", str(value))[:120] or "_"
    return f"{key}={text}"


def resource_of(path: str) -> tuple[str, str] | None:
    """('ssh', 'nvr') for 'ssh/nvr/exec/ls'. None if the path is too short."""
    parts = path.strip("/").split("/")
    if len(parts) < 2 or parts[0] not in KINDS:
        return None
    return parts[0], parts[1]


def model_segment(model: str) -> str:
    """The path segment for an LLM model name. Provider prefixes such as `openrouter/anthropic/x`
    contain slashes, which are path separators here, so every character outside the segment
    alphabet becomes `_`: `llm/<gateway>/model/openrouter_anthropic_x`."""
    return _VALUE_CHARS.sub("_", model)[:120] or "_"


def specificity(pattern: str) -> int:
    """Higher = more specific. Used to prefer narrow grants when several match."""
    parts = pattern.strip("/").split("/")
    score = 0
    for s in parts:
        score += 0 if s == "**" else 1 if s == "*" else 2 if _is_glob(s) else 3
    return score


def _shape(pattern: str) -> tuple[list[str], bool]:
    parts = pattern.strip("/").split("/")
    if parts[-1] == "**":
        return parts[:-1], True
    return parts, not any(p == "*" for p in parts)


def overlaps(left: str, right: str) -> bool:
    """Whether two scopes share any concrete path (including implicit literal prefixes)."""
    a, a_tail = _shape(left)
    b, b_tail = _shape(right)
    if (len(a) < len(b) and not a_tail) or (len(b) < len(a) and not b_tail):
        return False
    return all(_seg_overlaps(x, y) for x, y in zip(a, b, strict=False))


def covers(allowed: str, required: str) -> bool:
    """Whether the entire required scope is contained in the allowed scope."""
    a, a_tail = _shape(allowed)
    b, b_tail = _shape(required)
    if len(a) > len(b) or (not a_tail and (b_tail or len(a) != len(b))):
        return False
    return all(_seg_covers(x, y) for x, y in zip(a, b, strict=False))
