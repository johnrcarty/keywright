"""Claude Code hooks, stdlib only.

PreToolUse on Bash: the hazard tripwire over the whole line, with one refinement for lines that
invoke `kw` itself. The part of a `kw run/put/get/capture` line that is the remote payload is
the server's to judge (it is flagged there, prompted or refused there), so here it only earns a
note. Everything local on the same line (other segments, substitutions, redirections, `get -o`
destinations) is enforced as usual. And `kw setup|login|logout|session-start` always asks,
whatever options precede the subcommand: an agent must not rewrite its own gate.
"""

from __future__ import annotations

import json
import shlex
from typing import Any

from .hazards import Hazard, blocks, describe, scan_command, scan_path, worst

CLI_NAMES = {"kw", "keywright"}
GUARDED = {"setup", "login", "logout", "session-start"}
REMOTE_COMMAND = {"run", "capture"}
GLOBAL_VALUE_OPTS = {"--profile", "-p"}
_SEPARATORS = {";", "|", "||", "&&", "&", "(", ")"}


def _tokens(command: str) -> list[str] | None:
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";|&()<>")
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        return None


def _segments(tokens: list[str]) -> list[list[str]]:
    segs: list[list[str]] = [[]]
    for tok in tokens:
        if tok in _SEPARATORS:
            if segs[-1]:
                segs.append([])
        else:
            segs[-1].append(tok)
    return [s for s in segs if s]


def parse_invocation(words: list[str]) -> dict[str, Any] | None:
    """For a segment that invokes kw: {sub, host, remote, local_writes, local_reads}. None otherwise."""
    if not words or words[0].rsplit("/", 1)[-1] not in CLI_NAMES:
        return None
    i = 1
    while i < len(words) and words[i].startswith("-"):
        if words[i] in GLOBAL_VALUE_OPTS and "=" not in words[i]:
            i += 2
        else:
            i += 1
    if i >= len(words):
        return {"sub": None, "remote": [], "local_writes": [], "local_reads": []}
    sub, rest = words[i], words[i + 1:]
    out: dict[str, Any] = {"sub": sub, "remote": [], "local_writes": [], "local_reads": []}
    if sub in REMOTE_COMMAND:
        if "--" in rest:
            k = rest.index("--")
            out["remote"].append(shlex.join(rest[k + 1:]))
            rest = rest[:k]
        for j, w in enumerate(rest):
            if w in ("-c", "--command") and j + 1 < len(rest):
                out["remote"].append(rest[j + 1])
            if w.startswith(("-c=", "--command=")):
                out["remote"].append(w.split("=", 1)[1])
    positional = [w for w in rest if not w.startswith("-")]
    if sub == "put" and len(positional) >= 2:
        out["remote_write"] = positional[1]
        for j, w in enumerate(rest):
            if w in ("--file", "-f") and j + 1 < len(rest):
                out["local_reads"].append(rest[j + 1])
    if sub == "get":
        if len(positional) >= 2:
            out["remote_read"] = positional[1]
        for j, w in enumerate(rest):
            if w in ("-o", "--output") and j + 1 < len(rest):
                out["local_writes"].append(rest[j + 1])
    return out


def analyze(command: str) -> tuple[list[Hazard], list[Hazard], bool]:
    """(local hazards, server-gated hazards, guarded-subcommand present)."""
    tokens = _tokens(command)
    if tokens is None:
        return scan_command(command), [], False
    segments = _segments(tokens)
    if not any(s[0].rsplit("/", 1)[-1] in CLI_NAMES for s in segments):
        return scan_command(command), [], False
    local_parts: list[str] = []
    remote: list[Hazard] = []
    local_extra: list[Hazard] = []
    guarded = False
    for seg in segments:
        inv = parse_invocation(seg)
        if inv is None:
            local_parts.append(shlex.join(seg))
            continue
        if inv["sub"] in GUARDED:
            guarded = True
        for r in inv["remote"]:
            remote.extend(scan_command(r))
        if inv.get("remote_write"):
            remote.extend(scan_path(inv["remote_write"], "write"))
        if inv.get("remote_read"):
            remote.extend(scan_path(inv["remote_read"], "read"))
        for p in inv["local_writes"]:
            local_extra.extend(scan_path(p, "write"))
        for p in inv["local_reads"]:
            local_extra.extend(scan_path(p, "read"))
        # the invocation minus its payload still takes part in the local scan (cd, pipes around it)
        local_parts.append(shlex.join([w for w in seg if w not in inv["remote"]]).split(" -- ")[0])
    local = scan_command(" ; ".join(local_parts)) + [h for h in local_extra if h not in local_extra[:0]]
    seen: list[Hazard] = []
    for h in local:
        if h not in seen:
            seen.append(h)
    return seen, remote, guarded


def pre_tool_use(payload: dict[str, Any]) -> dict[str, Any] | None:
    if payload.get("tool_name") != "Bash":
        return None
    command = str((payload.get("tool_input") or {}).get("command") or "")
    if not command.strip():
        return None
    local, remote, guarded = analyze(command)
    notes = []
    if local:
        notes.append("local " + describe(local))
    if remote:
        notes.append("server-gated " + describe(remote))
    text = "Keywright hazard check: " + "; ".join(notes) if notes else ""
    if guarded:
        reason = "kw setup/login/logout change the agent's own gate; the human runs them."
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                       "permissionDecisionReason": reason},
                "systemMessage": reason + (" " + text if text else "")}
    level = worst(local)
    if level is None:
        return {"systemMessage": text} if text else None
    if not blocks(level):
        return {"systemMessage": text}
    decision = "deny" if level == "critical" else "ask"
    reason = text + (". Refused: if this must happen, the user runs it by hand." if level == "critical"
                     else ". Flagged as destructive; an existing allow rule does not cover it.")
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                   "permissionDecisionReason": reason},
            "systemMessage": text}


def run_pre_tool_use(stdin_text: str) -> str:
    try:
        payload = json.loads(stdin_text)
    except ValueError:
        return ""
    out = pre_tool_use(payload) if isinstance(payload, dict) else None
    return json.dumps(out) if out else ""
