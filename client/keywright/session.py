"""Which conversation this call belongs to.

The server scopes "This session" approvals to whatever the client names in X-Keywright-Session,
and Claude Code's stateless MCP transport names nothing. The CLI names it, in this order:

1. KW_SESSION in the environment: automation can set `job:<id>`, Claude Code gets
   `claude:<session_id>` from the SessionStart hook (`kw session-start --hook`) through
   CLAUDE_ENV_FILE. This is the preferred path because it is per conversation.
2. CODEX_THREAD_ID when supplied by Codex: a conversation identity that survives hidden
   process ancestry in a sandbox. Only a bounded, header-safe value is accepted.
3. A per-agent-process fallback: a file named by the nearest non-shell ancestor's
   (pid, start time, boot id), created with O_EXCL and holding a random id. PID reuse cannot
   revive an old identity because the start time differs; stale files are swept on every run.
4. None: the server then offers no "This session" scope, as before the CLI existed.
"""

from __future__ import annotations

import os
import re
import secrets
import sys
from pathlib import Path

SHELLS = {"bash", "sh", "zsh", "dash", "fish", "ksh", "sudo", "env", "timeout", "nohup", "script", "python3",
          "python"}
AGENT_HINTS = {"claude": "claude", "codex": "codex", "cephloom": "cephloom"}
MAX_LEN = 128


def runtime_dir() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR")
    if base and os.access(base, os.W_OK):
        return Path(base) / "keywright"
    return Path(os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")) / "keywright" / "run"


def resolve() -> tuple[str | None, str]:
    """(session value or None, how it was found)."""
    env = os.environ.get("KW_SESSION")
    if env:
        return env[:MAX_LEN], "KW_SESSION"
    thread = os.environ.get("CODEX_THREAD_ID", "")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,121}", thread):
        return f"codex:{thread}", "CODEX_THREAD_ID"
    if not sys.platform.startswith("linux"):
        return None, "none (no /proc on this platform)"
    anchor = _agent_ancestor()
    if anchor is None:
        return None, "none (no agent process found above this shell)"
    pid, start, kind = anchor
    try:
        value = _per_process(pid, start, kind)
    except OSError as e:
        return None, f"none ({e})"
    return value, f"process {pid} ({kind})"


def _proc_field(pid: int) -> tuple[int, str, str] | None:
    """(ppid, comm, starttime) from /proc/<pid>/stat, or None when the process is gone."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    # comm may contain spaces; it is bracketed
    comm = stat[stat.index("(") + 1:stat.rindex(")")]
    rest = stat[stat.rindex(")") + 2:].split()
    return int(rest[1]), comm, rest[19]


def _cmdline(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
    except OSError:
        return ""


def _agent_ancestor() -> tuple[int, str, str] | None:
    pid = os.getppid()
    for _ in range(64):
        if pid <= 1:
            return None
        info = _proc_field(pid)
        if info is None:
            return None
        ppid, comm, start = info
        if comm not in SHELLS:
            line = _cmdline(pid).lower()
            kind = next((k for k, needle in AGENT_HINTS.items() if needle in comm.lower() or needle in line), "shell")
            return pid, start, kind
        pid = ppid
    return None


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()[:8]
    except OSError:
        return "noboot"


def _per_process(pid: int, start: str, kind: str) -> str:
    d = runtime_dir()
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    _sweep(d)
    path = d / f"{pid}-{start}-{_boot_id()}"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_text().strip()
    value = f"{kind}:{secrets.token_urlsafe(12)}"
    with os.fdopen(fd, "w") as f:
        f.write(value)
    return value


def _sweep(d: Path) -> None:
    boot = _boot_id()
    for f in d.iterdir():
        parts = f.name.split("-")
        if len(parts) != 3:
            continue
        pid, start, b = parts
        info = _proc_field(int(pid)) if pid.isdigit() else None
        if b != boot or info is None or info[2] != start:
            try:
                f.unlink()
            except OSError:
                pass


def session_start_hook(payload: dict) -> str | None:
    """Claude Code SessionStart hook: persist the conversation id for later Bash calls.
    Returns the line written, or None when there was nowhere to write it."""
    sid = str(payload.get("session_id") or "").strip()
    target = os.environ.get("CLAUDE_ENV_FILE")
    if not sid or not target:
        return None
    safe = "".join(c for c in sid if c.isalnum() or c in "-_.")[:MAX_LEN - 7]
    line = f"export KW_SESSION=claude:{safe}\n"
    with open(target, "a") as f:
        f.write(line)
    return line.strip()
