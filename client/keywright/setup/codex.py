"""`kw setup codex`: teach Codex the CLI through a marked section in ~/.codex/AGENTS.md; MCP
registration only on request (Codex has MCP, the CLI is simply the better fit for long approvals)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from .claude_code import skill_text
from .common import Changes

BEGIN = "<!-- keywright:begin -->"
END = "<!-- keywright:end -->"


def codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME") or str(Path.home() / ".codex"))


def _section() -> str:
    body = skill_text().split("---", 2)[-1].strip()
    return f"{BEGIN}\n{body}\n{END}\n"


def apply(*, mcp: str = "none", url: str | None = None, dry_run: bool = False, out=None) -> int:
    out = out or sys.stdout
    ch = Changes(dry_run)
    path = codex_home() / "AGENTS.md"
    text = path.read_text() if path.exists() else ""
    if BEGIN in text and END in text:
        head, _, tail = text.partition(BEGIN)
        _, _, tail = tail.partition(END)
        text = head + _section() + tail.lstrip("\n")
    else:
        text = (text.rstrip("\n") + "\n\n" if text.strip() else "") + _section()
    ch.edit_text(path, text)
    if mcp == "keep":
        if not url:
            raise SystemExit("--mcp keep needs a profile (run `kw login` first)")
        ch.note("run: codex mcp add keywright --url <url> --bearer-token-env-var KEYWRIGHT_TOKEN "
                "(export KEYWRIGHT_TOKEN in the shell that starts Codex)")
        if not dry_run:
            subprocess.run(["codex", "mcp", "add", "keywright", "--url", url, "--bearer-token-env-var",
                            "KEYWRIGHT_TOKEN"], check=False)
    ch.apply(out)
    return 0


def uninstall(*, dry_run: bool = False, out=None) -> int:
    out = out or sys.stdout
    ch = Changes(dry_run)
    path = codex_home() / "AGENTS.md"
    if path.exists():
        text = path.read_text()
        if BEGIN in text:
            head, _, tail = text.partition(BEGIN)
            _, _, tail = tail.partition(END)
            ch.edit_text(path, head.rstrip("\n") + ("\n" + tail if tail.strip() else "\n"))
    ch.apply(out)
    return 0
