"""`kw setup claude-code`: the hazard hook, the session hook, per-subcommand permission rules,
the skill, and (optionally) the MCP registration, in ~/.claude/settings.json and ~/.claude.json."""

from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path
from typing import Any

from .. import __version__
from .common import (
    Changes,
    binary_path,
    claude_dir,
    drop_rules,
    ensure_rules,
    read_json,
    remove_hooks,
    set_hook,
)

# Subcommands an agent may run unprompted. `ping` belongs here precisely because it is what an
# agent reaches for when nobody is at the keyboard: a permission prompt on it would block on the
# person it exists to go and fetch. It authorizes nothing and the broker rate-limits it.
OPERATIONAL = ("run", "put", "get", "capture", "request", "status", "resources", "tools", "tool", "guide",
               "guides", "ping", "session", "version", "hazards")
MCP_NAMES = ("gatekeeper", "keywright")
LEGACY_HOOK_FILE = "hooks/gatekeeper-hazards.py"


def allow_rules() -> list[str]:
    return [f"Bash({name} {sub} *)" for name in ("kw", "keywright") for sub in OPERATIONAL] + \
           [f"Bash({name} {sub})" for name in ("kw", "keywright") for sub in OPERATIONAL]


def _is_our_rule(rule: str) -> bool:
    return rule.startswith(("Bash(kw ", "Bash(keywright ")) or rule in (f"mcp__{n}__*" for n in MCP_NAMES)


def skill_text() -> str:
    return (Path(__file__).resolve().parent.parent / "skill" / "SKILL.md").read_text()


def apply(*, mcp: str = "keep", url: str | None = None, token: str | None = None, dry_run: bool = False,
          bash_timeout: bool = True, out=None) -> int:
    """mcp: keep (leave any MCP registration alone) | user (register at user scope via `claude mcp add`)
    | remove (drop every gatekeeper/keywright MCP entry and its blanket allow rule)."""
    import sys

    out = out or sys.stdout
    ch = Changes(dry_run)
    home = claude_dir()
    settings_path = home / "settings.json"
    settings = read_json(settings_path)
    kw = binary_path()

    set_hook(settings, "PreToolUse", "Bash", f"{shlex.quote(kw)} hazards --hook", timeout=10,
             status="Keywright hazard check")
    set_hook(settings, "SessionStart", None, f"{shlex.quote(kw)} session-start --hook", timeout=10)
    ensure_rules(settings, "allow", allow_rules())
    if bash_timeout:
        env = settings.setdefault("env", {})
        if "BASH_DEFAULT_TIMEOUT_MS" not in env:
            env["BASH_DEFAULT_TIMEOUT_MS"] = "600000"
        # Claude Code caps a Bash call at 10 minutes; a longer approval wait would push the call into
        # the background. Keep kw's default wait inside that cap, leaving room for the command itself.
        if "KW_WAIT" not in env:
            env["KW_WAIT"] = "540"
    if mcp == "remove":
        drop_rules(settings, "allow", lambda r: r in (f"mcp__{n}__*" for n in MCP_NAMES))
    ch.edit_json(settings_path, settings)

    legacy = home / LEGACY_HOOK_FILE
    if legacy.exists():
        ch.note(f"remove the copied hook file {legacy} (the hook now runs `{kw} hazards --hook`)")
        if not dry_run:
            legacy.unlink()

    skill_path = home / "skills" / "keywright" / "SKILL.md"
    ch.edit_text(skill_path, skill_text())

    claude_json = Path.home() / ".claude.json"
    if mcp == "remove":
        data = read_json(claude_json)
        removed = 0
        for proj in (data.get("projects") or {}).values():
            servers = proj.get("mcpServers") if isinstance(proj, dict) else None
            for name in MCP_NAMES:
                if servers and name in servers:
                    del servers[name]
                    removed += 1
        top = data.get("mcpServers") or {}
        for name in MCP_NAMES:
            if name in top:
                del top[name]
                removed += 1
        if removed:
            ch.note(f"drop {removed} MCP registration(s) from {claude_json}")
            ch.edit_json(claude_json, data)
    elif mcp == "user":
        if not (url and token):
            raise SystemExit("--mcp user needs a profile (run `kw login` first)")
        cmd = ["claude", "mcp", "add", "--scope", "user", "--transport", "http", "keywright", url,
               "--header", f"Authorization: Bearer {token}"]
        ch.note("run: claude mcp add --scope user --transport http keywright <url> --header 'Authorization: Bearer …'")
        if not dry_run:
            subprocess.run(cmd, check=False)
    n = ch.apply(out)
    out.write(f"keywright {__version__}: Claude Code setup {'previewed' if dry_run else 'applied'} "
              f"({n} file(s) changed). Open /hooks once or start a new session to load it.\n")
    return 0


def uninstall(*, keep_config: bool = True, dry_run: bool = False, out=None) -> int:
    import sys

    out = out or sys.stdout
    ch = Changes(dry_run)
    home = claude_dir()
    settings_path = home / "settings.json"
    settings = read_json(settings_path)
    remove_hooks(settings)
    drop_rules(settings, "allow", _is_our_rule)
    env = settings.get("env") or {}
    env.pop("BASH_DEFAULT_TIMEOUT_MS", None)
    env.pop("KW_WAIT", None)
    if not env and "env" in settings:
        del settings["env"]
    ch.edit_json(settings_path, settings)
    skill = home / "skills" / "keywright" / "SKILL.md"
    if skill.exists():
        ch.note(f"remove {skill}")
        if not dry_run:
            skill.unlink()
    ch.apply(out)
    return 0


def describe(settings: dict[str, Any]) -> dict[str, Any]:
    """What `kw setup check` reports about a settings document."""
    from .common import find_hooks

    allow = (settings.get("permissions") or {}).get("allow") or []
    return {
        "hooks": find_hooks(settings),
        "allow_rules": [r for r in allow if _is_our_rule(r)],
        "bash_timeout": (settings.get("env") or {}).get("BASH_DEFAULT_TIMEOUT_MS"),
        "kw_wait": (settings.get("env") or {}).get("KW_WAIT"),
    }


def skill_version(path: Path) -> str | None:
    if not path.exists():
        return None
    for line in path.read_text().splitlines()[:8]:
        if line.startswith("keywright-version:"):
            return line.split(":", 1)[1].strip()
    return "unknown"


def mcp_registrations() -> list[str]:
    data = read_json(Path.home() / ".claude.json")
    found = []
    for name in MCP_NAMES:
        if name in (data.get("mcpServers") or {}):
            found.append(f"user:{name}")
        for proj, cfg in (data.get("projects") or {}).items():
            if isinstance(cfg, dict) and name in (cfg.get("mcpServers") or {}):
                found.append(f"{proj}:{name}")
    return found


def as_json(data: Any) -> str:
    return json.dumps(data, indent=2)
