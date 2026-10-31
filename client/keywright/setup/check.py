"""`kw setup check`: the doctor. Every line is a fact with a verdict; nonzero exit on any failure."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

from .. import __version__, config, session
from .claude_code import LEGACY_HOOK_FILE, mcp_registrations, skill_version
from .codex import BEGIN, END, codex_home
from .common import binary_path, claude_dir, find_hooks, read_json


def _line(ok: bool | None, what: str, detail: str = "") -> tuple[bool | None, str]:
    mark = {True: "ok  ", False: "FAIL", None: "info"}[ok]
    return ok, f"{mark}  {what}" + (f": {detail}" if detail else "")


def integration_checks() -> list[tuple[bool | None, str]]:
    """Check integrations present on this machine, including Codex-only installs."""
    lines = []
    home = claude_dir()
    kw = binary_path()
    has_claude = home.exists() or shutil.which("claude") is not None
    codex_dir = codex_home()
    has_codex = codex_dir.exists() or shutil.which("codex") is not None
    if has_claude:
        settings = read_json(home / "settings.json")
        hooks = find_hooks(settings)
        if hooks:
            stale = [h for h in hooks if kw not in h and "gatekeeper-hazards.py" in h]
            lines.append(_line(not stale, "claude code hooks", "; ".join(hooks)))
            if stale:
                lines.append(_line(False, "legacy hook", "points at a copied file; run `kw setup claude-code`"))
        else:
            lines.append(_line(False, "claude code hooks", "none; run `kw setup claude-code`"))
        if (home / LEGACY_HOOK_FILE).exists():
            lines.append(_line(False, "legacy hook file", f"{home / LEGACY_HOOK_FILE} still present"))
        sv = skill_version(home / "skills" / "keywright" / "SKILL.md")
        lines.append(_line(sv == __version__, "claude code skill", sv or "not installed"))
    else:
        lines.append(_line(None, "claude code", "not installed; skipped"))
    if has_codex:
        # Match Codex's global instruction-file precedence.
        candidates = [codex_dir / "AGENTS.override.md", codex_dir / "AGENTS.md"]
        active = next((p for p in candidates if p.is_file() and p.read_text().strip()), None)
        text = active.read_text() if active else ""
        installed = BEGIN in text and END in text and text.index(BEGIN) < text.index(END)
        detail = str(active) if installed else "Keywright instructions missing from the active global file; run `kw setup codex`"
        lines.append(_line(installed, "codex instructions", detail))
    if not has_claude and not has_codex:
        lines.append(_line(False, "agent integration", "none; run `kw setup codex` or `kw setup claude-code`"))
    regs = mcp_registrations() if has_claude else []
    lines.append(_line(None, "mcp registrations", ", ".join(regs) if regs else "none (CLI only)"))
    return lines


def run(*, profile_name: str | None = None, out=None) -> int:
    out = out or sys.stdout
    lines: list[tuple[bool | None, str]] = []
    lines.append(_line(None, "client", f"keywright {__version__} at {binary_path()}"))

    profile = None
    try:
        profile = config.load(profile_name)
        lines.append(_line(True, "profile", f"{profile.name} -> {profile.mcp_url}"))
    except config.ConfigError as e:
        lines.append(_line(False, "profile", str(e)))
    mode = config.file_mode_ok()
    if mode is not None:
        lines.append(_line(mode, "config file mode", "0600" if mode else f"{config.config_file()} is readable by others"))

    if profile:
        base = profile.mcp_url[: -len("/mcp")]
        try:
            with urllib.request.urlopen(base + "/healthz", timeout=10) as r:
                health = json.loads(r.read().decode())
            lines.append(_line(bool(health.get("ok")), "server", f"{base} version {health.get('version', '?')} "
                                                              f"notifier {health.get('notifier', '?')}"))
            sv = str(health.get("version") or "")
            if sv and sv.split(".")[:2] != __version__.split(".")[:2]:
                lines.append(_line(False, "version match", f"server {sv} vs client {__version__}"))
        except (urllib.error.URLError, ValueError, OSError) as e:
            lines.append(_line(False, "server", f"{base}/healthz unreachable ({e})"))
        try:
            from ..transport import AuthError, TransportError, call, payload

            listing = payload(call(profile, None, "access_list_resources", {}, read_timeout=20))
            lines.append(_line(True, "token", f"agent {listing.get('agent')} sees {len(listing.get('resources', []))} resource(s)"))
        except AuthError:
            lines.append(_line(False, "token", "rejected (401); run `kw login` with a current token"))
        except TransportError as e:
            lines.append(_line(False, "token", f"could not call the server ({e})"))

    value, source = session.resolve()
    lines.append(_line(None, "session", f"{value or 'none'} ({source})"))

    lines.extend(integration_checks())
    for tool in ("claude", "codex"):
        path = shutil.which(tool)
        if path:
            try:
                ver = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=10, check=False).stdout.strip()
            except (OSError, subprocess.TimeoutExpired):
                ver = "?"
            lines.append(_line(None, tool, ver.splitlines()[0] if ver else path))

    failed = any(ok is False for ok, _ in lines)
    for _, text in lines:
        out.write(text + "\n")
    return 1 if failed else 0
