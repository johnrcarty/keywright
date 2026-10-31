"""Shared edit machinery: JSON read/merge/write with a timestamped backup, a diff for --dry-run,
and the markers by which our own hook entries and rules are recognized on later runs."""

from __future__ import annotations

import difflib
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

OUR_HOOK_MARKERS = ("kw hazards --hook", "keywright hazards --hook", "gatekeeper-hazards.py",
                    "kw session-start --hook", "keywright session-start --hook")


class Changes:
    """Collects file edits; applies them (with backups) or prints them (dry run)."""

    def __init__(self, dry_run: bool):
        self.dry_run = dry_run
        self.edits: list[tuple[Path, str, str]] = []  # path, before, after
        self.notes: list[str] = []

    def note(self, text: str) -> None:
        self.notes.append(text)

    def edit_json(self, path: Path, data: Any) -> None:
        before = path.read_text() if path.exists() else ""
        after = json.dumps(data, indent=2) + "\n"
        if before != after:
            self.edits.append((path, before, after))

    def edit_text(self, path: Path, after: str) -> None:
        before = path.read_text() if path.exists() else ""
        if before != after:
            self.edits.append((path, before, after))

    def apply(self, out=sys.stdout) -> int:
        for path, before, after in self.edits:
            if self.dry_run:
                diff = difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                            fromfile=str(path), tofile=str(path))
                out.write("".join(diff) or f"(create {path})\n")
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                shutil.copy2(path, path.with_name(f"{path.name}.bak-{int(time.time())}"))
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_text(after)
            os.replace(tmp, path)
            out.write(f"wrote {path}\n")
        for n in self.notes:
            out.write(("would " if self.dry_run else "") + n + "\n")
        return len(self.edits)


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text() or "{}")
    except ValueError as e:
        raise SystemExit(f"{path} is not valid JSON ({e}); fix it before running setup") from e
    if not isinstance(data, dict):
        raise SystemExit(f"{path} does not hold a JSON object")
    return data


def binary_path() -> str:
    """Absolute path of the `kw` script, so hooks work even when ~/.local/bin is not on PATH."""
    for name in ("kw", "keywright"):
        p = shutil.which(name)
        if p:
            return p
    return "kw"


def set_hook(settings: dict[str, Any], event: str, matcher: str | None, command: str, *, timeout: int = 10,
             status: str | None = None) -> None:
    """Add or replace our hook entry for `event`; other people's hooks are untouched."""
    hooks = settings.setdefault("hooks", {})
    entries: list[dict[str, Any]] = hooks.setdefault(event, [])
    ours = {"type": "command", "command": command, "timeout": timeout}
    if status:
        ours["statusMessage"] = status
    for entry in entries:
        if (entry.get("matcher") or None) != matcher:
            continue
        inner = entry.setdefault("hooks", [])
        inner[:] = [h for h in inner if not _is_ours(h)]
        inner.append(ours)
        return
    entry = {"hooks": [ours]}
    if matcher:
        entry["matcher"] = matcher
    entries.append(entry)


def remove_hooks(settings: dict[str, Any]) -> None:
    hooks = settings.get("hooks") or {}
    for event, entries in list(hooks.items()):
        for entry in entries:
            entry["hooks"] = [h for h in entry.get("hooks", []) if not _is_ours(h)]
        hooks[event] = [e for e in entries if e.get("hooks")]
        if not hooks[event]:
            del hooks[event]
    if not hooks and "hooks" in settings:
        del settings["hooks"]


def _is_ours(h: dict[str, Any]) -> bool:
    cmd = str(h.get("command") or "")
    return any(m in cmd for m in OUR_HOOK_MARKERS)


def find_hooks(settings: dict[str, Any]) -> list[str]:
    out = []
    for entries in (settings.get("hooks") or {}).values():
        for entry in entries:
            for h in entry.get("hooks", []):
                if _is_ours(h):
                    out.append(str(h.get("command")))
    return out


def ensure_rules(settings: dict[str, Any], key: str, rules: list[str]) -> None:
    perms = settings.setdefault("permissions", {})
    have: list[str] = perms.setdefault(key, [])
    for r in rules:
        if r not in have:
            have.append(r)


def drop_rules(settings: dict[str, Any], key: str, predicate) -> None:
    perms = settings.get("permissions") or {}
    if key in perms:
        perms[key] = [r for r in perms[key] if not predicate(r)]
        if not perms[key]:
            del perms[key]


def claude_dir() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or str(Path.home() / ".claude"))
