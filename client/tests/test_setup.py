"""`kw setup`: merges into existing settings, backs up, is idempotent, previews with --dry-run,
and removes only what it added."""
import io
import json

import pytest

from keywright import __version__
from keywright.setup import claude_code, codex
from keywright.setup.claude_code import allow_rules

AI_VM_SETTINGS = {
    "permissions": {"allow": ["mcp__gatekeeper__*"]},
    "model": "opus[1m]",
    "effortLevel": "high",
    "autoMode": {"environment": ["### Org-wide", "**Organization**: example"]},
    "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
        {"type": "command", "command": "python3 ~/.claude/hooks/gatekeeper-hazards.py --hook", "timeout": 10,
         "statusMessage": "Gatekeeper hazard check"}]}]},
}


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / ".claude"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))
    monkeypatch.setattr("keywright.setup.common.binary_path", lambda: "/opt/kw/bin/kw")
    monkeypatch.setattr("keywright.setup.claude_code.binary_path", lambda: "/opt/kw/bin/kw")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "hooks").mkdir()
    (tmp_path / ".claude" / "hooks" / "gatekeeper-hazards.py").write_text("# old copy\n")
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps(AI_VM_SETTINGS, indent=2))
    (tmp_path / ".claude.json").write_text(json.dumps({
        "projects": {
            "/root": {"mcpServers": {"gatekeeper": {"type": "http", "url": "https://gk/mcp", "headers": {}}}},
            "/root/Projects/x": {"mcpServers": {"gatekeeper": {"type": "http", "url": "https://gk/mcp"}}, "other": 1},
        },
        "theme": "dark",
    }))
    return tmp_path


def settings(home):
    return json.loads((home / ".claude" / "settings.json").read_text())


def test_apply_merges_and_replaces_the_legacy_hook(home):
    out = io.StringIO()
    assert claude_code.apply(mcp="keep", out=out) == 0
    s = settings(home)
    assert s["model"] == "opus[1m]" and s["autoMode"]["environment"][0] == "### Org-wide"
    bash_hooks = [h["command"] for e in s["hooks"]["PreToolUse"] if e.get("matcher") == "Bash" for h in e["hooks"]]
    assert bash_hooks == ["/opt/kw/bin/kw hazards --hook"]
    start = [h["command"] for e in s["hooks"]["SessionStart"] for h in e["hooks"]]
    assert start == ["/opt/kw/bin/kw session-start --hook"]
    assert "mcp__gatekeeper__*" in s["permissions"]["allow"]  # --mcp keep leaves it
    assert set(allow_rules()) <= set(s["permissions"]["allow"])
    assert "Bash(kw setup *)" not in s["permissions"]["allow"] and "Bash(kw login *)" not in s["permissions"]["allow"]
    assert s["env"]["BASH_DEFAULT_TIMEOUT_MS"] == "600000" and s["env"]["KW_WAIT"] == "540"
    assert not (home / ".claude" / "hooks" / "gatekeeper-hazards.py").exists()
    skill = (home / ".claude" / "skills" / "keywright" / "SKILL.md").read_text()
    assert f"keywright-version: {__version__}" in skill
    assert list((home / ".claude").glob("settings.json.bak-*"))


def test_apply_is_idempotent(home):
    claude_code.apply(mcp="keep", out=io.StringIO())
    before = (home / ".claude" / "settings.json").read_text()
    out = io.StringIO()
    claude_code.apply(mcp="keep", out=out)
    assert (home / ".claude" / "settings.json").read_text() == before
    assert "0 file(s) changed" in out.getvalue()
    assert len(settings(home)["hooks"]["PreToolUse"]) == 1


def test_dry_run_writes_nothing(home):
    before = (home / ".claude" / "settings.json").read_text()
    out = io.StringIO()
    claude_code.apply(mcp="remove", dry_run=True, out=out)
    assert (home / ".claude" / "settings.json").read_text() == before
    assert (home / ".claude" / "hooks" / "gatekeeper-hazards.py").exists()
    assert "+++" in out.getvalue() and "kw hazards --hook" in out.getvalue()
    assert json.loads((home / ".claude.json").read_text())["projects"]["/root"]["mcpServers"]


def test_mcp_remove_drops_every_registration_and_the_blanket_rule(home):
    claude_code.apply(mcp="remove", out=io.StringIO())
    data = json.loads((home / ".claude.json").read_text())
    assert data["projects"]["/root"]["mcpServers"] == {} and "gatekeeper" not in data["projects"]["/root/Projects/x"]["mcpServers"]
    assert data["projects"]["/root/Projects/x"]["other"] == 1 and data["theme"] == "dark"
    assert "mcp__gatekeeper__*" not in settings(home)["permissions"]["allow"]
    assert list(home.glob(".claude.json.bak-*"))


def test_uninstall_removes_only_ours(home):
    claude_code.apply(mcp="keep", out=io.StringIO())
    claude_code.uninstall(out=io.StringIO())
    s = settings(home)
    assert "hooks" not in s and "env" not in s
    assert not any(r.startswith("Bash(kw") for r in s["permissions"].get("allow", []))
    assert s["model"] == "opus[1m]"
    assert not (home / ".claude" / "skills" / "keywright" / "SKILL.md").exists()


def test_codex_section_is_marked_and_idempotent(home):
    (home / ".codex").mkdir()
    (home / ".codex" / "AGENTS.md").write_text("# Mine\n\nkeep this\n")
    codex.apply(out=io.StringIO())
    text = (home / ".codex" / "AGENTS.md").read_text()
    assert text.startswith("# Mine\n\nkeep this\n") and text.count("<!-- keywright:begin -->") == 1
    codex.apply(out=io.StringIO())
    assert (home / ".codex" / "AGENTS.md").read_text().count("<!-- keywright:begin -->") == 1
    codex.uninstall(out=io.StringIO())
    assert "keywright" not in (home / ".codex" / "AGENTS.md").read_text()
    assert "keep this" in (home / ".codex" / "AGENTS.md").read_text()


def test_an_agent_may_ask_for_the_human_without_asking_the_human_first():
    """A permission prompt on `kw ping` would block on the person it exists to go and fetch."""
    from keywright.setup.claude_code import allow_rules

    rules = allow_rules()
    assert "Bash(kw ping *)" in rules and "Bash(kw ping)" in rules
    # The rules cover exactly the subcommands an agent drives, and nothing that reconfigures the box.
    assert not any(sub in r for r in rules for sub in ("setup", "login", "logout"))
