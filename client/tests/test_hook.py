"""The PreToolUse hook: local effects enforced, remote payloads deferred to the server, and the
subcommands that rewrite the agent's own gate always asking."""
import json
import subprocess
import sys

import pytest

from keywright.hook import analyze, parse_invocation, pre_tool_use, run_pre_tool_use


def decision(command: str):
    out = pre_tool_use({"tool_name": "Bash", "tool_input": {"command": command}})
    if out is None:
        return None, ""
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision"), out.get("systemMessage", "")


@pytest.mark.parametrize("command,expected", [
    ("kw run dev -- uptime; rm -r" + "f ~", "deny"),                       # local wipe next to a kw call
    ("kw get dev /tmp/f -o /etc/profile", "ask"),                          # local write to a startup file
    ("kw run dev -- rm -r" + "f /opt/*", None),                            # remote payload: server-gated, note only
    ("kw put dev /etc/sudoers.d/x --file x", None),                        # remote path: server-gated
    ("kw --profile x setup uninstall", "ask"),                             # guarded whatever precedes it
    ("kw login https://x --paste", "ask"),
    ("cd /tmp && kw run dev -- ls | grep x", None),
    ("ls -la", None),
    ("rm -r" + "f ~", "deny"),                                             # no kw at all: unchanged behaviour
    ("git push --force", "ask"),
])
def test_decisions(command, expected):
    got, message = decision(command)
    assert got == expected, message


def test_remote_payload_is_reported_as_server_gated():
    got, message = decision("kw run dev -r x -- rm -r" + "f /opt/*")
    assert got is None and "server-gated" in message and "high" in message


def test_analyze_splits_local_and_remote():
    local, remote, guarded = analyze("kw run dev -- uptime; rm -r" + "f ~")
    assert [h.severity for h in local] == ["critical"] and remote == [] and not guarded
    local, remote, guarded = analyze("kw run dev -c 'rm -r" + "f /opt/*'")
    assert local == [] and [h.severity for h in remote] == ["high"]


def test_parse_invocation_shapes():
    inv = parse_invocation(["kw", "-p", "x", "run", "h", "-r", "why", "--", "ls", "-la"])
    assert inv["sub"] == "run" and inv["remote"] == ["ls -la"]
    inv = parse_invocation(["/usr/local/bin/kw", "get", "h", "/etc/shadow", "-o", "/tmp/x"])
    assert inv["sub"] == "get" and inv["remote_read"] == "/etc/shadow" and inv["local_writes"] == ["/tmp/x"]
    assert parse_invocation(["ls"]) is None
    assert parse_invocation(["kw"])["sub"] is None


def test_run_pre_tool_use_is_forgiving():
    assert run_pre_tool_use("not json") == ""
    assert run_pre_tool_use(json.dumps({"tool_name": "Write", "tool_input": {"content": "rm -r" + "f /"}})) == ""
    out = json.loads(run_pre_tool_use(json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -r" + "f ~"}})))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_path_never_imports_the_transport():
    code = "import sys, keywright.cli, keywright.hook; assert 'mcp' not in sys.modules and 'httpx2' not in sys.modules"
    subprocess.run([sys.executable, "-c", code], check=True)
