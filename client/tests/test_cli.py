"""`kw` against the real server over HTTP: output routing, the exit-code contract, and the three
phases of a gated call (ask, wait, execute once)."""
import asyncio
import json
import threading
import time

import httpx
import pytest
from keywright_server import ssh

from keywright import cli
from keywright.transport import TransportError


@pytest.fixture
def env(live_server, monkeypatch):
    monkeypatch.setenv("KW_URL", live_server)
    monkeypatch.setenv("KW_TOKEN", "gk_testtoken")
    monkeypatch.setenv("KW_SESSION", "claude:test-1")
    return live_server


def run(capsys, *argv) -> tuple[int, str, str]:
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_resources_and_json(env, seeded, capsys):
    code, out, _ = run(capsys, "resources")
    assert code == 0 and "dev" in out and "nvr" in out and "session claude:test-1" in out
    code, out, _ = run(capsys, "resources", "--json")
    assert code == 0 and json.loads(out)["agent"] == "test-agent"


def test_open_host_runs_and_routes_output(env, seeded, fake_ssh, capsys):
    code, out, err = run(capsys, "run", "dev", "-r", "why", "--", "uptime", "-p")
    assert code == 0 and out == "ran: uptime -p\n"
    assert err.startswith("kw: audit=") and "exit=0" in err and "truncated=no" in err
    assert fake_ssh == [("127.0.0.1", "uptime -p", "root")]
    code, out, err = run(capsys, "run", "dev", "-q", "--", "uptime")
    assert code == 0 and err == ""
    code, out, _ = run(capsys, "run", "dev", "--json", "--", "uptime")
    assert code == 0 and json.loads(out)["stdout"] == "ran: uptime\n" and "keywright" in json.loads(out)


def test_remote_nonzero_and_passthrough(env, seeded, monkeypatch, capsys):
    async def failing(config, command, *, timeout=300, user=None, stdin=None):
        return ssh.RunResult(exit_code=4, stdout="", stderr="nope\n", truncated=False, duration_ms=1)

    monkeypatch.setattr(ssh, "run", failing)
    code, _out, err = run(capsys, "run", "dev", "--", "false")
    assert code == 1 and "nope" in err and "exit=4" in err
    code, _, _ = run(capsys, "run", "dev", "--exit-passthrough", "--", "false")
    assert code == 4


@pytest.mark.parametrize("argv,expected", [
    (["run", "nvr", "--no-wait", "--", "journalctl", "-n", "5"], 3),
    (["run", "prod", "--", "ls"], 4),
    (["run", "nowhere", "--", "ls"], 5),
    (["run", "dev", "--", "rm", "-r" + "f", "/home"], 4),
    (["status", "req_nothing"], 5),
    (["run", "dev"], 2),
    (["run", "dev", "-c", "ls", "--", "ls"], 2),
])
def test_exit_codes(env, seeded, fake_ssh, capsys, argv, expected):
    code, _, err = run(capsys, *argv)
    assert code == expected, err
    if expected == 3:
        assert "approval requested req_" in err
    if argv[1] == "dev" and expected == 4:
        assert "refused" in err and fake_ssh == []


def test_bad_token_and_no_config(env, seeded, monkeypatch, capsys):
    monkeypatch.setenv("KW_TOKEN", "gk_wrong")
    code, _, err = run(capsys, "run", "dev", "--", "ls")
    assert code == 6 and "token rejected" in err
    monkeypatch.delenv("KW_TOKEN")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/nonexistent")
    code, _, err = run(capsys, "resources")
    assert code == 6 and "kw login" in err


def test_delayed_approval_then_one_execution(env, seeded, fake_ssh, capsys):
    result: dict = {}

    def worker():
        result["code"] = cli.main(["run", "nvr", "--wait", "20", "-r", "logs", "--", "journalctl", "-n", "5"])

    t = threading.Thread(target=worker)
    t.start()
    with httpx.Client(base_url=env, headers={"Origin": env}) as http:
        http.post("/ui/login", data={"password": "adminpass123"})
        rid = None
        for _ in range(40):
            page = http.get("/ui").text
            if "journalctl -n 5" in page:
                rid = page.split("/ui/requests/")[1].split('"')[0]
                break
            time.sleep(0.1)
        assert rid
        r = http.post(f"/ui/requests/{rid}/decide", data={"scope": "once", "extent": "exact"}, follow_redirects=False)
        assert r.status_code == 303
    t.join(timeout=30)
    assert result["code"] == 0
    assert fake_ssh == [("127.0.0.1", "journalctl -n 5", "root")]
    out = capsys.readouterr()
    assert out.out == "ran: journalctl -n 5\n" and "approval requested" in out.err and "consumed=1" in out.err
    # the once grant is used up: the same call asks again
    code, _, _err = run(capsys, "run", "nvr", "--no-wait", "--", "journalctl", "-n", "5")
    assert code == 3 and len(fake_ssh) == 1


def test_wait_deadline_returns_pending(env, seeded, fake_ssh, capsys):
    started = time.monotonic()
    code, _, err = run(capsys, "run", "nvr", "--wait", "1", "--", "journalctl", "-n", "9")
    assert code == 3 and time.monotonic() - started < 10 and fake_ssh == []
    assert "approval requested" in err


def test_connection_loss_during_execution_is_reported_not_retried(env, seeded, fake_ssh, monkeypatch, capsys):
    calls = {"ssh_run": 0}
    original = cli.Gate.call

    def flaky(self, tool, arguments, read_timeout=60.0):
        if tool == "ssh_run":
            calls["ssh_run"] += 1
            if calls["ssh_run"] == 2:
                raise TransportError("ReadTimeout: simulated")
        if tool == "access_status":
            return type("R", (), {"is_error": False, "structured_content": {"status": "approved"}, "content": []})()
        return original(self, tool, arguments, read_timeout)

    monkeypatch.setattr(cli.Gate, "call", flaky)
    code, _, err = run(capsys, "run", "nvr", "--wait", "5", "--", "journalctl", "-n", "7")
    assert code == 6 and "outcome is unknown" in err and calls["ssh_run"] == 2 and fake_ssh == []


def test_put_get_and_truncation(env, seeded, fake_ssh, monkeypatch, capsys, tmp_path):
    src = tmp_path / "app.env"
    src.write_text("A=1\n")
    code, _, err = run(capsys, "put", "dev", "/etc/app/app.env", "--file", str(src), "-r", "cfg")
    assert code == 0 and "wrote 4 bytes to /etc/app/app.env" in err
    assert fake_ssh[-1][1].startswith("sh -c") and "/etc/app/app.env" in fake_ssh[-1][1]

    async def big(config, command, *, timeout=300, user=None, stdin=None):
        return ssh.RunResult(exit_code=0, stdout="partial", stderr="", truncated=True, duration_ms=1)

    monkeypatch.setattr(ssh, "run", big)
    target = tmp_path / "out.txt"
    code, _, err = run(capsys, "get", "dev", "/var/log/big", "-o", str(target))
    assert code == 7 and not target.exists() and "truncated" in err
    code, _, err = run(capsys, "get", "dev", "/var/log/big", "-o", str(target), "--allow-truncated")
    assert code == 0 and target.read_text() == "partial" and "truncated=yes" in err
    code, out, err = run(capsys, "get", "dev", "/var/log/big")
    assert code == 0 and out == "partial" and "truncated=yes" in err


def test_request_patterns_and_status(env, seeded, fake_ssh, capsys):
    code, out, err = run(capsys, "request", "--pattern", "ssh/dev/exec/uptime", "-r", "x", "--json")
    assert code == 0 and json.loads(out)["status"] == "approved"
    code, out, err = run(capsys, "request", "--pattern", "ssh/nvr/exec/uptime", "-r", "x", "--no-wait", "--json")
    assert code == 3
    rid = json.loads(out)["request_id"]
    code, _, err = run(capsys, "status", rid)
    assert code == 3 and "pending" in err


def test_tools_without_mcp_resources(env, seeded, capsys):
    code, out, _ = run(capsys, "tools")
    assert code == 0 and out == ""
    code, _, err = run(capsys, "tool", "ha", "--list")
    assert code == 5 and "no tools" in err


def test_hazards_subcommand_and_guide(capsys):
    assert cli.main(["hazards", "ls"]) == 0
    assert cli.main(["hazards", "git push --force"]) == 2
    capsys.readouterr()
    code, out, _ = run(capsys, "guide")
    assert code == 0 and out.startswith("---\nname: keywright")
    code, alias, _ = run(capsys, "guides")
    assert code == 0 and alias == out


def test_ping_asks_for_the_human_and_says_where_the_conversation_is(env, db, capsys):
    code, out, _ = run(capsys, "ping", "Which", "cert", "path", "do", "you", "want?", "--json")
    assert code == 0
    data = json.loads(out)
    assert data["status"] == "sent" and data["nudge_id"].startswith("ndg_")
    assert "ask your question in the conversation" in data["note"].lower()

    async def open_nudges():
        from keywright_server import nudges
        from keywright_server.db import session
        async with session() as s:
            return await nudges.open_nudges(s)

    waiting = asyncio.run(open_nudges())
    assert [n.message for n in waiting] == ["Which cert path do you want?"]
    assert ":" in waiting[0].context and waiting[0].session_id == "claude:test-1"


def test_ping_needs_something_to_say(env, capsys):
    assert run(capsys, "ping", "   ")[0] == 2


def test_a_second_different_ping_inside_the_cooldown_is_refused(env, capsys):
    assert run(capsys, "ping", "first question")[0] == 0
    code, _, err = run(capsys, "ping", "second, unrelated question")
    assert code == 4 and "rate_limited" in err and "retry_after" in err


def _approve_first_pending(env, needle, **decision) -> str:
    with httpx.Client(base_url=env, headers={"Origin": env}) as http:
        http.post("/ui/login", data={"password": "adminpass123"})
        for _ in range(60):
            page = http.get("/ui").text
            if needle in page:
                rid = page.split("/ui/requests/")[1].split('"')[0]
                break
            time.sleep(0.1)
        else:
            raise AssertionError(f"no pending request mentioning {needle!r}")
        r = http.post(f"/ui/requests/{rid}/decide", data={"scope": "once", **decision}, follow_redirects=False)
        assert r.status_code == 303
        return rid


def test_approved_proxied_tool_call_executes_once_with_the_callers_arguments(env, fake_upstream, capsys):
    """F1/F2 of the 2026-09-20 field report: the control key must not reach the upstream, and an
    approved proxied call must run rather than hand back the approval record as if it were the result."""
    result: dict = {}

    def worker():
        result["code"] = cli.main(["tool", "ha", "ha_get_state", "entity_id=light.kitchen", "--wait", "20", "-r", "is it on"])

    t = threading.Thread(target=worker)
    t.start()
    _approve_first_pending(env, "ha_get_state")
    t.join(timeout=30)
    out = capsys.readouterr()
    assert result["code"] == 0, out.err
    assert out.out == "state of light.kitchen: on\n"
    assert fake_upstream == [("ha_get_state", {"entity_id": "light.kitchen"})]
    # the once grant is used up: the same call asks again rather than running
    code, _, _ = run(capsys, "tool", "ha", "ha_get_state", "entity_id=light.kitchen", "--no-wait")
    assert code == 3 and len(fake_upstream) == 1


def test_status_names_the_command_to_reissue_once_approved(env, seeded, fake_ssh, capsys):
    code, _, err = run(capsys, "run", "nvr", "--no-wait", "--", "journalctl", "-n", "7")
    assert code == 3
    rid = err.split("approval requested ")[1].split()[0]
    code, _, err = run(capsys, "status", rid)
    assert code == 3 and "pending" in err

    def approve():
        time.sleep(0.5)
        _approve_first_pending(env, "journalctl -n 7", extent="exact")

    t = threading.Thread(target=approve)
    t.start()
    code, _, err = run(capsys, "status", rid, "--wait", "20")  # longer than one poll chunk is fine
    t.join(timeout=10)
    assert code == 0 and f"{rid} approved" in err
    assert "re-issue the same command to execute it (kw run nvr -- journalctl -n 7)" in err
    assert fake_ssh == []  # status never resumes


def test_kw_wait_sets_the_default_wait(monkeypatch):
    import importlib

    monkeypatch.setenv("KW_WAIT", "77")
    importlib.reload(cli)
    try:
        assert cli.DEFAULT_WAIT == 77
        assert cli.build_parser().parse_args(["run", "x", "-c", "true"]).wait == 77
    finally:
        monkeypatch.delenv("KW_WAIT")
        importlib.reload(cli)


def test_llm_prints_the_gateway_environment(env, capsys):
    code, out, _ = run(capsys, "llm", "anthropic")
    assert code == 0
    lines = out.splitlines()
    assert lines[0] == f"export ANTHROPIC_BASE_URL={env}/llm/anthropic"
    assert lines[1] == "export ANTHROPIC_AUTH_TOKEN=gk_testtoken"
    assert lines[2] == f"export OPENAI_BASE_URL={env}/llm/anthropic/v1"
    code, out, _ = run(capsys, "llm", "anthropic", "--shell", "fish")
    assert code == 0 and out.startswith("set -gx ANTHROPIC_BASE_URL ")
