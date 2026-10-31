"""End-to-end over real HTTP: MCP client -> Keywright -> (mocked) SSH, plus the admin UI."""

import asyncio
import json

import httpx
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from keywright_server import ssh


def mcp_client(url: str, token: str | None = "gk_testtoken", session: str | None = None) -> Client:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    if session:
        headers["X-Keywright-Session"] = session
    return Client(streamable_http_client(url + "/mcp", http_client=create_mcp_http_client(headers=headers)))


def payload(result):
    return result.structured_content or json.loads(result.content[0].text)


async def test_unauthorized_without_token(live_server):
    async with httpx.AsyncClient() as c:
        r = await c.post(live_server + "/mcp", json={})
        assert r.status_code == 401
    with pytest.raises((httpx.HTTPStatusError, Exception)) as ei:
        async with mcp_client(live_server, token="gk_wrong") as client:
            await client.list_tools()
    assert "401" in str(ei.value) or "unauthorized" in str(ei.value).lower() or ei.value


async def test_tools_and_open_resource(live_server, seeded, fake_ssh):
    async with mcp_client(live_server) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        assert {"access_list_resources", "access_request", "access_status", "ssh_run"} <= tools

        res = payload(await client.call_tool("access_list_resources", {}))
        assert res["agent"] == "test-agent"
        assert {r["resource"]: r["default"] for r in res["resources"]} == {
            "ssh/dev": "open", "ssh/nvr": "approval", "ssh/prod": "locked"}

        out = await client.call_tool("ssh_run", {"host": "dev", "command": "uptime"})
        assert not out.is_error
        assert payload(out)["stdout"] == "ran: uptime\n"
        assert fake_ssh == [("127.0.0.1", "uptime", "root")]
        handle = payload(out)["keywright"]
        assert handle["matched"] == {"ssh/dev/exec/uptime": "resource:open"} and handle["audit_id"] > 0
        assert f"[keywright] audit #{handle['audit_id']}" in out.content[0].text

        locked = await client.call_tool("ssh_run", {"host": "prod", "command": "ls"})
        assert locked.is_error and payload(locked)["error"] == "locked"

        unknown = await client.call_tool("ssh_run", {"host": "nope", "command": "ls"})
        assert payload(unknown)["error"] == "unknown_resource"


async def test_approval_roundtrip_via_ui(live_server, seeded, fake_ssh):
    async with mcp_client(live_server) as client:
        out = await client.call_tool("ssh_run", {"host": "nvr", "command": "docker ps", "reason": "check",
                                                 "wait_seconds": 0})
        p = payload(out)
        assert out.is_error and p["error"] == "approval_required"
        rid = p["request_id"]
        assert p["patterns"] == ["ssh/nvr/exec/docker/ps"]

        # same call again reuses the pending request (no duplicate)
        p2 = payload(await client.call_tool("ssh_run", {"host": "nvr", "command": "docker ps", "wait_seconds": 0}))
        assert p2["request_id"] == rid

        # human approves "once" from the admin UI
        async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as http:
            r = await http.post("/ui/login", data={"password": "adminpass123"}, follow_redirects=False)
            assert r.status_code == 303 and "kw_admin" in r.cookies
            r = await http.post(f"/ui/requests/{rid}/decide", data={"scope": "once"}, follow_redirects=False)
            assert r.status_code == 303

        st = payload(await client.call_tool("access_status", {"request_id": rid}))
        assert st["status"] == "approved" and st["scope"] == "once"

        ok = await client.call_tool("ssh_run", {"host": "nvr", "command": "docker ps"})
        assert not ok.is_error and payload(ok)["exit_code"] == 0
        # once means once
        again = payload(await client.call_tool("ssh_run", {"host": "nvr", "command": "docker ps", "wait_seconds": 0}))
        assert again["error"] == "approval_required" and again["request_id"] != rid


async def test_wait_unblocks_when_decided(live_server, seeded, fake_ssh):
    # Stateless HTTP has no MCP session id; the client names its own so "this session" is possible.
    async with mcp_client(live_server, session="e2e-proc-1") as client:
        task = asyncio.create_task(client.call_tool(
            "ssh_run", {"host": "nvr", "command": "journalctl -n 5", "reason": "logs", "wait_seconds": 20}))
        await asyncio.sleep(0.5)
        async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as http:
            await http.post("/ui/login", data={"password": "adminpass123"})
            page = await http.get("/ui")
            assert "journalctl -n 5" in page.text
            rid = page.text.split("/ui/requests/")[1].split('"')[0]
            r = await http.post(f"/ui/requests/{rid}/decide", data={"scope": "session", "extent": "patterns"},
                                follow_redirects=False)
            assert r.status_code == 303
        out = await task
        assert not out.is_error and "ran: journalctl -n 5" in payload(out)["stdout"]
        # session grant covers a second call in the same session without asking
        out2 = await client.call_tool("ssh_run", {"host": "nvr", "command": "journalctl -n 50"})
        assert not out2.is_error
    # ...but not a different process, nor one that sends no session id at all
    for other in ("e2e-proc-2", None):
        async with mcp_client(live_server, session=other) as client:
            blocked = payload(await client.call_tool("ssh_run", {"host": "nvr", "command": "journalctl -n 50",
                                                                 "wait_seconds": 0}))
            assert blocked["error"] == "approval_required"
            listing = payload(await client.call_tool("access_list_resources", {}))
            assert (listing["session"] is None) == (other is None)
            assert ("session_note" in listing) == (other is None)


async def test_deny_and_decision_link(live_server, seeded, fake_ssh):
    from keywright_server import approvals

    async with mcp_client(live_server) as client:
        p = payload(await client.call_tool("access_request", {"patterns": ["ssh/nvr/exec/rm"], "reason": "cleanup",
                                                              "wait_seconds": 0}))
        assert p["status"] == "pending"
        link = approvals.decision_links(p["request_id"])["deny"]
        path = "/d/" + link.split("/d/", 1)[1]
        async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as http:
            page = await http.get(path)
            assert page.status_code == 200 and "cleanup" in page.text
            done = await http.post(path, data={"deny_reason": "not today"})
            assert "Recorded" in done.text
        st = payload(await client.call_tool("access_status", {"request_id": p["request_id"]}))
        assert st["status"] == "denied" and st["deny_reason"] == "not today"
        blocked = payload(await client.call_tool("ssh_run", {"host": "nvr", "command": "rm -rf /tmp/x", "wait_seconds": 0}))
        assert blocked["error"] == "denied" and blocked["retry_after"] == 600


async def test_admin_pages_render(live_server, seeded):
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}, follow_redirects=True) as http:
        r = await http.get("/ui")
        assert r.url.path == "/ui/login"
        await http.post("/ui/login", data={"password": "adminpass123"})
        for path in ["/ui", "/ui/requests", "/ui/grants", "/ui/policies", "/ui/resources", "/ui/resources/new?kind=ssh",
                     "/ui/resources/new?kind=mcp", "/ui/agents", "/ui/audit", "/ui/settings", "/healthz"]:
            r = await http.get(path)
            assert r.status_code == 200, path
        # create an agent through the UI and see the token once
        r = await http.post("/ui/agents", data={"name": "ui-agent"})
        assert "gk_" in r.text and "claude mcp add" in r.text
        # add a rule
        r = await http.post("/ui/policies", data={"pattern": "ssh/nvr/exec/uptime", "effect": "allow"})
        assert "ssh/nvr/exec/uptime" in r.text
        # switch notifier to webhook via the settings form and probe
        r = await http.post("/ui/settings/notifications/probe", data={"driver": "webhook", "url": "http://hook.test/x",
                                                                       "format": "json", "buttons": ["once", "deny"]})
        assert "Probe OK" in r.text
        r = await http.post("/ui/settings/notifications", data={"driver": "log"})
        assert "Log only" in r.text


async def test_agent_can_tell_why_it_is_waiting_or_failing(live_server, seeded, fake_ssh, monkeypatch, log_notifier):
    """From the 2026-09-17 stress test: a slow human, a lost notification and an unenrolled key all looked
    the same to the agent. Each pending or failed result now says which it is, and a `**` match on an
    exact-command grant says how far it really reaches."""
    import asyncssh

    async with mcp_client(live_server) as client:
        loop = "for i in 1 2; do ping -c1 10.0.0.$i; done"
        p = payload(await client.call_tool("ssh_run", {"host": "nvr", "command": loop, "reason": "sweep",
                                                       "wait_seconds": 0}))
        assert p["error"] == "approval_required" and p["notified"] == "sent" and "has not answered" in p["hint"]
        st = payload(await client.call_tool("access_status", {"request_id": p["request_id"]}))
        assert st["status"] == "pending" and st["notified"] == "sent"

        async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as http:
            await http.post("/ui/login", data={"password": "adminpass123"}, follow_redirects=False)
            r = await http.post(f"/ui/requests/{p['request_id']}/decide", data={"scope": "ttl"}, follow_redirects=False)
            assert r.status_code == 303
        ok = await client.call_tool("ssh_run", {"host": "nvr", "command": loop})
        handle = payload(ok)["keywright"]
        assert list(handle["matched"]) == ["ssh/nvr/exec/**"] and handle["bound"] == {"ssh/nvr/exec/**": "Exact command"}
        assert "ssh/nvr/exec/** <- grant:" in ok.content[0].text and "(Exact command)" in ok.content[0].text

        # a notifier that throws is recorded, and the agent is told to send the human to the UI
        async def broken(req, agent, links, buttons):
            raise RuntimeError("push service down")

        monkeypatch.setattr(log_notifier.active, "send", broken)
        p = payload(await client.call_tool("ssh_run", {"host": "nvr", "command": "docker ps", "wait_seconds": 0}))
        assert p["error"] == "approval_required" and p["notified"] == "failed" and "admin UI" in p["hint"]

        # ssh failures name the stage without leaking the error text
        async def rejected(config, command, *, timeout=300, user=None):
            raise asyncssh.PermissionDenied("secret-bearing reason")

        monkeypatch.setattr(ssh, "run", rejected)
        p = payload(await client.call_tool("ssh_run", {"host": "dev", "command": "uptime"}))
        assert p["error"] == "ssh_failed" and p["stage"] == "auth" and "enrol" in p["hint"]
        assert "secret-bearing" not in json.dumps(p)


async def test_put_get_and_batched_request(live_server, seeded, monkeypatch):
    """ssh_put/ssh_get classify by path and bind to the file's digest; access_request(operations=...) approves
    several exact steps from one prompt."""
    calls = []

    async def run(config, command, *, timeout=300, user=None, stdin=None):
        calls.append((command, stdin))
        out = "FROM=file\n" if command.startswith("cat -- ") else ""
        return ssh.RunResult(exit_code=0, stdout=out, stderr="", truncated=False, duration_ms=2)

    monkeypatch.setattr(ssh, "run", run)
    compose = "services:\n  web:\n    image: nginx\n"
    path = "/etc/komodo/stacks/web/compose.yaml"
    async with mcp_client(live_server) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert {"ssh_put", "ssh_get"} <= names

        bad = payload(await client.call_tool("ssh_put", {"host": "nvr", "path": "../x", "content": "y"}))
        assert bad["error"] == "invalid_arguments" and "absolute" in bad["hint"]

        p = payload(await client.call_tool("access_request", {
            "reason": "deploy web", "wait_seconds": 0,
            "operations": [{"host": "nvr", "put": path, "content": compose},
                           {"host": "nvr", "get": "/etc/komodo/stacks/web/.env"},
                           {"host": "nvr", "command": "docker compose up -d"}]}))
        assert p["status"] == "pending" and p["operations"] == 3 and p["notified"] == "sent"
        assert p["patterns"] == ["ssh/nvr/put/etc/komodo/stacks/web/compose.yaml",
                                 "ssh/nvr/get/etc/komodo/stacks/web/.env", "ssh/nvr/exec/docker/compose/up"]
        async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as http:
            await http.post("/ui/login", data={"password": "adminpass123"}, follow_redirects=False)
            page = await http.get(f"/ui/requests/{p['request_id']}")
            assert "Write <code>" + path in page.text and "$ docker compose up -d" in page.text and "nginx" not in page.text
            r = await http.post(f"/ui/requests/{p['request_id']}/decide", data={"scope": "ttl"}, follow_redirects=False)
            assert r.status_code == 303

        # the same contents at the same path: allowed, written over stdin through an atomic rename
        ok = await client.call_tool("ssh_put", {"host": "nvr", "path": path, "content": compose, "mode": "0600"})
        out = payload(ok)
        assert not ok.is_error and out["bytes"] == len(compose) and out["keywright"]["bound"] == {
            "ssh/nvr/put/etc/komodo/stacks/web/compose.yaml": "Exact file contents"}
        command, stdin = calls[-1]
        assert stdin == compose.encode() and "mktemp" in command and command.endswith(f"{path} 0600")
        assert "(Exact file contents)" in ok.content[0].text
        # different contents: a new prompt, and the contents stay out of it
        changed = payload(await client.call_tool("ssh_put", {"host": "nvr", "path": path, "content": compose + "#\n",
                                                             "wait_seconds": 0}))
        assert changed["error"] == "approval_required" and len(calls) == 1

        got = payload(await client.call_tool("ssh_get", {"host": "nvr", "path": "/etc/komodo/stacks/web/.env"}))
        assert got["content"] == "FROM=file\n" and calls[-1][0] == "cat -- /etc/komodo/stacks/web/.env"
        ran = await client.call_tool("ssh_run", {"host": "nvr", "command": "docker compose up -d"})
        assert not ran.is_error and payload(ran)["keywright"]["bound"] == {"ssh/nvr/exec/docker/compose/up": "Exact command"}

        # everything in the batch is now held, so asking again is a no-op rather than a prompt
        again = payload(await client.call_tool("access_request", {
            "reason": "again", "operations": [{"host": "nvr", "get": "/etc/komodo/stacks/web/.env"}]}))
        assert again["status"] == "approved" and again["note"] == "already allowed"


async def test_capture_moves_a_secret_without_returning_it(live_server, seeded, monkeypatch):
    calls = []

    async def run(config, command, *, timeout=300, user=None, stdin=None):
        calls.append((config["host"], command, stdin))
        if command.startswith("fail"):
            return ssh.RunResult(exit_code=1, stdout="partial-secret", stderr="boom", truncated=False, duration_ms=1)
        out = "OAUTH_CLIENT_SECRET=s3cr3t-value\n" if command.startswith("docker exec") else ""
        return ssh.RunResult(exit_code=0, stdout=out, stderr="", truncated=False, duration_ms=1)

    monkeypatch.setattr(ssh, "run", run)
    env = "/etc/komodo/stacks/open-webui/.env"
    cmd = "docker exec auth-server-1 ak shell"
    async with mcp_client(live_server) as client:
        # both halves in one request: the command on the source and the write on the destination
        p = payload(await client.call_tool("ssh_capture", {"host": "nvr", "command": cmd, "to_host": "nvr",
                                                           "to_path": env, "append": True, "reason": "oidc",
                                                           "wait_seconds": 0}))
        assert p["error"] == "approval_required" and p["patterns"] == [
            "ssh/nvr/exec/docker/exec", "ssh/nvr/put/etc/komodo/stacks/open-webui/.env"]
        assert calls == []
        async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as http:
            await http.post("/ui/login", data={"password": "adminpass123"}, follow_redirects=False)
            page = await http.get(f"/ui/requests/{p['request_id']}")
            assert f"$ {cmd}" in page.text and "Output appended to <b>nvr</b>" in page.text and "not returned" in page.text
            await http.post(f"/ui/requests/{p['request_id']}/decide", data={"scope": "ttl"}, follow_redirects=False)

            ok = await client.call_tool("ssh_capture", {"host": "nvr", "command": cmd, "to_host": "nvr",
                                                        "to_path": env, "append": True})
            out = payload(ok)
            assert not ok.is_error and out["written"] == env and out["bytes"] == 33 and out["append"] is True
            assert "s3cr3t" not in json.dumps(out) and "s3cr3t" not in ok.content[0].text
            assert calls[0] == ("127.0.0.1", cmd, None)
            _, write, stdin = calls[1]
            assert stdin == b"OAUTH_CLIENT_SECRET=s3cr3t-value\n" and 'cat >> "$f"' in write and write.endswith(env)
            audit_page = await http.get("/ui/audit")
            assert "ssh_capture" in audit_page.text and "s3cr3t" not in audit_page.text

        # the capture approval does not let the same command return its output to the agent
        back = payload(await client.call_tool("ssh_run", {"host": "nvr", "command": cmd, "wait_seconds": 0}))
        assert back["error"] == "approval_required"
        # a failing source writes nothing
        before = len(calls)
        failed = payload(await client.call_tool("ssh_capture", {"host": "dev", "command": "fail-now", "to_host": "dev",
                                                                "to_path": "/tmp/x", "reason": "t"}))
        assert failed["error"] == "capture_failed" and "exited 1" in failed["hint"] and len(calls) == before + 1
        assert "partial-secret" not in json.dumps(failed)


async def test_admin_pages_render_recorded_activity(live_server, seeded, fake_ssh):
    """The dashboard, audit log and resource list render the activity list and resource cards."""
    async with mcp_client(live_server) as client:
        payload(await client.call_tool("ssh_run", {"host": "dev", "command": "uptime", "wait_seconds": 0}))
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as http:
        await http.post("/ui/login", data={"password": "adminpass123"})
        dash = (await http.get("/ui")).text
        assert 'class="activity-row"' in dash and "ssh/dev/exec/uptime" in dash
        audit = (await http.get("/ui/audit", params={"q": "uptime"})).text
        assert 'class="activity-row"' in audit and "$ uptime" in audit
        assert 'class="activity-row"' not in (await http.get("/ui/audit", params={"q": "nomatch"})).text
        resources = (await http.get("/ui/resources")).text
        for name in ("dev", "nvr", "prod"):
            assert f"<h2>{name}</h2>" in resources
        assert "Approval required" in resources and "Locked" in resources and "Open access" in resources
        assert "Host key not pinned" in resources


async def test_proxied_call_reaches_upstream_with_exactly_the_callers_arguments(live_server, fake_upstream):
    """Keywright's control keys (`_reason`, `_wait_seconds`) never reach the upstream, the classifier,
    the human, or the audit row; the upstream sees what the caller asked for and nothing else."""
    from sqlalchemy import select

    from keywright_server import db as dbm
    from keywright_server.models import AuditEvent

    args = {"entity_id": "light.kitchen", "_reason": "is it on", "_wait_seconds": 0}
    async with mcp_client(live_server) as client:
        p = payload(await client.call_tool("ha__ha_get_state", args))
        assert p["error"] == "approval_required" and p["patterns"] == ["mcp/ha/tools/ha_get_state"]
        assert fake_upstream == []
        async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as http:
            await http.post("/ui/login", data={"password": "adminpass123"})
            r = await http.post(f"/ui/requests/{p['request_id']}/decide", data={"scope": "once"}, follow_redirects=False)
            assert r.status_code == 303
        out = await client.call_tool("ha__ha_get_state", args)
        assert not out.is_error and "state of light.kitchen: on" in out.content[0].text
    assert fake_upstream == [("ha_get_state", {"entity_id": "light.kitchen"})]
    async with dbm.session() as s:
        ev = (await s.execute(select(AuditEvent).where(AuditEvent.tool == "mcp_call", AuditEvent.decision == "allow"))).scalar_one()
    assert ev.detail["arguments"] == {"entity_id": "light.kitchen"}
    assert "_wait_seconds" not in json.dumps(ev.detail) and "_reason" not in json.dumps(ev.detail)


async def test_proxied_call_rejects_a_bad_wait_control_value(live_server, fake_upstream):
    async with mcp_client(live_server) as client:
        p = payload(await client.call_tool("ha__ha_get_state", {"entity_id": "light.a", "_wait_seconds": "soon"}))
    assert p["error"] == "invalid_arguments" and fake_upstream == []
