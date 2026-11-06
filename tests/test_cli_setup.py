import asyncio
import hashlib
import io
import json
import shlex
import subprocess
import tarfile
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from keywright_server import cli_setup, ssh
from keywright_server import cli_setup_remote as remote
from keywright_server.config import settings
from keywright_server.models import AuditEvent, Resource
from keywright_server.web import auth
from keywright_server.web.app import create_app


@pytest.fixture
async def browser(db, monkeypatch):
    monkeypatch.setattr(settings, "public_url", "https://kw.test")
    monkeypatch.setattr(settings, "auth_mode", "password")
    await auth.set_password(db, "fixture-password")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="https://kw.test",
                                headers={"Origin": "https://kw.test"}) as client:
        await client.post("/ui/login", data={"password": "fixture-password"})
        yield client
    await cli_setup.shutdown()


@pytest.fixture
async def host(db):
    res = Resource(name="Runner", kind="ssh", default_mode="locked", config={
        "host": "runner.test", "user": "runner", "port": 2222, "key_path": "/keys/shared",
        "host_key": "ssh-ed25519 fixture", "unrelated_setting": "not-copied",
    })
    db.add(res)
    await db.commit()
    return res


async def create(browser, host):
    response = await browser.post("/ui/cli-setup/doordash", data={"host_id": host.id, "name": "DoorDash"})
    assert response.status_code == 303
    return response.headers["location"].rsplit("/", 1)[-1]


async def step(browser, rid, action, value=""):
    response = await browser.post(f"/ui/cli-setup/{rid}/{action}", data={"value": value})
    assert response.status_code == 303
    await asyncio.gather(*list(cli_setup.TASKS))
    return await browser.get(f"/ui/cli-setup/{rid}")


async def test_owner_setup_reuses_connection_and_keeps_secrets_on_host(browser, db, host, monkeypatch):
    calls = []

    async def run(config, command, **kwargs):
        action, _rid = shlex.split(command)[-2:]
        calls.append((config, command, kwargs))
        status = {"install": "installed", "signin": "signin", "finish": "signed_in", "verify": "ready"}[action]
        output = {"status": status}
        if action == "signin":
            output["signin_url"] = "https://www.doordash.com/consumer/login/?state=fixture"
        return ssh.RunResult(0, json.dumps(output), "sensitive-stderr-must-not-be-shown", False, 1)

    monkeypatch.setattr(ssh, "run", run)
    picker = await browser.get("/ui/resources/new?integration=doordash")
    assert 'Runner — runner@runner.test' in picker.text
    rid = await create(browser, host)
    res = await db.get(Resource, rid)
    assert res.default_mode == "approval" and res.config["key_path"] == host.config["key_path"]
    assert "unrelated_setting" not in res.config and "cli_runtime" not in res.config
    assert not calls  # Selecting a host creates a connection, not an installation.
    assert "Sign in to DoorDash" in (await step(browser, rid, "install")).text
    assert "Open DoorDash sign-in" in (await step(browser, rid, "signin")).text
    secret = "http://localhost:8080/?code=secret-callback-for-test"
    assert "Verify DoorDash access" in (await step(browser, rid, "finish", secret)).text
    page = await step(browser, rid, "verify")
    assert "DoorDash is ready" in page.text and secret not in page.text
    await db.refresh(res)
    assert res.config["cli_runtime"] == rid and "signin_url" not in res.config["cli_setup"]
    assert res.config["cli_setup"]["status"] == "ready"
    assert all(c[0] == {k: host.config[k] for k in cli_setup.CONNECTION_KEYS} for c in calls)
    assert secret not in "\n".join(c[1] for c in calls)
    assert secret in calls[2][2]["stdin"].decode()
    audit_rows = list(await db.scalars(select(AuditEvent)))
    persisted = json.dumps([res.config, *[r.detail for r in audit_rows]])
    assert secret not in persisted and "sensitive-stderr" not in persisted
    assert len([r for r in audit_rows if r.tool == "cli.setup"]) == 8
    await db.refresh(host)
    assert host.default_mode == "locked" and "cli_runtime" not in host.config
    edit = await browser.get("/ui/resources/" + rid)
    assert "Manage DoorDash sign-in" in edit.text and "Enrol with a password" not in edit.text
    await browser.post("/ui/resources", data={"rid": rid, "integration": "doordash", "name": "DoorDash",
                                           "host": "different.test", "user": "runner", "port": 2222})
    await db.refresh(res)
    assert res.config["host"] == "runner.test"


async def test_setup_requires_admin_same_origin_and_valid_host(browser, db, host):
    browser.cookies.clear()
    assert (await browser.post("/ui/cli-setup/doordash", data={"host_id": host.id})).status_code == 303
    assert list(await db.scalars(select(Resource))) == [host]
    await browser.post("/ui/login", data={"password": "fixture-password"})
    assert (await browser.post("/ui/cli-setup/doordash", data={"host_id": host.id},
                               headers={"Origin": "https://evil.test"})).status_code == 403
    for invalid in ("missing", ""):
        await browser.post("/ui/cli-setup/doordash", data={"host_id": invalid})
    assert list(await db.scalars(select(Resource))) == [host]
    rid = await create(browser, host)
    assert (await browser.post(f"/ui/cli-setup/{rid}/install", headers={"Origin": "https://evil.test"})).status_code == 403
    assert not cli_setup.TASKS


async def test_duplicate_jobs_and_out_of_order_steps_are_rejected(browser, db, host, monkeypatch):
    barrier = asyncio.Event()
    calls = []

    async def run(*args, **kwargs):
        calls.append(args)
        await barrier.wait()
        return ssh.RunResult(0, '{"status":"installed"}', "", False, 1)

    monkeypatch.setattr(ssh, "run", run)
    rid = await create(browser, host)
    await step(browser, rid, "finish", "unused-code")
    assert not calls
    await browser.post(f"/ui/cli-setup/{rid}/install")
    await browser.post(f"/ui/cli-setup/{rid}/install")
    assert len(calls) == 1
    page = await browser.get(f"/ui/cli-setup/{rid}")
    assert "Installing DoorDash CLI" in page.text
    barrier.set()
    await asyncio.gather(*list(cli_setup.TASKS))
    assert (await db.get(Resource, rid)).config["cli_setup"]["status"] == "installed"


@pytest.mark.parametrize("output,exit_code", [
    ("secret-token-and-callback", 1),
    ('{"status":"signin","signin_url":"https://evil.test/login"}', 0),
    ('{"status":"signin","signin_url":"https://doordash.com.evil.test/login"}', 0),
    ('{"status":"signin","signin_url":"https://secret@www.doordash.com/login"}', 0),
])
async def test_untrusted_or_secret_setup_output_is_not_displayed(browser, db, host, monkeypatch, output, exit_code):
    rid = await create(browser, host)
    res = await db.get(Resource, rid)
    res.config = {**res.config, "cli_setup": {**res.config["cli_setup"], "status": "installed"}}
    await db.commit()

    async def run(*args, **kwargs):
        return ssh.RunResult(exit_code, output, "secret-stderr", False, 1)

    monkeypatch.setattr(ssh, "run", run)
    page = await step(browser, rid, "signin")
    assert "Setup could not finish" in page.text
    await db.refresh(res)
    assert res.config["cli_setup"]["status"] == "error"
    assert output not in page.text and "secret-stderr" not in page.text
    assert output not in json.dumps(res.config)


def test_interrupted_setup_is_recoverable_without_automatic_retries():
    value = cli_setup.state({"cli_setup": {"status": "running", "resume": "installed", "started_at": time.time() - 301}})
    assert value["status"] == "error"
    assert cli_setup.allowed_actions(value) == {"signin", "token"}


def test_remote_finish_keeps_token_out_of_output_and_command(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    root = tmp_path / ".local/share/keywright/cli/res_fixture"
    (root / "bin").mkdir(parents=True)
    (root / "bin/dd-cli").touch()
    secret = "fixture-secret-token-123456789"
    callback = "http://localhost/?code=secret-code"
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps({"access_token": secret}).encode())

    monkeypatch.setattr(remote.subprocess, "run", run)
    result = remote.run("finish", "res_fixture", {"value": callback})
    assert result == {"status": "signed_in"}
    assert (root / "token").read_text() == secret
    assert (root / "token").stat().st_mode & 0o777 == 0o600
    assert callback not in " ".join(calls[0][0]) and calls[0][1]["input"] == (callback + "\n").encode()
    assert remote.run("verify", "res_fixture", {}) == {"status": "ready"}
    assert calls[1][1]["env"]["DD_CLI_ACCESS_TOKEN"] == secret
    assert calls[1][1]["stdout"] == subprocess.DEVNULL


@pytest.mark.parametrize("bad_name", ["../outside", "/tmp/outside", remote.ARCHIVE + "/../outside"])
def test_installer_rejects_archive_traversal(tmp_path, monkeypatch, bad_name):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        member = tarfile.TarInfo(bad_name)
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    payload = data.getvalue()
    monkeypatch.setattr(remote, "SHA256", hashlib.sha256(payload).hexdigest())
    monkeypatch.setattr(remote.urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(payload))
    monkeypatch.setattr(remote.platform, "system", lambda: "Linux")
    monkeypatch.setattr(remote.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(remote.platform, "libc_ver", lambda: ("glibc", "2.36"))
    with pytest.raises(remote.SetupError, match="download_integrity"):
        remote.install(tmp_path)
    assert not (tmp_path / remote.ARCHIVE).exists()


def test_managed_runtime_preserves_command_and_stdin_without_exposing_token():
    command = "printf '%s\\n' '$(touch /tmp/should-not-run); literal'"
    config = {"integration": "doordash", "cli_runtime": "res_fixture"}
    wrapped = cli_setup.runtime_command(config, command)
    assert shlex.split(wrapped)[-1] == command
    result = subprocess.run(["sh", "-c", wrapped], input="unchanged", capture_output=True, text=True, check=True)
    assert result.stdout == "$(touch /tmp/should-not-run); literal\n"
    result = subprocess.run(["sh", "-c", cli_setup.runtime_command(config, "cat")],
                            input="unchanged stdin", capture_output=True, text=True, check=True)
    assert result.stdout == "unchanged stdin"
    assert cli_setup.runtime_command({}, command) == command
    with pytest.raises(ValueError):
        cli_setup.runtime_command({"integration": "doordash", "cli_runtime": "../../other"}, command)
