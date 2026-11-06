"""Resumable admin CLI setup. Jobs contain status only; user secrets travel over SSH stdin."""
from __future__ import annotations

import asyncio
import json
import re
import secrets
import shlex
import time
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import update

from . import audit, ssh
from .db import session
from .models import Resource

CONNECTION_KEYS = ("host", "port", "user", "key_path", "host_key")
TASKS: set[asyncio.Task] = set()
LEASE_SECONDS = 300
MESSAGES = {
    "installed": "DoorDash CLI installed. Continue to sign in.",
    "signin": "Open DoorDash sign-in, then paste the return address below within 10 minutes.",
    "signed_in": "Sign-in saved on the selected host. Verify access to finish.",
    "ready": "DoorDash is ready to use through Keywright.",
    "unsupported_host": "Guided installation needs glibc Linux on x86_64. Choose another host or use manual setup.",
    "download_integrity": "The download failed its integrity check. Nothing from that archive was installed.",
    "binary_failed": "The CLI could not run on this host. Check its OS compatibility or choose another host.",
    "not_installed": "Install the CLI on this host before signing in.",
    "signin_failed": "DoorDash sign-in did not complete. Start a new sign-in and try again.",
    "signin_url": "The CLI did not return a recognized DoorDash sign-in link. You can use an exported token instead.",
    "invalid_input": "Enter the complete return address, sign-in code, or exported token in the appropriate field.",
    "sign_in_required": "Sign in before verifying access.",
    "verification_failed": "DoorDash access could not be verified. Check beta access and try signing in again; the token may have expired.",
    "host_setup_failed": "Setup could not finish. The host needs Python 3.9+, outbound HTTPS, and a writable home directory. Check the host before retrying.",
    "interrupted": "Setup was interrupted. Check the host before retrying; the last operation may have completed.",
}


def state(config):
    value = dict(config.get("cli_setup") or {})
    if value.get("status") == "running" and time.time() - value.get("started_at", 0) > LEASE_SECONDS:
        value.update(status="error", message=MESSAGES["interrupted"])
    return value


def allowed_actions(value):
    phase = value.get("resume", "new") if value.get("status") == "error" else value.get("status", "new")
    if phase == "running":
        return set()
    if phase == "new":
        return {"install"}
    if phase == "installed":
        return {"signin", "token"}
    if phase == "signin":
        return {"signin", "finish", "token"}
    if phase in ("signed_in", "ready"):
        return {"signin", "token", "verify"}
    return set()


async def start(rid, action, value=""):
    async with session() as db:
        res = await db.get(Resource, rid)
        if not res or res.kind != "ssh" or res.config.get("integration") != "doordash" or not res.config.get("cli_setup"):
            raise ValueError("No managed DoorDash setup found.")
        before = dict(res.config)
        previous = state(before)
        if action not in allowed_actions(previous):
            raise ValueError("This step is not available. Refresh setup to see its current status.")
        if action in ("finish", "token") and (not value.strip() or len(value) > 16384 or any(c in value for c in "\r\n\x00")):
            raise ValueError("Enter the return address or token on a single line.")
        resume = previous.get("resume", "new") if previous.get("status") == "error" else previous.get("status", "new")
        job = secrets.token_urlsafe(16)
        current = {**previous, "status": "running", "resume": resume, "action": action, "job": job,
                   "started_at": time.time(), "message": "Working on the selected host…"}
        current.pop("signin_url", None)
        result = await db.execute(update(Resource).where(Resource.id == rid, Resource.config == before)
                                  .values(config={**before, "cli_setup": current}))
        if result.rowcount != 1:
            raise ValueError("Another setup step started. Refresh this page.")
        await audit.record(db, tool="cli.setup", decision="started", detail={"resource": res.name, "step": action})
        connection = {key: before[key] for key in CONNECTION_KEYS if key in before}
    task = asyncio.create_task(_perform(rid, job, action, value, connection), name="cli-setup")
    TASKS.add(task)
    task.add_done_callback(TASKS.discard)


async def _perform(rid, job, action, value, connection):
    learned = None
    try:
        script = Path(__file__).with_name("cli_setup_remote.py").read_text()
        command = "python3 -c " + shlex.quote(script) + " " + shlex.quote(action) + " " + shlex.quote(rid)
        result = await ssh.run(connection, command, timeout=150,
                               stdin=json.dumps({"value": value}).encode())
        learned = result.learned_host_key
        output = json.loads(result.stdout) if not result.truncated else {}
        expected = {"install": "installed", "signin": "signin", "finish": "signed_in", "token": "signed_in", "verify": "ready"}[action]
        if result.exit_code == 0 and output.get("status") == expected:
            outcome = {"status": expected, "message": MESSAGES[expected]}
            if action == "signin":
                url = output.get("signin_url", "")
                parsed = urlsplit(url)
                if (not isinstance(url, str) or len(url) > 8192 or parsed.scheme != "https" or not parsed.hostname
                        or not (parsed.hostname == "doordash.com" or parsed.hostname.endswith(".doordash.com"))
                        or parsed.username or parsed.password or parsed.port not in (None, 443)):
                    raise ValueError("Unexpected sign-in URL")
                outcome["signin_url"] = url
        else:
            code = output.get("error", "host_setup_failed")
            outcome = {"status": "error", "message": MESSAGES.get(code, MESSAGES["host_setup_failed"])}
    except asyncio.CancelledError:
        await _finish(rid, job, {"status": "error", "message": MESSAGES["interrupted"]}, learned)
        raise
    except Exception:  # noqa: BLE001 — never expose SSH/CLI exception text containing sign-in data
        # SSH and CLI error text can include secrets: keep it out of UI, logs and audits.
        outcome = {"status": "error", "message": MESSAGES["host_setup_failed"]}
    await _finish(rid, job, outcome, learned)


async def _finish(rid, job, outcome, learned):
    async with session() as db:
        res = await db.get(Resource, rid)
        if not res or res.config.get("cli_setup", {}).get("job") != job:
            return
        before = dict(res.config)
        config = {**before, "cli_setup": {**before["cli_setup"], **outcome}}
        if learned:
            config["host_key"] = learned
        if outcome["status"] == "installed":
            config["cli_runtime"] = rid
        if outcome["status"] != "signin":
            config["cli_setup"].pop("signin_url", None)
        result = await db.execute(update(Resource).where(Resource.id == rid, Resource.config == before).values(config=config))
        if result.rowcount:
            await audit.record(db, tool="cli.setup", decision=outcome["status"],
                               detail={"resource": res.name, "step": before["cli_setup"]["action"]})


async def shutdown():
    tasks = list(TASKS)
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


def runtime_command(config, command):
    """Apply the managed install only to this resource, preserving the approved command and stdin."""
    directory = config.get("cli_runtime")
    if not directory:
        return command
    if config.get("integration") != "doordash" or not re.fullmatch(r"res_[A-Za-z0-9_-]{1,80}", directory):
        raise ValueError("Invalid managed CLI runtime")
    script = ('unset DD_CLI_ACCESS_TOKEN; d="$HOME/.local/share/keywright/cli/' + directory + '"; '
              'PATH="$d/bin:$PATH"; export PATH; '
              'if [ -f "$d/token" ]; then DD_CLI_ACCESS_TOKEN=$(cat "$d/token") || exit; '
              'export DD_CLI_ACCESS_TOKEN; fi; exec sh -c "$1"')
    return "sh -c " + shlex.quote(script) + " keywright " + shlex.quote(command)
