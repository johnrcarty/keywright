"""Runs one command on one host over SSH. Keys live on the Keywright host only.

Resource config for kind=ssh:
  {"host": "10.0.0.5", "port": 22, "user": "root", "key_path": "/var/lib/keywright/keys/web1",
   "host_key": "<pinned 'ssh-ed25519 AAAA...' line, learned on first connect>"}
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import shlex
import time
from dataclasses import dataclass
from typing import Any

import asyncssh

MAX_OUTPUT = 1024 * 1024
MAX_PUT = 1024 * 1024
CONNECT_TIMEOUT = 30
MAX_TIMEOUT = 600


@dataclass
class RunResult:
    exit_code: int | None
    stdout: str
    stderr: str
    truncated: bool
    duration_ms: int
    learned_host_key: str | None = None  # set when we pinned the host key on this call


class HostKeyMismatch(Exception):
    pass


def _server_key_line(conn) -> str | None:
    """'ssh-ed25519 AAAA...' for the host key the server proved it holds on this connection."""
    key = conn.get_server_host_key()
    return key.export_public_key().decode().strip() if key is not None else None


def _known_hosts_for(pinned: str):
    """asyncssh known_hosts argument that trusts exactly the pinned key (for any hostname)."""
    try:
        return ([asyncssh.import_public_key(pinned)], [], [])
    except asyncssh.KeyImportError as e:
        raise HostKeyMismatch("stored host key is not a valid public key; forget it in the UI and re-pin") from e


async def run(config: dict[str, Any], command: str, *, timeout: int = 300, user: str | None = None,
              stdin: bytes | None = None) -> RunResult:
    timeout = max(1, min(int(timeout or 300), MAX_TIMEOUT))
    host = config["host"]
    port = int(config.get("port") or 22)
    username = user or config.get("user") or "root"
    key_path = config.get("key_path")
    pinned = config.get("host_key")
    started = time.monotonic()

    options: dict[str, Any] = {
        "host": host,
        "port": port,
        "username": username,
        "client_keys": [key_path] if key_path else [],
        "agent_path": None,
        "config": None,
        "connect_timeout": CONNECT_TIMEOUT,
    }
    if pinned:
        options["known_hosts"] = _known_hosts_for(pinned)
    else:
        options["known_hosts"] = None  # first contact: learn and pin below

    learned = None
    async with asyncssh.connect(**options) as conn:
        if not pinned:
            learned = _server_key_line(conn)
        # Drain both streams concurrently, retaining at most MAX_OUTPUT bytes in total.
        # conn.run() buffers all output before returning, so slicing afterwards is not a memory limit.
        buffers = [bytearray(), bytearray()]
        remaining = MAX_OUTPUT
        truncated = False
        async with conn.create_process(command, encoding=None) as process:
            if stdin:
                process.stdin.write(stdin)
            process.stdin.write_eof()

            async def drain(reader, target):
                nonlocal remaining, truncated
                while chunk := await reader.read(32768):
                    keep = min(len(chunk), remaining)
                    target.extend(chunk[:keep])
                    remaining -= keep
                    truncated |= keep < len(chunk)

            try:
                await asyncio.wait_for(asyncio.gather(
                    drain(process.stdout, buffers[0]), drain(process.stderr, buffers[1]), process.wait_closed(),
                ), timeout=timeout)
                code = process.exit_status
            except TimeoutError:
                process.close()
                code = 124
                buffers[1] = bytearray(f"keywright: command timed out after {timeout}s".encode())
                if len(buffers[0]) + len(buffers[1]) > MAX_OUTPUT:
                    del buffers[0][MAX_OUTPUT - len(buffers[1]):]
                    truncated = True
        out, err = (bytes(b).decode(errors="replace") for b in buffers)
    return RunResult(
        exit_code=code,
        stdout=out if isinstance(out, str) else out.decode(errors="replace"),
        stderr=err if isinstance(err, str) else err.decode(errors="replace"),
        truncated=truncated,
        duration_ms=int((time.monotonic() - started) * 1000),
        learned_host_key=learned,
    )


def remote_path(path: str) -> str:
    """An absolute path that can also be spelled as permission-path segments, so a rule can name it
    (ssh/<host>/put/etc/komodo/stacks/**). Anything else is refused rather than escaped."""
    from keywright.patterns import validate

    if not isinstance(path, str) or not path.startswith("/") or path.endswith("/") or "//" in path:
        raise ValueError("path must be absolute, without a trailing slash or empty segments")
    parts = path[1:].split("/")
    if any(seg in (".", "..") or seg.endswith("*") for seg in parts):
        raise ValueError("path must not contain . or .. segments or end a segment with *")
    try:
        validate("ssh/x/put/" + "/".join(parts))
    except ValueError as e:
        raise ValueError(f"path segments may only use letters, digits and _ . : @ + = , - ({e})") from e
    return path


def put_command(path: str, mode: str) -> str:
    """Write stdin to `path` atomically: temp file beside it, mode set, then renamed into place, so a
    dropped connection never leaves a half-written file. Parent directories are created."""
    if not re.fullmatch(r"0?[0-7]{3}", mode):
        raise ValueError("mode must be three octal digits, e.g. 0644")
    script = ('set -e; f=$1; d=$(dirname -- "$f"); mkdir -p -- "$d"; t=$(mktemp -- "$d/.keywright.XXXXXX"); '
              'cat > "$t"; chmod "$2" "$t"; mv -f -- "$t" "$f"')
    return f"sh -c {shlex.quote(script)} keywright {shlex.quote(path)} {mode}"


def append_command(path: str) -> str:
    """Append stdin to `path`, creating it (and its directory) if needed, and never widening its mode."""
    script = 'set -e; f=$1; mkdir -p -- "$(dirname -- "$f")"; [ -e "$f" ] || (umask 077; : > "$f"); cat >> "$f"'
    return f"sh -c {shlex.quote(script)} keywright {shlex.quote(path)}"


def get_command(path: str) -> str:
    return f"cat -- {shlex.quote(path)}"


def failure_stage(exc: BaseException) -> tuple[str, str]:
    """Where a run broke, coarse enough to hold no secrets: (stage, what the agent should do)."""
    if isinstance(exc, asyncssh.PermissionDenied):
        return "auth", "The host rejected Keywright's key; the admin has to enrol it on the host."
    if isinstance(exc, (asyncssh.HostKeyNotVerifiable, HostKeyMismatch)):
        return "hostkey", "The host key does not match the pinned one; the admin has to re-probe the resource."
    if isinstance(exc, (OSError, TimeoutError, asyncssh.ConnectionLost, asyncssh.DisconnectError)):
        return "unreachable", "No SSH connection to the host; check that it is up and the port is open."
    return "exec", "The connection worked but the command could not be run."


async def probe(config: dict[str, Any]) -> tuple[bool, str, str | None]:
    """Connection test used by the admin UI. Returns (ok, message, learned_host_key)."""
    try:
        r = await run(config, "echo keywright-ok", timeout=15)
    except asyncssh.PermissionDenied:
        return False, "Authentication failed: is the key authorized on the host?", None
    except asyncssh.HostKeyNotVerifiable as e:
        return False, f"Host key mismatch: {e}", None
    except HostKeyMismatch as e:
        return False, str(e), None
    except (OSError, asyncssh.Error, TimeoutError) as e:
        return False, f"{type(e).__name__}: {e}", None
    if r.exit_code == 0 and "keywright-ok" in r.stdout:
        return True, f"Connected as {config.get('user') or 'root'}@{config['host']} in {r.duration_ms} ms", r.learned_host_key
    return False, f"Unexpected reply (exit {r.exit_code}): {r.stderr[:200]}", r.learned_host_key


# ---- key generation & enrolment -----------------------------------------------------------------
def generate_key(name: str, keys_dir, comment: str | None = None) -> tuple[str, str]:
    """Create an ed25519 keypair under keys_dir/<name>. Returns (private_path, public_line)."""
    from pathlib import Path

    keys_dir = Path(keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv = keys_dir / name
    if priv.exists():
        raise FileExistsError(f"{priv} already exists")
    key = asyncssh.generate_private_key("ssh-ed25519", comment=comment or f"keywright->{name}")
    import os

    fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(key.export_private_key())
    pub_line = key.export_public_key().decode().strip()
    (keys_dir / f"{name}.pub").write_text(pub_line + "\n")
    return str(priv), pub_line


def authorized_keys_line(pub_line: str, restrict_from: str | None) -> str:
    if restrict_from:
        # This setting represents one outbound address, not arbitrary authorized_keys options.
        restrict_from = str(ipaddress.ip_address(restrict_from))
    if "\n" in pub_line or "\r" in pub_line:
        raise ValueError("Public key must be a single line")
    return (f'from="{restrict_from}" ' if restrict_from else "") + pub_line


def enroll_script(pub_line: str, restrict_from: str | None) -> str:
    """POSIX shell that installs the key for the invoking user, idempotently."""
    line = authorized_keys_line(pub_line, restrict_from)
    key_part = pub_line.split()[1]
    return (
        "set -e\n"
        'D="$HOME/.ssh"; F="$D/authorized_keys"\n'
        'mkdir -p "$D" && chmod 700 "$D"\n'
        f"if grep -qF {shlex.quote(key_part)} \"$F\" 2>/dev/null; then echo 'keywright: key already present'; "
        f"else printf '%s\\n' {shlex.quote(line)} >> \"$F\" && echo 'keywright: key installed for' \"$(id -un)@$(hostname)\"; fi\n"
        'chmod 600 "$F"\n'
    )


async def enroll_with_password(config: dict[str, Any], password: str, pub_line: str, restrict: bool = True,
                               *, login_user: str | None = None, escalate: str | None = None,
                               root_password: str | None = None) -> tuple[bool, str, str | None]:
    """Log in once with a password, install the public key for the resource user, learn the host key.

    login_user: account to log in as when password SSH is disabled for the target user (e.g. root).
    escalate:   how to become the target user from login_user: "sudo" (uses root_password or the
                login password) or "su" (uses root_password). None when login_user is the target.
    Passwords are used for this connection only and never stored. Returns (ok, message, host_key)."""
    import base64
    import shlex

    host = config["host"]
    port = int(config.get("port") or 22)
    target = config.get("user") or "root"
    login = (login_user or "").strip() or target

    def safe_output(value: str) -> str:
        for secret in (password, root_password):
            if secret:
                value = value.replace(secret, "[redacted]")
        return value

    try:
        async with asyncssh.connect(host, port=port, username=login, password=password,
                                    known_hosts=_known_hosts_for(config["host_key"]) if config.get("host_key") else None,
                                    client_keys=[], agent_path=None, config=None, connect_timeout=CONNECT_TIMEOUT) as conn:
            learned = _server_key_line(conn)
            src = conn.get_extra_info("sockname")[0] if restrict else None
            script = enroll_script(pub_line, src)
            if login == target:
                res = await asyncio.wait_for(conn.run(script, check=False), timeout=30)
            else:
                b64 = base64.b64encode(script.encode()).decode()
                inner = f"echo {b64} | base64 -d | sh"
                if escalate == "su":
                    cmd = f"su - {shlex.quote(target)} -c {shlex.quote(inner)}"
                    res = await asyncio.wait_for(
                        conn.run(cmd, input=(root_password or "") + "\n", term_type="xterm", check=False), timeout=45)
                elif escalate == "sudo":
                    cmd = f"sudo -H -S -p '' -u {shlex.quote(target)} sh -c {shlex.quote(inner)}"
                    res = await asyncio.wait_for(
                        conn.run(cmd, input=(root_password or password) + "\n", check=False), timeout=45)
                else:
                    return False, f"Logged in as {login}, but no escalation method chosen to become {target}.", learned
            out = safe_output(res.stdout or "").replace("\r", "")
            if res.exit_status != 0:
                err = safe_output(res.stderr or "")[:300] or out[-300:]
                return False, f"install script failed (exit {res.exit_status}): {err.strip()}", learned
            note = next((ln.strip() for ln in out.splitlines() if "keywright:" in ln), out.strip()[-200:])
    except asyncssh.PermissionDenied:
        return False, f"Password rejected for {login}@{host} (or password logins are disabled for that user).", None
    except (OSError, asyncssh.Error, TimeoutError, HostKeyMismatch) as e:
        return False, f"{type(e).__name__}: {e}", None
    ok, msg, _ = await probe({**config, "host_key": learned} if learned else config)
    if not ok:
        return False, f"{note}; but key login as {target} failed afterwards: {msg}", learned
    tail = f" Restricted to source {src}." if restrict else ""
    return True, f"{note}; key login verified ({msg}).{tail}", learned
