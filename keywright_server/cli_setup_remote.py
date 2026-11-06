"""Fixed DoorDash setup operations, executed with python3 on the selected SSH host.

Only small status objects leave the host. CLI output and credentials never do.
Keep this file stdlib-only: it also runs on hosts with Python 3.9+.
"""
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

VERSION = "0.2.6"
ARCHIVE = "dd-cli-v0.2.6-linux-amd64"
SHA256 = "b6abad40c4881589611d3b87e8f5e68fa5473f12469bd2a9d71db7064c5ff051"
URL = "https://github.com/doordash-oss/doordash-cli/releases/download/v0.2.6/" + ARCHIVE + ".tar.gz"
MAX_ARCHIVE = 32 * 1024 * 1024


class SetupError(Exception):
    pass


def private_write(path, content):
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".setup-")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(content)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def install(root):
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64") or platform.libc_ver()[0] != "glibc":
        raise SetupError("unsupported_host")
    release = root / ARCHIVE
    binary = release / ARCHIVE
    if not binary.is_file():
        with urllib.request.urlopen(URL, timeout=45) as response:
            data = response.read(MAX_ARCHIVE + 1)
        if len(data) > MAX_ARCHIVE or hashlib.sha256(data).hexdigest() != SHA256:
            raise SetupError("download_integrity")
        with tempfile.TemporaryDirectory(dir=root) as staging:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                members = archive.getmembers()
                if sum(m.size for m in members) > 128 * 1024 * 1024:
                    raise SetupError("download_integrity")
                for member in members:
                    parts = Path(member.name).parts
                    if (not parts or parts[0] != ARCHIVE or ".." in parts or member.name.startswith("/")
                            or not (member.isfile() or member.isdir())):
                        raise SetupError("download_integrity")
                # No links, devices, absolute paths or traversal; works on older Python versions.
                for member in members:
                    dest = Path(staging) / member.name
                    if member.isdir():
                        dest.mkdir(parents=True, exist_ok=True)
                    else:
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        with archive.extractfile(member) as source, dest.open("wb") as target:
                            shutil.copyfileobj(source, target)
                        dest.chmod(0o700 if member.mode & 0o111 else 0o600)
            candidate = Path(staging) / ARCHIVE / ARCHIVE
            if not candidate.is_file():
                raise SetupError("download_integrity")
            result = subprocess.run([str(candidate), "--help"], capture_output=True, timeout=20, check=False)
            if result.returncode:
                raise SetupError("binary_failed")
            os.rename(Path(staging) / ARCHIVE, release)
    bindir = root / "bin"
    bindir.mkdir(mode=0o700, exist_ok=True)
    launcher = '#!/bin/sh\nexec "$(dirname "$0")/../' + ARCHIVE + '/' + ARCHIVE + '" "$@"\n'
    private_write(bindir / "dd-cli", launcher.encode())
    (bindir / "dd-cli").chmod(0o700)
    return {"status": "installed", "version": VERSION}


def run(action, resource_id, payload):
    if not re.fullmatch(r"res_[A-Za-z0-9_-]{1,80}", resource_id):
        raise SetupError("invalid_setup")
    root = Path.home() / ".local/share/keywright/cli" / resource_id
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    root.chmod(0o700)
    if action == "install":
        return install(root)
    binary = root / "bin/dd-cli"
    if not binary.is_file():
        raise SetupError("not_installed")
    env = dict(os.environ)
    env.pop("DD_CLI_ACCESS_TOKEN", None)
    if action == "signin":
        result = subprocess.run([str(binary), "export-token", "--start"], capture_output=True, timeout=35, env=env, check=False)
        if result.returncode:
            raise SetupError("signin_failed")
        urls = re.findall(r'https://[^\s<>"\x1b]+', (result.stdout + result.stderr).decode(errors="replace"))
        for url in urls:
            parsed = urlsplit(url)
            if (len(url) < 8192 and parsed.hostname
                    and (parsed.hostname == "doordash.com" or parsed.hostname.endswith(".doordash.com"))
                    and not parsed.username and not parsed.password and parsed.port in (None, 443)):
                return {"status": "signin", "signin_url": url}
        raise SetupError("signin_url")
    if action in ("finish", "token"):
        value = payload.get("value", "").strip()
        if not value or len(value) > 16384 or "\n" in value or "\r" in value or "\x00" in value:
            raise SetupError("invalid_input")
        if action == "finish":
            result = subprocess.run([str(binary), "--json-output", "export-token", "--finish", "-"],
                                    input=(value + "\n").encode(), capture_output=True, timeout=45, env=env, check=False)
            if result.returncode:
                raise SetupError("signin_failed")
            data = json.loads(result.stdout)
            value = data.get("access_token", "")
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,16384}", value):
            raise SetupError("invalid_input")
        private_write(root / "token", value.encode())
        return {"status": "signed_in"}
    if action == "verify":
        if not (root / "token").is_file():
            raise SetupError("sign_in_required")
        env["DD_CLI_ACCESS_TOKEN"] = (root / "token").read_text()
        result = subprocess.run([str(binary), "order", "history", "--intent", "Verify DoorDash access"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=40, env=env, check=False)
        if result.returncode:
            raise SetupError("verification_failed")
        return {"status": "ready"}
    raise SetupError("invalid_setup")


if __name__ == "__main__":
    os.umask(0o077)
    try:
        payload = json.loads(sys.stdin.buffer.read(20000) or b"{}")
        print(json.dumps(run(sys.argv[1], sys.argv[2], payload)))
    except SetupError as exc:
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)
    except Exception:  # noqa: BLE001 — never expose sign-in data in exception text
        # Never forward subprocess output, callback URLs, credentials, or exception text.
        print(json.dumps({"error": "host_setup_failed"}))
        sys.exit(1)
