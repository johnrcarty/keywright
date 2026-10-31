"""Deadline enforcement must survive an uncooperative SDK/resolver and reap its process."""

import asyncio
import json
import sys
import time

import pytest

from keywright import transport
from keywright.config import Profile

PROFILE = Profile("test", "https://broker.invalid", "never-print-this-token")


@pytest.fixture
def worker(monkeypatch):
    spawn = asyncio.create_subprocess_exec
    children = []
    monkeypatch.setattr(transport, "CONNECT_TIMEOUT", 0.4)
    monkeypatch.setattr(transport, "CLEANUP_TIMEOUT", 0.1)
    monkeypatch.setattr(transport, "RESPONSE_GRACE", 0)

    def install(code):
        async def start(*args, **kwargs):
            assert PROFILE.token not in " ".join(args)
            child = await spawn(sys.executable, "-u", "-c", code, **kwargs)
            children.append(child)
            return child

        monkeypatch.setattr(asyncio, "create_subprocess_exec", start)
        return children

    return install


def test_blocked_handshake_is_bounded_and_reaped(worker):
    children = worker("import sys,time; sys.stdin.read(); time.sleep(60)")
    start = time.monotonic()
    with pytest.raises(transport.TransportError, match="handshake timed out") as error:
        transport.call(PROFILE, None, "access_list_resources")
    assert time.monotonic() - start < 3
    assert "sandbox" in str(error.value) and PROFILE.token not in str(error.value)
    assert children[0].returncode is not None


def test_blocking_dns_thread_cannot_hold_cli_open(worker, monkeypatch):
    # Import/SDK startup may take longer on slow runners; allow time to reach the resolver.
    monkeypatch.setattr(transport, "CONNECT_TIMEOUT", 2)
    children = worker("import socket,time,runpy; "
                      "socket.getaddrinfo=lambda *a,**k: time.sleep(60); "
                      "runpy.run_module('keywright._transport_worker',run_name='__main__')")
    start = time.monotonic()
    with pytest.raises(transport.TransportError, match="handshake timed out"):
        transport.call(PROFILE, None, "access_list_resources")
    assert time.monotonic() - start < 4
    assert children[0].returncode is not None


def test_response_deadline_is_separate_and_never_retries(worker):
    children = worker("import sys,time; sys.stdin.read(); print('[\"ready\",null]',flush=True); time.sleep(60)")
    with pytest.raises(transport.TransportError, match="response timed out"):
        transport.call(PROFILE, None, "ssh_run", read_timeout=0.2)
    assert len(children) == 1 and children[0].returncode is not None


def test_completed_result_survives_stuck_cleanup_and_long_operation(worker):
    result = json.dumps(["result", {"content": [{"type": "text", "text": "done"}]}])
    children = worker("import sys,time; sys.stdin.read(); print('[\"ready\",null]',flush=True); "
                      f"time.sleep(0.5); print({result!r},flush=True); time.sleep(60)")
    res = transport.call(PROFILE, None, "ssh_run", read_timeout=2)
    assert res.content[0].text == "done"
    assert len(children) == 1 and children[0].returncode is not None


async def test_async_cancellation_reaps_worker(worker):
    children = worker("import sys,time; sys.stdin.read(); time.sleep(60)")
    task = asyncio.create_task(transport.acall(PROFILE, None, "ssh_run"))
    while not children:
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert children[0].returncode is not None


async def test_error_diagnostic_does_not_echo_credentials(monkeypatch):
    import httpx2

    class BrokenClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            raise OSError(f"https://user:{PROFILE.token}@broker.invalid/?secret=private")

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr(httpx2, "AsyncClient", BrokenClient)
    with pytest.raises(transport.TransportError) as error:
        await transport._call(PROFILE, None, "access_list_resources", {}, 1, lambda *args: None)
    assert "OSError" in str(error.value)
    assert PROFILE.token not in str(error.value) and "secret=private" not in str(error.value)


async def test_server_accepts_connection_but_never_responds(monkeypatch):
    accepted = asyncio.Event()
    writers = []

    async def silent(reader, writer):
        writers.append(writer)
        accepted.set()

    server = await asyncio.start_server(silent, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    monkeypatch.setattr(transport, "CONNECT_TIMEOUT", 2)
    monkeypatch.setattr(transport, "CLEANUP_TIMEOUT", 0.1)
    profile = Profile("test", f"http://127.0.0.1:{port}", PROFILE.token)
    try:
        start = time.monotonic()
        with pytest.raises(transport.TransportError, match="handshake timed out"):
            await transport.acall(profile, None, "access_list_resources")
        assert accepted.is_set() and time.monotonic() - start < 4
    finally:
        server.close()
        for writer in writers:
            writer.close()
            await writer.wait_closed()
        await server.wait_closed()
