import asyncio
import os
import socket
import threading

import pytest
import pytest_asyncio


@pytest.fixture(scope="session", autouse=True)
def _data_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("gkdata")
    os.environ["KW_DATA_DIR"] = str(d)
    os.environ["KW_SECRET_KEY"] = "test-secret-key-not-for-prod"
    os.environ["KW_ADMIN_PASSWORD"] = "adminpass123"
    os.environ["KW_REQUEST_TIMEOUT"] = "60"
    from keywright_server.config import settings

    settings.data_dir = d
    settings.admin_password = "adminpass123"
    settings.request_timeout_s = 60
    settings.ensure_dirs()
    return d


@pytest_asyncio.fixture
async def db(_data_dir, tmp_path):
    """Fresh database per test."""
    from keywright_server import db as dbm
    from keywright_server import settings_store
    from keywright_server.config import settings

    path = tmp_path / "t.db"
    settings.public_url = "http://gk.test"
    await dbm.reset_for_tests(f"sqlite+aiosqlite:///{path}")
    settings_store._cache.clear()
    async with dbm.session() as s:
        yield s


@pytest_asyncio.fixture
async def agent(db):
    from keywright_server.mcp_server import hash_token
    from keywright_server.models import Agent

    a = Agent(name="test-agent", token_hash=hash_token("gk_testtoken"), token_prefix="gk_testt")
    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


@pytest_asyncio.fixture
async def log_notifier(db):
    from keywright_server.notify.manager import manager

    await manager._apply({"driver": "log", "config": {}, "buttons": ["once", "session", "deny"]})
    yield manager
    await manager.stop()


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest_asyncio.fixture
async def live_server(db, agent, log_notifier):
    """Full app on a random port, in a background thread with its own loop (mirrors production)."""
    import uvicorn

    from keywright_server.web.app import create_app

    port = free_port()
    config = uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.05)
    assert server.started
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


@pytest_asyncio.fixture
async def seeded(db):
    """Three SSH resources covering the three default modes."""
    from keywright_server.models import Resource

    db.add_all([
        Resource(kind="ssh", name="dev", default_mode="open", config={"host": "127.0.0.1", "user": "root"}),
        Resource(kind="ssh", name="nvr", default_mode="approval", config={"host": "127.0.0.1", "user": "root"}),
        Resource(kind="ssh", name="prod", default_mode="locked", config={"host": "127.0.0.1", "user": "root"}),
    ])
    await db.commit()


@pytest.fixture
def fake_ssh(monkeypatch):
    """Replace the SSH runner; returns the list of (host, command, user) calls made."""
    from keywright_server import ssh

    calls = []

    async def run(config, command, *, timeout=300, user=None, stdin=None):
        calls.append((config["host"], command, user))
        return ssh.RunResult(exit_code=0, stdout=f"ran: {command}\n", stderr="", truncated=False, duration_ms=3,
                             learned_host_key="ssh-ed25519 AAAAfake")

    monkeypatch.setattr(ssh, "run", run)
    return calls


@pytest_asyncio.fixture
async def fake_upstream(db, monkeypatch):
    """A brokered MCP server `ha` in approval mode whose upstream is faked; returns the (tool, arguments)
    calls that reached it. The fake validates strictly, as a well-built upstream does."""
    from mcp import types

    from keywright_server import mcp_proxy
    from keywright_server.models import Resource

    db.add(Resource(kind="mcp", name="ha", default_mode="approval", config={"url": "http://ha.test/mcp"}))
    await db.commit()
    calls = []
    tools = [types.Tool(name="ha_get_state", description="Read a state",
                        inputSchema={"type": "object", "properties": {"entity_id": {"type": "string"}},
                                     "additionalProperties": False})]

    async def list_tools(resource_name, config, *, force=False):
        return tools

    async def call_tool(config, tool, arguments):
        calls.append((tool, dict(arguments or {})))
        unknown = set(arguments or {}) - {"entity_id"}
        if unknown:
            return types.CallToolResult(is_error=True, content=[types.TextContent(
                type="text", text=f"VALIDATION_FAILED: unknown parameter {sorted(unknown)}")])
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"state of {arguments['entity_id']}: on")])

    monkeypatch.setattr(mcp_proxy, "list_tools", list_tools)
    monkeypatch.setattr(mcp_proxy, "call_tool", call_tool)
    return calls
