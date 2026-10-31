"""Regression cases for the credential broker's authorization boundaries."""
import asyncio
import threading
from datetime import timedelta

import pytest
from keywright.classify import classify
from sqlalchemy import func, select

from keywright_server import approvals, policy
from keywright_server.db import session
from keywright_server.models import Agent, Grant, Policy, Resource, now


@pytest.fixture
async def protected(db):
    db.add(Resource(kind="ssh", name="box", default_mode="approval", config={"host": "example.invalid"}))
    await db.commit()


@pytest.mark.parametrize("command", [
    "echo safe\nrm /tmp/example",
    "echo safe # comment\nrm /tmp/example",
    "echo changed > /tmp/example",
    "/tmp/ls -la",
    "PATH=/tmp ls",
    "ls#attacker-executable",
    "env LD_PRELOAD=/tmp/example.so ls",
    "sudo --user=root ls",
    "git -c alias.status='!id' status",
    "find /tmp -okdir echo {} ;",
])
def test_complex_shell_requires_host_scope(command):
    assert classify("box", command) == ["ssh/box/exec/**"]


async def test_once_is_single_use_under_concurrency(db, agent, protected):
    grant = Grant(agent_id=agent.id, pattern="ssh/box/exec/ls", scope="once", uses_remaining=1)
    db.add(grant)
    await db.commit()
    async def attempt():
        async with session() as other:
            identity = await other.get(Agent, agent.id)
            return await policy.evaluate(other, identity, None, ["ssh/box/exec/ls"])
    results = await asyncio.gather(*(attempt() for _ in range(8)))
    assert sum(v.allowed for v in results) == 1


async def test_same_once_grant_covers_one_compound_call(db, agent, protected):
    grant = Grant(agent_id=agent.id, pattern="ssh/box/exec/**", scope="once", uses_remaining=1)
    db.add(grant)
    await db.commit()
    v = await policy.evaluate(db, agent, None, ["ssh/box/exec/ls", "ssh/box/exec/df"])
    assert v.allowed and v.consumed_grants == [grant.id]
    await db.refresh(grant)
    assert grant.uses_remaining == 0


async def test_concurrent_decisions_create_one_grant(db, agent, protected, log_notifier):
    req = await approvals.create(db, agent, None, ["ssh/box/exec/ls"], "inspect")
    async def decide():
        async with session() as other:
            await approvals.decide(other, req.id, "once", via="ui")
    await asyncio.gather(*(decide() for _ in range(8)))
    count = await db.scalar(select(func.count()).select_from(Grant).where(Grant.request_id == req.id))
    assert count == 1


async def test_pending_requests_are_bound_to_operation_and_session(db, agent, protected, log_notifier):
    from keywright_server.mcp_server import _request_or_reuse
    patterns = ["ssh/box/exec/rm"]
    first, _ = await _request_or_reuse(db, agent, "s1", patterns, "cleanup", {"command": "rm /tmp/one"})
    same, reused = await _request_or_reuse(db, agent, "s1", patterns, "retry", {"command": "rm /tmp/one"})
    changed, _ = await _request_or_reuse(db, agent, "s1", patterns, "cleanup", {"command": "rm /tmp/two"})
    other_session, _ = await _request_or_reuse(db, agent, "s2", patterns, "cleanup", {"command": "rm /tmp/one"})
    assert same.id == first.id and reused
    assert len({first.id, changed.id, other_session.id}) == 3


async def test_once_cannot_authorize_different_arguments(db, agent, protected, log_notifier):
    detail = {"command": "rm /tmp/one"}
    req = await approvals.create(db, agent, "s1", ["ssh/box/exec/rm"], "cleanup", detail)
    await approvals.decide(db, req.id, "once", via="ui")
    assert not (await policy.evaluate(db, agent, "s1", req.patterns,
                                     operation={"command": "rm /tmp/two"})).allowed
    assert not (await policy.evaluate(db, agent, "s2", req.patterns, operation=detail)).allowed
    assert (await policy.evaluate(db, agent, "s1", req.patterns, operation=detail)).allowed


async def test_narrow_deny_blocks_dynamic_host_scope(db, agent, protected):
    db.add_all([Policy(pattern="ssh/box/exec/**", effect="allow"),
                Policy(pattern="ssh/box/exec/rm", effect="deny")])
    await db.commit()
    assert (await policy.evaluate(db, agent, None, ["ssh/box/exec/**"])).status == "deny"


async def test_disabled_agent_cannot_use_previously_loaded_identity(db, agent, protected):
    db.add(Policy(pattern="ssh/box/exec/**", effect="allow"))
    await db.commit()
    async with session() as other:
        identity = await other.get(Agent, agent.id)
        identity.disabled_at = now()
        await other.commit()
    assert not (await policy.evaluate(db, agent, None, ["ssh/box/exec/ls"])).allowed


async def test_rotated_token_cannot_finish_waiting_call(db, agent, protected):
    db.add(Policy(pattern="ssh/box/exec/**", effect="allow"))
    await db.commit()
    async with session() as other:
        identity = await other.get(Agent, agent.id)
        identity.token_hash = "rotated"
        await other.commit()
    assert not (await policy.evaluate(db, agent, None, ["ssh/box/exec/ls"])).allowed


async def test_notifications_cannot_create_permanent_rules(db, agent, protected, log_notifier):
    req = await approvals.create(db, agent, None, ["ssh/box/exec/ls"], "inspect")
    await log_notifier.on_decision_token(f"KW_ALWAYS_{req.id}")
    await db.refresh(req)
    assert req.status == "pending"
    with pytest.raises(ValueError):
        await approvals.decide(db, req.id, "always", via="link")


async def test_unsigned_notification_is_rejected(db, agent, protected, log_notifier):
    req = await approvals.create(db, agent, None, ["ssh/box/exec/ls"], "inspect")
    await log_notifier.on_decision_token(f"KW_ONCE_{req.id}")
    await db.refresh(req)
    assert req.status == "pending"


async def test_expired_pending_request_is_not_reused(db, agent, protected, log_notifier):
    req = await approvals.create(db, agent, None, ["ssh/box/exec/ls"], "inspect")
    req.expires_at = now() - timedelta(seconds=1)
    await db.commit()
    assert await approvals.find_pending(db, agent, req.patterns) is None


@pytest.mark.parametrize('scope', ['once', 'session', 'ttl', 'deny'])
def test_compact_actions_are_signed_and_bound_to_scope(scope):
    action = approvals.notification_action('req_example', scope)
    assert approvals.parse_notification_action(action) == ('req_example', scope)
    assert approvals.parse_notification_action(action + 'x') is None
    assert approvals.parse_notification_action(action.replace('req_example', 'req_other')) is None
    assert approvals.parse_notification_action(action.replace(scope.upper(), 'ALWAYS')) is None


async def test_approval_refuses_resource_locked_after_request(db, agent, protected, log_notifier):
    req = await approvals.create(db, agent, None, ['ssh/box/exec/ls'], 'inspect')
    resource = await db.scalar(select(Resource).where(Resource.name == 'box'))
    resource.default_mode = 'locked'
    await db.commit()
    with pytest.raises(ValueError, match='locked'):
        await approvals.decide(db, req.id, 'once', via='ui')
    assert not await db.scalar(select(func.count()).select_from(Grant))


async def test_partial_consumption_rolls_back_if_another_grant_was_spent(db, agent, protected, monkeypatch):
    from sqlalchemy import update
    first = Grant(id='grt_a', agent_id=agent.id, pattern='ssh/box/exec/ls', scope='once', uses_remaining=1)
    second = Grant(id='grt_b', agent_id=agent.id, pattern='ssh/box/exec/df', scope='once', uses_remaining=1)
    db.add_all([first, second])
    await db.commit()
    execute = db.execute
    did_spend = False
    async def race(statement, *args, **kwargs):
        nonlocal did_spend
        if getattr(statement, 'is_update', False) and not did_spend:
            did_spend = True
            async with session() as other:
                await other.execute(update(Grant).where(Grant.id == 'grt_b').values(uses_remaining=0))
                await other.commit()
        return await execute(statement, *args, **kwargs)
    monkeypatch.setattr(db, 'execute', race)
    verdict = await policy.evaluate(db, agent, None, ['ssh/box/exec/ls', 'ssh/box/exec/df'])
    assert not verdict.allowed
    await db.refresh(first)
    assert first.uses_remaining == 1


async def test_browser_mutations_reject_cross_origin_and_missing_origin(live_server):
    import httpx
    async with httpx.AsyncClient(base_url=live_server) as client:
        for headers in ({}, {'Origin': 'https://evil.invalid'}, {'Origin': 'null'},
                        {'Origin': live_server, 'Sec-Fetch-Site': 'same-site'}):
            result = await client.post('/ui/login', data={'password': 'adminpass123'}, headers=headers)
            assert result.status_code == 403
        result = await client.post('/ui/login', data={'password': 'adminpass123'}, headers={'Origin': live_server})
        assert result.status_code == 303
        result = await client.post('/ui/agents', data={'name': 'csrf-created'}, headers={'Origin': 'https://evil.invalid'})
        assert result.status_code == 403
        result = await client.post('/ui/agents', data={'name': 'legitimate'}, headers={'Referer': live_server + '/ui/agents'})
        assert result.status_code == 303
        result = await client.get('/ui/agents')
        assert result.headers['cache-control'] == 'no-store'
        assert result.headers['referrer-policy'] == 'same-origin'
        assert result.headers['x-frame-options'] == 'DENY'


async def test_login_redirect_stays_local(live_server):
    import httpx
    async with httpx.AsyncClient(base_url=live_server, headers={'Origin': live_server}) as client:
        for target in ('//evil.invalid/', '/\\evil.invalid/', '/%2f%2fevil.invalid/', 'https://evil.invalid/'):
            result = await client.post('/ui/login', data={'password': 'adminpass123', 'next': target})
            assert result.status_code == 303 and result.headers['location'] == '/ui'


async def test_login_is_rate_limited(live_server):
    import httpx

    from keywright_server.web import auth
    auth._login_attempts.clear()
    auth._global_attempts.clear()
    try:
        async with httpx.AsyncClient(base_url=live_server, headers={'Origin': live_server}) as client:
            for _ in range(8):
                assert (await client.post('/ui/login', data={'password': 'wrong'})).status_code == 200
            result = await client.post('/ui/login', data={'password': 'wrong'})
            assert result.status_code == 429 and result.headers['retry-after'] == '60'
    finally:
        auth._login_attempts.clear()
        auth._global_attempts.clear()


async def test_mcp_sessions_cannot_be_used_by_another_agent(live_server, db):
    import httpx

    from keywright_server.mcp_server import hash_token
    db.add(Agent(name='other-agent', token_hash=hash_token('other-token')))
    await db.commit()
    headers = {'Authorization': 'Bearer gk_testtoken', 'Accept': 'application/json, text/event-stream',
               'MCP-Protocol-Version': '2025-03-26'}
    async with httpx.AsyncClient(base_url=live_server, headers=headers) as client:
        response = await client.post('/mcp', json={
            'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
            'params': {'protocolVersion': '2025-03-26', 'capabilities': {},
                       'clientInfo': {'name': 'security-test', 'version': '1'}},
        })
        assert response.status_code == 200
        sid = response.headers['mcp-session-id']
        for method in ('GET', 'DELETE', 'POST'):
            response = await client.request(method, '/mcp', headers={
                'Authorization': 'Bearer other-token', 'Mcp-Session-Id': sid,
            }, **({'json': {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'}} if method == 'POST' else {}))
            assert response.status_code == 404
        assert (await client.delete('/mcp', headers={'Mcp-Session-Id': sid})).status_code == 200


async def test_forwarded_https_origin_matches_behind_trusted_proxy(db, agent, log_notifier):
    """A TLS-terminating proxy hands us http:// + X-Forwarded-Proto; the browser's Origin is https://."""
    import httpx
    import uvicorn

    from conftest import free_port
    from keywright_server.web import auth
    from keywright_server.web.app import create_app

    forwarded = {'Host': 'gk.test', 'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'gk.test',
                 'Origin': 'https://gk.test'}
    for trusted, expected in (('192.0.2.1', 403), ('127.0.0.1', 303)):
        port = free_port()
        config = uvicorn.Config(create_app(), host='127.0.0.1', port=port, log_level='warning', lifespan='on',
                                forwarded_allow_ips=trusted)
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.05)
        assert server.started
        try:
            async with httpx.AsyncClient(base_url=f'http://127.0.0.1:{port}') as client:
                result = await client.post('/ui/login', data={'password': 'adminpass123'}, headers=forwarded)
                assert result.status_code == expected, (trusted, result.text)
                if expected == 303:
                    assert 'Secure' in result.headers['set-cookie']
        finally:
            server.should_exit = True
            thread.join(timeout=5)
            auth._login_attempts.clear()


def test_https_cookies_are_secure():
    from starlette.testclient import TestClient

    from keywright_server.web import auth
    from keywright_server.web.app import create_app
    with TestClient(create_app(), base_url='https://gk.test') as client:
        response = client.post('/ui/login', data={'password': 'adminpass123'},
                               headers={'Origin': 'https://gk.test'}, follow_redirects=False)
        assert response.status_code == 303
        assert 'Secure' in response.headers['set-cookie'] and 'HttpOnly' in response.headers['set-cookie']
    auth._login_attempts.clear()


async def test_password_reset_invalidates_old_session(db):
    from starlette.requests import Request

    from keywright_server.web import auth
    await auth.set_password(db, 'first-password')
    token = auth.signer().sign(auth._session_payload()).decode()
    request = Request({'type': 'http', 'headers': [(b'cookie', f'{auth.COOKIE}={token}'.encode())]})
    assert auth.is_logged_in(request)
    await auth.set_password(db, 'different-password')
    assert not auth.is_logged_in(request)


async def test_waiter_cleanup_and_already_decided_requests(db, agent, protected, log_notifier):
    req = await approvals.create(db, agent, None, ['ssh/box/exec/ls'], 'inspect')
    assert req.id not in approvals._waiters
    await approvals.wait(req.id, 0.01)
    assert req.id not in approvals._waiters
    await approvals.decide(db, req.id, 'deny', via='ui')
    await asyncio.wait_for(approvals.wait(req.id, 10), timeout=0.5)
    assert req.id not in approvals._waiters


async def test_nested_credentials_are_redacted_from_audit(db):
    from keywright_server import audit
    event = await audit.record(db, tool='mcp_call', decision='allow', detail={
        'arguments': {'entity_id': 'light.kitchen', 'password': 'secret-password',
                      'nested': [{'api_key': 'secret-key'}, {'Authorization': 'Bearer secret-token'}]},
    })
    assert event.detail['arguments']['entity_id'] == 'light.kitchen'
    assert 'secret-' not in str(event.detail)


async def test_mcp_approval_displays_arguments_and_redacts_secrets(live_server, db, agent, log_notifier):
    import httpx

    from keywright_server.models import AccessRequest
    from keywright_server.notify.base import request_summary
    req = AccessRequest(agent_id=agent.id, agent=agent, patterns=['mcp/ha/tools/turn_off'], reason='Turn off kitchen',
                        detail={'arguments': {'entity_id': 'light.kitchen', 'password': 'secret-value'}},
                        expires_at=now() + timedelta(minutes=10))
    db.add(req)
    await db.commit()
    assert 'light.kitchen' in request_summary(req, agent)[1]
    assert 'secret-value' not in request_summary(req, agent)[1]
    async with httpx.AsyncClient(base_url=live_server, headers={'Origin': live_server}) as client:
        await client.post('/ui/login', data={'password': 'adminpass123'})
        for path in ('/ui', f'/ui/requests/{req.id}', '/d/' + approvals.decision_token(req.id, 'once')):
            response = await client.get(path)
            assert response.status_code == 200
            assert 'light.kitchen' in response.text and 'secret-value' not in response.text


async def test_token_rotation_during_approval_wait_cannot_be_hidden_by_relationship_refresh(
    db, agent, protected, log_notifier, monkeypatch,
):
    from keywright_server.mcp_server import _gate
    agent_id = agent.id
    async def decide_then_rotate(request_id, timeout_s):
        async with session() as other:
            await approvals.decide(other, request_id, 'once', via='ui')
            identity = await other.get(Agent, agent_id)
            identity.token_hash = 'rotated-during-wait'
            await other.commit()
    monkeypatch.setattr(approvals, 'wait', decide_then_rotate)
    verdict, error = await _gate(db, agent, 's1', ['ssh/box/exec/ls'], 'inspect',
                                 {'command': 'ls'}, 10, 'ssh_run')
    assert verdict is None and error.structured_content['error'] == 'deny'
