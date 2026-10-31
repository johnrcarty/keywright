"""Built-in inventory MCP uses the same approval boundary and commits audited changes atomically."""
import asyncio
import json
from types import SimpleNamespace

import httpx
import mcp_types as types
import pytest
from sqlalchemy import func, select

from keywright_server import approvals, audit, mcp_proxy
from keywright_server import inventory as inv
from keywright_server import inventory_mcp as internal
from keywright_server.db import session
from keywright_server.mcp_server import _proxy_call, on_call_tool, on_list_tools
from keywright_server.models import AccessRequest, Agent, AuditEvent, Policy, Resource


@pytest.fixture
async def resource(db, agent, log_notifier):
    res = Resource(kind='mcp', name='Keywright', default_mode='approval',
                   config={'adapter': 'keywright', 'bundles': internal.DEFAULT_BUNDLES})
    db.add(res)
    for tool in internal.READ_TOOLS:
        db.add(Policy(pattern=f'mcp/Keywright/tools/{tool}', effect='allow', agent_id=agent.id))
    await db.commit()
    return res


async def call(agent, tool, arguments=None):
    async with session() as db:
        a = await db.get(Agent, agent.id)
        out = await _proxy_call(db, a, 'test-session', 'Keywright', tool,
                                {**(arguments or {}), '_wait_seconds': 0, '_reason': 'Map a deployment'})
        return out.structured_content


async def revision(agent):
    return (await call(agent, 'list_inventory'))['revision']


async def allow(db, result):
    assert result['error'] == 'approval_required'
    await approvals.decide(db, result['request_id'], 'once', via='ui')


async def open_writes(db, resource):
    resource.default_mode = 'open'
    await db.commit()


async def test_exact_host_setup_approval_and_audit(db, agent, resource):
    args = {'expected_revision': await revision(agent), 'asset': {'name': 'API VM', 'kind': 'vm'}}
    pending = await call(agent, 'setup_host', args)
    assert await db.scalar(select(func.count()).select_from(inv.Asset)) == 0
    await allow(db, pending)
    changed = await call(agent, 'setup_host', {**args, 'asset': {'name': 'Different VM', 'kind': 'vm'}})
    assert changed['error'] == 'approval_required'
    saved = await call(agent, 'setup_host', args)
    assert 'asset_id' in saved
    assert (await db.get(inv.Asset, saved['asset_id'])).name == 'API VM'
    ev = await db.scalar(select(AuditEvent).where(AuditEvent.decision == 'allow',
                        AuditEvent.detail['tool'].as_string() == 'setup_host'))
    assert ev.agent_id == agent.id and ev.detail['arguments'] == args
    assert ev.detail['changes'][0]['before'] is None
    assert ev.detail['changes'][0]['after']['id'] == saved['asset_id']
    assert (await call(agent, 'setup_host', args))['error'] == 'approval_required'
    assert await db.scalar(select(func.count()).select_from(inv.Asset)) == 1


async def test_read_tools_are_also_gated_and_never_leak_credentials(db, agent, resource):
    db.add(Policy(pattern='mcp/Keywright/tools/list_inventory', effect='deny', agent_id=agent.id))
    secret = Resource(name='PVE', kind='ssh', default_mode='locked',
                      config={'host': '192.168.1.3', 'key_path': '/secret/key', 'password': 'private-value'})
    db.add(secret)
    await db.commit()
    assert (await call(agent, 'list_inventory'))['error'] == 'denied'
    async with session() as other:
        deny = await other.scalar(select(Policy).where(Policy.effect == 'deny'))
        await other.delete(deny)
        await other.commit()
    listing = await call(agent, 'list_inventory')
    assert {'id': secret.id, 'name': 'PVE', 'kind': 'ssh'} in listing['resources']
    assert '/secret/key' not in json.dumps(listing) and 'private-value' not in json.dumps(listing)
    async with session() as other:
        read = await other.scalar(select(Policy).where(Policy.pattern == 'mcp/Keywright/tools/list_inventory'))
        await other.delete(read)
        await other.commit()
    pending = await call(agent, 'list_inventory')
    assert pending['error'] == 'approval_required' and 'rows' not in pending
    await allow(db, pending)
    assert 'rows' in await call(agent, 'list_inventory')


async def test_atomic_host_interfaces_addresses_resource_and_topology(db, agent, resource):
    await open_writes(db, resource)
    parent = await inv.save_asset(db, {'name': 'PVE', 'kind': 'physical'})
    switch = await inv.save_asset(db, {'name': 'Switch', 'kind': 'network'})
    ssh = Resource(name='API', kind='ssh', config={'host': '192.168.1.9'}, default_mode='locked')
    db.add(ssh)
    subnet = await inv.save_subnet(db, {'name': 'LAN', 'cidr': '192.168.1.0/24', 'gateway': '192.168.1.1'})
    await db.commit()
    args = {'expected_revision': await revision(agent), 'asset': {'name': 'API', 'kind': 'vm',
            'parent_id': parent.id, 'notes': 'Keep me'}, 'resource_ids': [ssh.id],
            'interfaces': [{'name': 'eth0', 'medium': 'wired', 'attached_to_id': switch.id, 'port': '7',
                'allocations': [{'subnet_id': subnet.id, 'address': '192.168.1.9', 'state': 'assigned'}]}]}
    saved = await call(agent, 'setup_host', args)
    assert saved.get('asset_id'), saved
    aid = saved['asset_id']
    assert (await db.get(inv.ResourceLink, ssh.id)).asset_id == aid
    ips = await call(agent, 'list_ips', {'asset_id': aid})
    assert ips['rows'][0]['address'] == '192.168.1.9' and ips['rows'][0]['state'] == 'assigned'
    topology = await call(agent, 'get_topology', {'asset_id': aid})
    assert {e['type'] for e in topology['edges']} == {'hosted_on', 'connected_to'}
    update = await call(agent, 'setup_host', {'expected_revision': saved['revision'],
                        'asset': {'id': aid, 'site': 'Rack 2'}})
    assert 'asset_id' in update
    asset = await db.get(inv.Asset, aid)
    assert asset.name == 'API' and asset.kind == 'vm' and asset.parent_id == parent.id and asset.notes == 'Keep me'
    await db.refresh(ssh)
    assert ssh.default_mode == 'locked' and ssh.config == {'host': '192.168.1.9'}
    # Retrying a previously applied operation is refused even under standing write access.
    assert 'changed since' in (await call(agent, 'setup_host', args))['hint']


@pytest.mark.parametrize('failure', ['duplicate_ip', 'wrong_interface', 'resource_link', 'parent_cycle'])
async def test_failed_compound_operation_rolls_back(db, agent, resource, failure):
    await open_writes(db, resource)
    old = await inv.save_asset(db, {'name': 'Existing', 'kind': 'physical'})
    iface = await inv.save_interface(db, {'asset_id': old.id, 'name': 'eth0', 'medium': 'wired'})
    subnet = await inv.save_subnet(db, {'name': 'LAN', 'cidr': '192.168.1.0/24'})
    await inv.save_allocation(db, {'subnet_id': subnet.id, 'address': '192.168.1.9', 'label': 'In use', 'state': 'reserved'})
    await inv.link_resource(db, {'resource_id': resource.id, 'asset_id': old.id})
    await db.commit()
    args = {'expected_revision': await revision(agent), 'asset': {'name': 'New'}}
    if failure == 'duplicate_ip':
        args['interfaces'] = [{'name': 'eth0', 'allocations': [{'subnet_id': subnet.id, 'address': '192.168.1.9'}]}]
    elif failure == 'wrong_interface':
        args['interfaces'] = [{'id': iface.id}]
    elif failure == 'resource_link':
        args['resource_ids'] = [resource.id]
    else:
        args['asset'] = {'id': old.id, 'parent_id': old.id}
    result = await call(agent, 'setup_host', args)
    assert result['error'] == 'inventory_conflict', result
    assert await db.scalar(select(func.count()).select_from(inv.Asset)) == 1
    assert await db.scalar(select(func.count()).select_from(inv.Interface)) == 1
    assert await db.scalar(select(func.count()).select_from(inv.Allocation)) == 1
    await db.refresh(old)
    assert old.name == 'Existing' and old.parent_id is None


async def test_stale_approval_and_concurrent_writes(db, agent, resource):
    args = {'expected_revision': await revision(agent), 'asset': {'name': 'Stale'}}
    pending = await call(agent, 'setup_host', args)
    await allow(db, pending)
    await inv.save_asset(db, {'name': 'Manual', 'kind': 'physical'})
    await db.commit()
    assert 'changed since' in (await call(agent, 'setup_host', args))['hint']
    await open_writes(db, resource)
    rev = await revision(agent)
    results = await asyncio.gather(*(call(agent, 'setup_host', {'expected_revision': rev, 'asset': {'name': name}})
                                    for name in ('Concurrent A', 'Concurrent B')))
    assert sum('asset_id' in r for r in results) == 1
    assert sum(r.get('error') == 'inventory_conflict' for r in results) == 1
    assert await db.scalar(select(func.count()).select_from(inv.Asset)) == 2


@pytest.mark.parametrize('tool,args', [('list_inventory', {'limit': True}), ('list_ips', {'limit': 501}),
    ('setup_host', {'asset': {'name': 'Missing revision'}}), ('list_inventory', {'url': 'http://internal'}),
    ('setup_host', {'expected_revision': 'a'*64, 'asset': {'name': 'Wrong', 'default_mode': 'open'}}),
    ('run_sql', {'sql': 'drop table resources'})])
async def test_invalid_calls_never_request_or_mutate(db, agent, resource, tool, args):
    assert (await call(agent, tool, args))['error'] == 'invalid_arguments'
    assert await db.scalar(select(func.count()).select_from(AccessRequest)) == 0
    assert await db.scalar(select(func.count()).select_from(inv.Asset)) == 0


async def test_subnets_ip_reservations_pagination_and_ipv6(db, agent, resource):
    await open_writes(db, resource)
    subnet = await call(agent, 'save_subnet', {'expected_revision': await revision(agent),
        'subnet': {'name': 'LAN', 'cidr': '192.168.1.0/24', 'gateway': '192.168.1.1',
                   'dhcp_start': '192.168.1.100', 'dhcp_end': '192.168.1.200'}})
    reserved = await call(agent, 'save_ip', {'expected_revision': subnet['revision'],
        'allocation': {'subnet_id': subnet['subnet_id'], 'address': '192.168.1.9', 'label': 'New service'}})
    assert reserved.get('allocation_id'), reserved
    ip_list = await call(agent, 'list_ips', {'address': '192.168.1.9'})
    assert ip_list['rows'][0]['state'] == 'reserved' and ip_list['rows'][0]['interface_id'] is None
    ipv6 = await call(agent, 'save_subnet', {'expected_revision': reserved['revision'],
        'subnet': {'name': 'IPv6', 'cidr': '2001:db8::/64'}})
    assert ipv6.get('subnet_id'), ipv6
    page = await call(agent, 'list_subnets', {'limit': 1})
    assert page['total'] == 2 and page['next_offset'] == 1
    page2 = await call(agent, 'list_subnets', {'offset': 1, 'limit': 1})
    assert page2['next_offset'] is None
    lan = next(r for r in (await call(agent, 'list_subnets'))['rows'] if r['name'] == 'LAN')
    assert lan['gaps'] == [('192.168.1.2', '192.168.1.8'), ('192.168.1.10', '192.168.1.99'), ('192.168.1.201', '192.168.1.254')]


async def test_authentication_tool_visibility_and_locked_mode(db, agent, resource):
    missing = SimpleNamespace(request=SimpleNamespace(headers={}))
    assert (await on_list_tools(missing, None)).tools == []
    out = await on_call_tool(missing, types.CallToolRequestParams(name='Keywright__list_inventory', arguments={}))
    assert out.structured_content['error'] == 'unauthorized'
    ctx = SimpleNamespace(request=SimpleNamespace(headers={'authorization': 'Bearer gk_testtoken'}))
    names = {t.name for t in (await on_list_tools(ctx, None)).tools}
    assert 'Keywright__setup_host' in names
    resource.default_mode = 'locked'
    await db.commit()
    names = {t.name for t in (await on_list_tools(ctx, None)).tools}
    assert 'Keywright__setup_host' not in names and 'Keywright__list_ips' in names
    assert (await call(agent, 'setup_host', {'expected_revision': await revision(agent), 'asset': {'name': 'Blocked'}}))['error'] == 'locked'


async def test_audit_failure_rolls_back_inventory(db, agent, resource, monkeypatch):
    await open_writes(db, resource)
    rev = await revision(agent)
    original = audit.record

    async def fail(db, **kwargs):
        if kwargs.get('detail', {}).get('changes'):
            raise RuntimeError('Audit unavailable')
        return await original(db, **kwargs)

    monkeypatch.setattr(audit, 'record', fail)
    with pytest.raises(RuntimeError, match='Audit unavailable'):
        await call(agent, 'setup_host', {'expected_revision': rev, 'asset': {'name': 'Must roll back'}})
    assert await db.scalar(select(func.count()).select_from(inv.Asset)) == 0


async def test_internal_resource_admin_setup_and_probe(db):
    from keywright_server.web import auth
    from keywright_server.web.app import create_app
    await auth.set_password(db, 'adminpass123')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url='http://gk.test',
                                 headers={'Origin': 'http://gk.test'}, follow_redirects=True) as client:
        await client.post('/ui/login', data={'password': 'adminpass123'})
        page = await client.get('/ui/resources/new?kind=mcp&adapter=keywright')
        assert page.status_code == 200 and 'Keywright inventory' in page.text
        assert 'Streamable HTTP URL' not in page.text and 'name="headers"' not in page.text
        await client.post('/ui/resources', data={'kind': 'mcp', 'adapter': 'keywright', 'name': 'Keywright',
            'default_mode': 'approval', 'audit_handle': '1', 'bundles_text': 'read-only: tools/list_*'})
        res = await db.scalar(select(Resource).where(Resource.name == 'Keywright'))
        assert res.config['adapter'] == 'keywright' and res.default_mode == 'approval'
        assert 'url' not in res.config and 'headers' not in res.config
        assert (await mcp_proxy.probe(res.config))[0]
        tools = await mcp_proxy.list_tools(res.name, res.config)
        assert len(tools) == 8
        page = await client.get('/ui/access', params={'resource': res.id})
        assert page.status_code == 200 and 'setup_host' in page.text and 'list_ips' in page.text


async def test_cached_discovery_keeps_source_time_and_link(db, agent, resource):
    from keywright_server import discovery as disc
    from keywright_server.models import DiscoveryLink
    source = Resource(name='Omada', kind='mcp', config={'adapter': 'omada'}, default_mode='locked')
    db.add(source)
    await db.commit()
    run_id, _ = await disc.start_run(source.id, 'omada')
    await disc.finish_run(run_id, [{'external_id': 'client', 'data': {'name': 'TV', 'kind': 'device',
        'site': 'Home', 'mac': 'aa:bb:cc:dd:ee:ff', 'addresses': ['192.168.1.15'], 'medium': 'wifi',
        'port': 'Home', 'attachment': '', 'parent': '', 'status': 'Active'}}])
    observation = await db.scalar(select(disc.Observation))
    asset = await inv.save_asset(db, {'name': 'Living room TV', 'kind': 'device'})
    db.add(DiscoveryLink(observation_id=observation.id, asset_id=asset.id, reviewed_data=observation.data))
    await db.commit()
    result = await call(agent, 'list_discovery', {'resource_id': source.id, 'query': '192.168.1.15'})
    assert result['total'] == 1
    assert result['rows'][0]['asset_id'] == asset.id
    assert result['rows'][0]['source_name'] == 'Omada' and result['rows'][0]['last_seen']
    assert (await call(agent, 'list_ips'))['total'] == 0  # Observations never become confirmed allocations implicitly.


async def test_internal_mcp_over_http_with_human_approval(live_server, resource):
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared._httpx_utils import create_mcp_http_client
    http_client = create_mcp_http_client(headers={'Authorization': 'Bearer gk_testtoken'})
    async with Client(streamable_http_client(live_server + '/mcp', http_client=http_client)) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert {f'Keywright__{n}' for n in internal.OPERATIONS} <= names
        out = await client.call_tool('Keywright__list_inventory', {})
        args = {'expected_revision': out.structured_content['revision'], 'asset': {'name': 'HTTP deployment'},
                '_reason': 'Record the deployed service host', '_wait_seconds': 0}
        pending = await client.call_tool('Keywright__setup_host', args)
        rid = pending.structured_content['request_id']
        async with httpx.AsyncClient(base_url=live_server, headers={'Origin': live_server}) as http:
            await http.post('/ui/login', data={'password': 'adminpass123'})
            page = await http.get(f'/ui/requests/{rid}')
            assert 'HTTP deployment' in page.text and 'setup_host' in page.text
            approved = await http.post(f'/ui/requests/{rid}/decide', data={'scope': 'once'})
            assert approved.status_code == 303
        saved = await client.call_tool('Keywright__setup_host', args)
        assert not saved.is_error and saved.structured_content['asset_id']
        assert saved.meta['keywright']['audit_id']
        topology = await client.call_tool('Keywright__get_topology', {'query': 'HTTP deployment'})
        assert topology.structured_content['rows'][0]['name'] == 'HTTP deployment'
