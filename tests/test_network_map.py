"""The graph must not turn cached controller observations into live connectivity claims."""
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select

from keywright_server import discovery as disc
from keywright_server import inventory, network_map
from keywright_server.models import DiscoveryLink, Resource, now
from keywright_server.web import auth
from keywright_server.web.app import create_app


def observed(mac='aa:bb:cc:dd:ee:01', name='Office AP', category='device', site='home', **changes):
    return {'external_id': f'{site}/{category}/{mac}', 'data': {
        'name': name, 'kind': 'network' if category == 'device' else 'device', 'site': site,
        'mac': mac, 'addresses': ['192.0.2.10'], 'medium': 'unknown', 'attachment': '',
        'port': '', 'parent': '', 'status': 'Unknown', **changes}}


async def controller(db, name='Omada'):
    r = Resource(name=name, kind='mcp', default_mode='locked',
                 config={'adapter': 'omada', 'client_secret': 'must-not-leak'})
    db.add(r)
    await db.commit()
    return r


async def collect(r, records):
    run_id, _ = await disc.start_run(r.id, 'omada')
    return await disc.finish_run(run_id, records)


async def test_graph_source_scoping_and_reported_attachments(db):
    r, other = await controller(db), await controller(db, 'Other')
    ap = observed(device_type='ap', model='EAP')
    client = observed('aa:bb:cc:dd:ee:02', 'Laptop', category='client', medium='wifi',
                      attachment=ap['external_id'], port='Home Wi-Fi', status='Active')
    remote = observed('aa:bb:cc:dd:ee:02', 'Same MAC at other site', category='client', site='remote',
                      attachment='remote/device/aa:bb:cc:dd:ee:01')
    await collect(r, [ap, client, remote])
    await collect(other, [observed(name='Other controller AP')])
    graph = await network_map.snapshot(db, r.id)
    assert len(graph['nodes']) == 3 and len(graph['edges']) == 1
    laptop = next(n for n in graph['nodes'] if n['name'] == 'Laptop')
    ap_node = next(n for n in graph['nodes'] if n['name'] == 'Office AP')
    assert laptop['attachment'] == ap_node['id'] and laptop['state'] == 'online'
    assert ap_node['state'] == 'unknown' and ap_node['role'] == 'ap'
    assert graph['edges'][0]['provenance'] == 'Omada' and graph['edges'][0]['medium'] == 'wifi'
    assert graph['fresh'] and graph['counts']['unreviewed'] == 3
    assert 'must-not-leak' not in str(graph) and 'client_secret' not in str(graph)
    assert graph['nodes'][0]['review_url'].startswith('/ui/inventory/discovery/obs_')


async def test_missing_and_inactive_do_not_look_online(db):
    r = await controller(db)
    await collect(r, [observed(), observed('aa:bb:cc:dd:ee:02', 'Old', category='client'),
                      observed('aa:bb:cc:dd:ee:03', 'Recent', category='client')])
    old = await db.scalar(select(disc.Observation).where(disc.Observation.external_id.like('%ee:02')))
    old.last_seen = now() - timedelta(hours=25)
    await db.commit()
    await collect(r, [observed(status='Inactive')])
    graph = await network_map.snapshot(db, r.id)
    assert {n['name']: n['state'] for n in graph['nodes']} == {
        'Office AP': 'inactive', 'Old': 'old', 'Recent': 'missing'}
    assert sum(n['missing'] for n in graph['nodes']) == 2


@pytest.mark.parametrize('reason', ['expired', 'failed', 'configuration'])
async def test_stale_source_never_claims_device_is_online_or_gone(db, reason):
    r = await controller(db)
    run = await collect(r, [observed(status='Active')])
    if reason == 'expired':
        stored = await db.get(disc.Run, run.id)
        stored.finished_at = now() - timedelta(seconds=181)
        await db.commit()
    elif reason == 'failed':
        run_id, _ = await disc.start_run(r.id, 'omada')
        await disc.finish_run(run_id, error='Controller unavailable')
    else:
        r.config = {**r.config, 'client_secret': 'changed'}
        await db.commit()
    graph = await network_map.snapshot(db, r.id)
    assert not graph['fresh'] and graph['nodes'][0]['state'] == 'stale'
    assert graph['last_success'] and graph['nodes'][0]['source_status'] == 'Active'
    assert graph['configuration_changed'] == (reason == 'configuration')


async def test_empty_or_non_omada_source_has_no_observations(db):
    assert (await network_map.snapshot(db))['sources'] == []
    r = Resource(name='SSH', kind='ssh', config={})
    db.add(r)
    await db.commit()
    assert (await network_map.snapshot(db, r.id))['source'] == ''
    omada = await controller(db)
    graph = await network_map.snapshot(db, omada.id)
    assert not graph['fresh'] and not graph['nodes'] and not graph['last_success']


async def test_manual_edges_require_reviewed_links_and_respect_source_attachment(db):
    r = await controller(db)
    ap, switch = observed(), observed('aa:bb:cc:dd:ee:02', 'Switch')
    await collect(r, [ap, switch])
    a = await inventory.save_asset(db, {'name': 'AP', 'kind': 'network'})
    b = await inventory.save_asset(db, {'name': 'Switch', 'kind': 'network'})
    iface = await inventory.save_interface(db, {'asset_id': a.id, 'name': 'eth0', 'medium': 'wired',
                                                'attached_to_id': b.id, 'port': '8'})
    await db.commit()
    assert (await network_map.snapshot(db, r.id))['edges'] == []
    rows = list((await db.scalars(select(disc.Observation).order_by(disc.Observation.external_id))).all())
    db.add_all([DiscoveryLink(observation_id=rows[0].id, asset_id=a.id, interface_id=iface.id),
                DiscoveryLink(observation_id=rows[1].id, asset_id=b.id)])
    await db.commit()
    graph = await network_map.snapshot(db, r.id)
    assert graph['edges'] == [{'source': rows[1].id, 'target': rows[0].id, 'medium': 'wired',
                               'label': '8', 'provenance': 'Inventory', 'historical': False}]
    assert graph['counts']['unreviewed'] == 0 and all(n['asset_url'] for n in graph['nodes'])
    ap_node = next(n for n in graph['nodes'] if n['name'] == 'Office AP')
    assert ap_node['attachment_source'] == 'Inventory' and ap_node['medium'] == 'wired'
    assert ap_node['port'] == '8'
    await collect(r, [observed(attachment=switch['external_id'], medium='wired', port='9'), switch])
    # snapshot uses its own transaction in the web route; expire this test's cached ORM rows too.
    source_id = r.id
    db.expire_all()
    graph = await network_map.snapshot(db, source_id)
    assert len(graph['edges']) == 1 and graph['edges'][0]['provenance'] == 'Omada'
    assert graph['edges'][0]['label'] == '9'


async def test_refresh_cooldown_does_not_create_runs_or_collect_twice(db, monkeypatch):
    r = await controller(db)
    calls = []
    async def read(*args):
        calls.append(args)
        return [observed()]
    monkeypatch.setattr(disc, 'collect', read)
    await disc.refresh(r.id, 'omada', min_interval=60)
    with pytest.raises(disc.DiscoveryError, match='Wait 60 seconds'):
        await disc.refresh(r.id, 'omada', min_interval=60)
    assert len(calls) == 1
    assert await db.scalar(select(func.count()).select_from(disc.Run)) == 1


async def test_routes_require_admin_origin_and_never_fetch_on_get(db, monkeypatch):
    r = await controller(db)
    source_id = r.id
    await auth.set_password(db, 'adminpass123')
    calls = []
    async def read(*args):
        calls.append(args)
        return [observed(name='</script><script>alert(1)</script>')]
    monkeypatch.setattr(disc, 'collect', read)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()),
                                 base_url='http://gk.test') as client:
        for path in ('/ui/inventory/map', '/ui/inventory/map/data'):
            assert (await client.get(path)).status_code == 303
        form = {'resource_id': source_id}
        assert (await client.post('/ui/inventory/map/refresh', data=form,
                                 headers={'Origin': 'http://gk.test'})).status_code == 303
        await client.post('/ui/login', data={'password': 'adminpass123'}, headers={'Origin': 'http://gk.test'})
        for path in ('/ui/inventory/map', '/ui/inventory/map/data'):
            assert (await client.get(path)).status_code == 200
        assert not calls
        for headers in ({}, {'Origin': 'https://evil.test'}):
            assert (await client.post('/ui/inventory/map/refresh', data=form, headers=headers)).status_code == 403
        response = await client.post('/ui/inventory/map/refresh', data=form, headers={'Origin': 'http://gk.test'})
        assert response.status_code == 200 and response.json()['nodes']
        assert response.headers['cache-control'] == 'no-store'
        page = await client.get('/ui/inventory/map')
        assert page.status_code == 200 and '</script><script>alert(1)</script>' not in page.text
        assert r'\u003c/script\u003e' in page.text and 'Network map' in page.text
        assert (await client.post('/ui/inventory/map/refresh', data=form,
                                 headers={'Origin': 'http://gk.test'})).status_code == 409
        assert len(calls) == 1
        # Extra Omada display fields remain reviewable by the existing discovery view.
        assert (await client.get('/ui/inventory/discovery')).status_code == 200


async def test_failed_refresh_returns_saved_graph_with_error(db, monkeypatch):
    r = await controller(db)
    await collect(r, [observed(status='Active')])
    # Age only the attempt time to allow another refresh while the saved snapshot is still recent.
    run = await db.scalar(select(disc.Run))
    run.started_at = now() - timedelta(seconds=61)
    await db.commit()
    async def fail(*args):
        raise disc.DiscoveryError('Controller unavailable')
    monkeypatch.setattr(disc, 'collect', fail)
    app = create_app()
    app.dependency_overrides[auth.require_admin] = lambda: None
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://gk.test') as client:
        response = await client.post('/ui/inventory/map/refresh', data={'resource_id': r.id},
                                     headers={'Origin': 'http://gk.test'})
    assert response.status_code == 502
    graph = response.json()
    assert graph['error'] == 'Controller unavailable' and graph['last_success']
    assert len(graph['nodes']) == 1 and graph['nodes'][0]['state'] == 'stale'


async def test_reported_mesh_never_uses_a_conflicting_manual_wired_uplink(db):
    r = await controller(db)
    await collect(r, [observed(device_type='ap', medium='wifi'), observed('aa:bb:cc:dd:ee:02', 'Switch')])
    a = await inventory.save_asset(db, {'name': 'AP', 'kind': 'network'})
    b = await inventory.save_asset(db, {'name': 'Switch', 'kind': 'network'})
    await inventory.save_interface(db, {'asset_id': a.id, 'name': 'uplink', 'medium': 'wired',
                                       'attached_to_id': b.id, 'port': 'PoE'})
    rows = list((await db.scalars(select(disc.Observation).order_by(disc.Observation.external_id))).all())
    db.add_all([DiscoveryLink(observation_id=rows[0].id, asset_id=a.id),
                DiscoveryLink(observation_id=rows[1].id, asset_id=b.id)])
    await db.commit()
    graph = await network_map.snapshot(db, r.id)
    assert graph['edges'] == []
    assert next(n for n in graph['nodes'] if n['name'] == 'Office AP')['medium'] == 'wifi'


async def test_explicit_unmanaged_wan_parent_is_drawn_but_never_marked_online(db):
    r = await controller(db)
    await collect(r, [observed(name='Gateway', device_type='gateway')])
    gateway = await inventory.save_asset(db, {'name': 'Gateway', 'kind': 'network'})
    wan = await inventory.save_asset(db, {'name': 'WAN', 'kind': 'service'})
    await inventory.save_interface(db, {'asset_id': gateway.id, 'name': 'uplink', 'medium': 'wired',
                                       'attached_to_id': wan.id, 'port': 'WAN 1'})
    row = await db.scalar(select(disc.Observation))
    db.add(DiscoveryLink(observation_id=row.id, asset_id=gateway.id))
    await db.commit()
    graph = await network_map.snapshot(db, r.id)
    assert len(graph['nodes']) == 2 and len(graph['edges']) == 1
    external = next(n for n in graph['nodes'] if n['name'] == 'WAN')
    assert external['virtual'] and external['role'] == 'external' and external['state'] == 'unknown'
    assert external['source_status'] == 'Not monitored' and not external['review_url']
    assert graph['edges'][0]['provenance'] == 'Inventory' and graph['edges'][0]['label'] == 'WAN 1'
    assert graph['counts']['unknown'] == 1  # The external connection isn't an observed device.
