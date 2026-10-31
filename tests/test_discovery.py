"""Discovery previews must not turn observations into allocations or agent access."""
import json
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select

from keywright_server import discovery as disc
from keywright_server import inventory as inv
from keywright_server.models import Agent, AuditEvent, Grant, Policy, Resource, now
from keywright_server.ssh import RunResult


def observed(key='node/pve', name='pve', **changes):
    return {'external_id': key, 'data': {'name': name, 'kind': 'physical', 'site': '', 'mac': '',
            'addresses': [], 'medium': 'unknown', 'attachment': '', 'port': '', 'parent': '',
            'status': 'online', **changes}}


async def source(db, name='PVE', kind='ssh', **config):
    r = Resource(name=name, kind=kind, config={'host': 'pve.internal', 'host_key': 'pinned', **config},
                 default_mode='locked')
    db.add(r)
    await db.commit()
    return r


def test_omada_normalization_preserves_attachment_without_guessing_hosting():
    site = {'siteId': 'site1', 'name': 'Home'}
    row = disc.omada_row({'mac': 'AA-BB-CC-DD-EE-FF', 'name': 'wireless', 'ip': '192.168.1.9',
                         'ipv6List': ['2001:db8::9', 'fe80::1', '::', 'ff02::1', 'garbage'],
                         'wireless': True, 'apMac': '00-11-22-33-44-55', 'ssid': 'Home Wi-Fi',
                         'active': False, 'client_secret': 'must not persist'}, site, 'client')
    assert row['external_id'] == 'site1/client/aa:bb:cc:dd:ee:ff'
    assert row['data']['addresses'] == ['192.168.1.9', '2001:db8::9']
    assert row['data']['medium'] == 'wifi' and row['data']['parent'] == ''
    assert row['data']['attachment'] == 'site1/device/00:11:22:33:44:55'
    assert row['data']['status'] == 'Inactive'
    assert 'client_secret' not in json.dumps(row)
    wired = disc.omada_row({'mac': 'AA-BB-CC-DD-EE-FF', 'wireless': False, 'port': 3}, site, 'client')
    assert wired['data']['medium'] == 'wired' and wired['data']['port'] == '3'
    device = disc.omada_row({'mac': 'AA-BB-CC-DD-EE-FF', 'type': 'ap', 'status': 1}, site, 'device')
    assert device['data']['medium'] == 'unknown' and device['data']['status'] == 'Unknown'
    with pytest.raises(disc.DiscoveryError):
        disc.omada_row({'mac': 'bad'}, site, 'client')


async def test_omada_paginates_all_sites_and_lists(monkeypatch):
    calls = []
    async def request(config, tool, args):
        calls.append((tool, args.copy()))
        if tool == 'omada_list_sites':
            rows = [{'siteId': 'site1', 'name': 'Home'}, {'siteId': 'site2', 'name': 'Remote'}]
        else:
            rows = [{'mac': 'AA-BB-CC-DD-EE-01'}, {'mac': 'AA-BB-CC-DD-EE-02'}]
        return {'data': [rows[args['page']-1]], 'totalRows': 2, 'currentPage': args['page']}
    monkeypatch.setattr(disc.omada, 'request', request)
    records = await disc.collect_omada({})
    assert len(records) == 8 and len(calls) == 10
    assert len({r['external_id'] for r in records}) == 8
    assert {args['site_id'] for _, args in calls if 'site_id' in args} == {'site1', 'site2'}


@pytest.mark.parametrize('second', [
    {'data': [], 'totalRows': 2, 'currentPage': 2},
    {'data': [{}], 'totalRows': 3, 'currentPage': 2},
    {'data': [{}], 'totalRows': 2, 'currentPage': 1},
    {'data': [None], 'totalRows': 2, 'currentPage': 2},
])
async def test_bad_pagination_fails_closed(monkeypatch, second):
    async def request(config, tool, args):
        return {'data': [{}], 'totalRows': 2, 'currentPage': 1} if args['page'] == 1 else second
    monkeypatch.setattr(disc.omada, 'request', request)
    with pytest.raises(disc.DiscoveryError):
        await disc.pages({}, 'omada_list_sites')


def test_proxmox_vm_identity_survives_migration_and_does_not_invent_addresses():
    rows = [{'type': 'node', 'node': 'pve', 'status': 'online'},
            {'type': 'qemu', 'node': 'pve', 'vmid': 501, 'name': 'sample-vm', 'status': 'running'},
            {'type': 'lxc', 'node': 'pve', 'vmid': 502, 'name': 'sample-container', 'status': 'stopped'},
            {'type': 'storage', 'id': 'storage/pve/local'}]
    before = disc.proxmox_rows(rows)
    rows[1]['node'] = 'hypervisor-a'
    after = disc.proxmox_rows(rows)
    assert len(before) == 3 and before[1]['external_id'] == after[1]['external_id'] == 'qemu/501'
    assert before[1]['data']['parent'] == 'node/pve' and after[1]['data']['parent'] == 'node/hypervisor-a'
    assert after[1]['data']['addresses'] == []
    assert before[2]['data']['kind'] == 'container'
    with pytest.raises(disc.DiscoveryError):
        disc.proxmox_rows([{'type': 'qemu', 'node': 'pve', 'vmid': 'bad'}])


async def test_proxmox_uses_fixed_read_command_and_rejects_truncation(monkeypatch):
    async def run(config, command, **kwargs):
        assert command == 'pvesh get /cluster/resources --output-format json'
        return RunResult(0, '[]', '', True, 1)
    monkeypatch.setattr(disc.ssh, 'run', run)
    with pytest.raises(disc.DiscoveryError, match='completely'):
        await disc.collect('proxmox', {})


async def test_refresh_is_atomic_tracks_changes_and_never_mutates_inventory(db, monkeypatch):
    r = await source(db)
    records = [observed(), observed('qemu/501', 'sample-vm', kind='vm', parent='node/pve')]
    async def collect(provider, config):
        return records
    monkeypatch.setattr(disc, 'collect', collect)
    first = await disc.refresh(r.id, 'proxmox')
    assert first.status == 'succeeded' and first.count == 2
    records = [observed('qemu/501', 'sample-vm', kind='vm', parent='node/hypervisor-a')]
    second = await disc.refresh(r.id, 'proxmox')
    rows = list((await db.scalars(select(disc.Observation))).all())
    vm = next(x for x in rows if x.external_id == 'qemu/501')
    host = next(x for x in rows if x.external_id == 'node/pve')
    assert vm.previous['parent'] == 'node/pve' and vm.data['parent'] == 'node/hypervisor-a'
    assert vm.run_id == second.id and host.run_id == first.id
    records = [observed('qemu/501', 'bad'), observed('qemu/501', 'duplicate')]
    failed = await disc.refresh(r.id, 'proxmox')
    assert failed.status == 'failed'
    await db.refresh(vm)
    assert vm.data['name'] == 'sample-vm' and vm.run_id == second.id
    for model in [inv.Asset, inv.Interface, inv.Allocation, inv.ResourceLink, Grant, Policy, Agent]:
        assert await db.scalar(select(func.count()).select_from(model)) == 0
    assert r.default_mode == 'locked'
    assert await db.scalar(select(func.count()).select_from(AuditEvent)) == 6


async def test_source_failure_is_sanitized_and_previous_observations_remain(db, monkeypatch):
    r = await source(db)
    run_id, _ = await disc.start_run(r.id, 'proxmox')
    await disc.finish_run(run_id, [observed()])
    async def fail(*args):
        raise RuntimeError('credential=secret connection failure')
    monkeypatch.setattr(disc, 'collect', fail)
    run = await disc.refresh(r.id, 'proxmox')
    assert run.status == 'failed' and 'secret' not in run.error
    observation = await db.scalar(select(disc.Observation))
    assert observation.run_id == run_id


async def test_sources_require_correct_adapter_pinned_host_and_no_overlapping_refresh(db):
    r = await source(db)
    with pytest.raises(disc.DiscoveryError):
        await disc.start_run(r.id, 'omada')
    with pytest.raises(disc.DiscoveryError):
        await disc.start_run(r.id, 'shell')
    r.config = {**r.config, 'host_key': ''}
    await db.commit()
    with pytest.raises(disc.DiscoveryError):
        await disc.start_run(r.id, 'proxmox')
    r.config = {**r.config, 'host_key': 'pinned'}
    await db.commit()
    await disc.start_run(r.id, 'proxmox')
    with pytest.raises(disc.DiscoveryError, match='already running'):
        await disc.start_run(r.id, 'proxmox')


async def test_matching_reports_all_ambiguous_candidates_without_merging(db):
    a = await inv.save_asset(db, {'name': 'same-name', 'kind': 'physical'})
    b = await inv.save_asset(db, {'name': 'different-name', 'kind': 'vm'})
    await inv.save_interface(db, {'asset_id': b.id, 'name': 'eth0', 'medium': 'virtual',
                                'mac': 'aa:bb:cc:dd:ee:ff'})
    data = await inv.snapshot(db)
    observation = disc.Observation(data=observed(name='same-name', mac='aa:bb:cc:dd:ee:ff')['data'])
    matches = disc.matches(observation, data)
    assert {x['asset'].id for x in matches} == {a.id, b.id}
    assert {x['reasons'] for x in matches} == {'name', 'MAC'}


async def test_expired_refresh_cannot_overwrite_a_newer_snapshot(db):
    r = await source(db)
    old_id, _ = await disc.start_run(r.id, 'proxmox')
    old = await db.get(disc.Run, old_id)
    old.started_at = now() - timedelta(minutes=6)
    await db.commit()
    new_id, _ = await disc.start_run(r.id, 'proxmox')
    await disc.finish_run(new_id, [observed(name='new snapshot')])
    result = await disc.finish_run(old_id, [observed(name='stale snapshot')])
    assert result.status == 'failed' and 'superseded' in result.error
    row = await db.scalar(select(disc.Observation))
    assert row.data['name'] == 'new snapshot' and row.run_id == new_id


async def test_discovery_ui_requires_admin_and_same_origin(db, monkeypatch):
    from keywright_server.web import auth
    from keywright_server.web.app import create_app
    r = await source(db)
    await auth.set_password(db, 'adminpass123')
    async def collect(*args):
        return [observed(name='<script>unsafe</script>')]
    monkeypatch.setattr(disc, 'collect', collect)
    app = create_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://gk.test',
                                 follow_redirects=False) as client:
        assert (await client.get('/ui/inventory/discovery')).status_code == 303
        form = {'provider': 'proxmox', 'resource_id': r.id}
        assert (await client.post('/ui/inventory/discovery/refresh', data=form,
                                 headers={'Origin': 'http://gk.test'})).status_code == 303
        await client.post('/ui/login', data={'password': 'adminpass123'}, headers={'Origin': 'http://gk.test'})
        assert (await client.post('/ui/inventory/discovery/refresh', data=form)).status_code == 403
        assert (await client.post('/ui/inventory/discovery/refresh', data=form,
                                 headers={'Origin': 'https://evil.test'})).status_code == 403
        assert (await client.post('/ui/inventory/discovery/refresh', data=form,
                                 headers={'Origin': 'http://gk.test'})).status_code == 303
        page = await client.get('/ui/inventory/discovery')
        assert page.status_code == 200
        assert '&lt;script&gt;unsafe&lt;/script&gt;' in page.text and '<script>unsafe</script>' not in page.text
        assert 'Refreshes only collect observations' in page.text and 'succeeded' in page.text.lower()
        assert 'No observations to show' in (await client.get('/ui/inventory/discovery?q=nomatch')).text
    assert await db.scalar(select(func.count()).select_from(disc.Run)) == 1


async def test_discovery_preview_paginates_and_preserves_filters(db):
    from keywright_server.web import auth
    from keywright_server.web.app import create_app
    r = await source(db)
    run_id, _ = await disc.start_run(r.id, 'proxmox')
    await disc.finish_run(run_id, [observed(f'qemu/{i}', f'Guest {i:03d}') for i in range(101)])
    app = create_app()
    app.dependency_overrides[auth.require_admin] = lambda: None
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://gk.test') as client:
        first = await client.get('/ui/inventory/discovery', params={'source': r.id, 'q': 'Guest'})
        assert '100 of 101 observations' in first.text and 'Guest 100' not in first.text
        second = await client.get('/ui/inventory/discovery', params={'source': r.id, 'q': 'Guest', 'page': 2})
        assert '1 of 101 observations' in second.text and 'Guest 100' in second.text
        assert f'source={r.id}&amp;q=Guest&amp;page=1' in second.text


def test_ap_mesh_uplink_is_explicit_and_wired_parent_is_not_guessed():
    data = disc.omada_row({'mac': '00-11-22-33-44-55', 'type': 'ap'}, {'siteId': 'home'}, 'device')['data']
    disc.ap_uplink(data, {'wirelessLinked': True, 'wirelessUplink': {
        'uplinkMac': 'AA-BB-CC-DD-EE-FF', 'rssi': -74, 'activity': 1, 'secret': 'do-not-store'}}, 'home')
    assert data['medium'] == 'wifi' and data['attachment'] == 'home/device/aa:bb:cc:dd:ee:ff'
    assert data['port'] == 'Mesh' and not data['uplink_note'] and 'do-not-store' not in str(data)
    wired = disc.omada_row({'mac': '00-11-22-33-44-55', 'type': 'ap'}, {'siteId': 'home'}, 'device')['data']
    disc.ap_uplink(wired, {'wirelessLinked': False}, 'home')
    assert wired['medium'] == 'wired' and not wired['attachment']
    assert 'not reported' in wired['uplink_note']
    disc.ap_uplink(data, {'wirelessLinked': True, 'wirelessUplink': {'uplinkMac': data['mac']}}, 'home')
    assert not data['attachment'] and 'not identified' in data['uplink_note']


@pytest.mark.parametrize('unavailable', [False, True])
async def test_omada_collects_ap_uplinks_without_breaking_older_controllers(monkeypatch, unavailable):
    calls = []
    async def request(config, tool, args):
        calls.append((tool, args))
        if tool == 'omada_get_ap':
            if unavailable:
                raise disc.omada.OmadaError('Not supported')
            return {'wirelessLinked': True, 'wirelessUplink': {'uplinkMac': 'AA-BB-CC-DD-EE-FF'}}
        rows = {'omada_list_sites': [{'siteId': 'home'}],
                'omada_list_devices': [{'type': 'ap', 'mac': '00-11-22-33-44-55'}],
                'omada_list_clients': [{'mac': '00-11-22-33-44-66', 'active': True}]}[tool]
        return {'data': rows, 'totalRows': len(rows), 'currentPage': 1}
    monkeypatch.setattr(disc.omada, 'request', request)
    records = await disc.collect_omada({})
    assert len(records) == 2 and len(calls) == 4
    assert records[1]['data']['status'] == 'Active'
    ap = records[0]['data']
    if unavailable:
        assert not ap['attachment'] and 'unavailable' in ap['uplink_note']
    else:
        assert ap['attachment'] == 'home/device/aa:bb:cc:dd:ee:ff'
