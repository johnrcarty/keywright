"""Reviewed discovery must preserve ownership, manual edits, and allocated addresses."""
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select, text

from keywright_server import discovery as disc
from keywright_server import inventory as inv
from keywright_server import reconciliation as rec
from keywright_server.db import session
from keywright_server.models import Agent, AuditEvent, DiscoveryLink, Grant, Policy, Resource, now


def record(key='client', **changes):
    return {'external_id': key, 'data': {'name': 'Observed device', 'kind': 'device', 'site': 'Home',
            'mac': 'aa:bb:cc:dd:ee:ff', 'addresses': ['192.168.1.9'], 'medium': 'wifi', 'port': 'Home Wi-Fi',
            'attachment': '', 'parent': '', 'status': 'Active', **changes}}


@pytest.fixture
async def source(db):
    resource = Resource(name='Omada', kind='mcp', config={'adapter': 'omada'}, default_mode='locked')
    db.add(resource)
    await db.commit()
    return resource


async def observe(source, *records):
    run_id, _ = await disc.start_run(source.id, 'omada')
    await disc.finish_run(run_id, list(records))
    async with session() as db:
        return {r.external_id: r.id for r in (await db.scalars(select(disc.Observation))).all()}


async def form_for(oid, target_id='', interface_id='', **extra):
    async with session() as db:
        ctx = await rec.review(db, oid, target_id, interface_id)
    return {'review_token': ctx['review_token'], 'target_id': ctx['target_selection'],
            'interface_id': ctx['selected_interface_id'], 'action': 'save', 'name': ctx['observation'].data['name'],
            'kind': ctx['observation'].data['kind'], 'site': ctx['observation'].data['site'], **extra}


async def test_import_only_creates_selected_records_and_audits_provenance(db, source):
    oid = (await observe(source, record()))['client']
    form = await form_for(oid)
    aid = await rec.apply(oid, form)
    asset = await db.get(inv.Asset, aid)
    assert asset.name == 'Observed device' and asset.site == 'Home'
    link = await db.get(DiscoveryLink, oid)
    assert link.asset_id == aid and link.interface_id is None and link.reviewed_data['addresses'] == ['192.168.1.9']
    for model in (inv.Interface, inv.Allocation, inv.ResourceLink, Grant, Policy, Agent):
        assert await db.scalar(select(func.count()).select_from(model)) == 0
    audit = await db.scalar(select(AuditEvent).where(AuditEvent.tool == 'inventory.discovery.review'))
    assert audit.detail['resource_id'] == source.id and audit.detail['after']['asset']['name'] == asset.name
    with pytest.raises(disc.DiscoveryError, match='changed since'):
        await rec.apply(oid, form)
    assert await db.scalar(select(func.count()).select_from(inv.Asset)) == 1


async def test_link_existing_preserves_manual_fields_and_does_not_grant_access(db, source):
    a = await inv.save_asset(db, {'name': 'Manual name', 'kind': 'vm', 'site': 'Rack', 'tags': 'keep', 'notes': 'owner'})
    await inv.link_resource(db, {'asset_id': a.id, 'resource_id': source.id})
    await db.commit()
    oid = (await observe(source, record()))['client']
    await rec.apply(oid, await form_for(oid, a.id))
    await db.refresh(a)
    assert (a.name, a.kind, a.site, a.tags, a.notes) == ('Manual name', 'vm', 'Rack', 'keep', 'owner')
    await rec.apply(oid, await form_for(oid, apply_site='1'))
    await db.refresh(a)
    assert a.site == 'Home' and a.name == 'Manual name' and a.kind == 'vm'
    assert source.default_mode == 'locked'
    assert await db.scalar(select(func.count()).select_from(Grant)) == 0


async def test_interface_and_confirmed_allocation_import_keeps_old_addresses(db, source):
    subnet = await inv.save_subnet(db, {'name': 'LAN', 'cidr': '192.168.1.0/24',
                                    'dhcp_start': '192.168.1.2', 'dhcp_end': '192.168.1.200'})
    await db.commit()
    oid = (await observe(source, record()))['client']
    aid = await rec.apply(oid, await form_for(oid, apply_interface='1', interface_name='wlan0',
                               address_0=subnet.id, confirm_addresses='1'))
    link = await db.get(DiscoveryLink, oid)
    iface = await db.get(inv.Interface, link.interface_id)
    assert iface.asset_id == aid and iface.medium == 'wifi' and iface.mac == 'aa:bb:cc:dd:ee:ff'
    await observe(source, record(addresses=['192.168.1.20'], port='Changed SSID'))
    await db.refresh(iface)
    assert iface.port == 'Home Wi-Fi'
    await rec.apply(oid, await form_for(oid, apply_interface='1', address_0=subnet.id, confirm_addresses='1'))
    ips = list((await db.scalars(select(inv.Allocation.address).order_by(inv.Allocation.address))).all())
    assert ips == ['192.168.1.20', '192.168.1.9']
    await db.refresh(iface)
    assert iface.port == 'Changed SSID'


@pytest.mark.parametrize('failure', ['confirmation', 'conflict', 'gateway', 'subnet'])
async def test_failed_address_import_rolls_back_asset_interface_and_link(db, source, failure):
    subnet = await inv.save_subnet(db, {'name': 'LAN', 'cidr': '192.168.1.0/24',
                                      'gateway': '192.168.1.9' if failure == 'gateway' else ''})
    if failure == 'conflict':
        await inv.save_allocation(db, {'subnet_id': subnet.id, 'address': '192.168.1.9',
                                      'state': 'reserved', 'label': 'Someone else'})
    await db.commit()
    oid = (await observe(source, record()))['client']
    form = await form_for(oid, apply_interface='1', interface_name='eth0',
                          address_0='missing' if failure == 'subnet' else subnet.id,
                          confirm_addresses='' if failure == 'confirmation' else '1')
    with pytest.raises((disc.DiscoveryError, inv.InventoryError)):
        await rec.apply(oid, form)
    for model in (inv.Asset, inv.Interface, DiscoveryLink):
        assert await db.scalar(select(func.count()).select_from(model)) == 0


async def test_reused_private_address_requires_explicit_address_space(db, source):
    a = await inv.save_subnet(db, {'name': 'LAN', 'cidr': '192.168.1.0/24', 'scope': 'home'})
    b = await inv.save_subnet(db, {'name': 'LAN', 'cidr': '192.168.1.0/24', 'scope': 'lab'})
    await db.commit()
    oid = (await observe(source, record()))['client']
    await rec.apply(oid, await form_for(oid, apply_interface='1', interface_name='eth0',
                                      address_0=b.id, confirm_addresses='1'))
    allocation = await db.scalar(select(inv.Allocation))
    assert allocation.subnet_id == b.id and allocation.subnet_id != a.id


async def test_parent_import_and_reviewed_migration(db, source):
    records = [record('host1', name='PVE', kind='physical', mac='', addresses=[]),
               record('host2', name='Hypervisor B', kind='physical', mac='', addresses=[]),
               record('vm', name='VM', kind='vm', mac='', addresses=[], parent='host1')]
    ids = await observe(source, *records)
    with pytest.raises(disc.DiscoveryError, match='parent host first'):
        await rec.apply(ids['vm'], await form_for(ids['vm'], apply_parent='1'))
    host1 = await rec.apply(ids['host1'], await form_for(ids['host1']))
    host2 = await rec.apply(ids['host2'], await form_for(ids['host2']))
    vmid = await rec.apply(ids['vm'], await form_for(ids['vm'], apply_parent='1'))
    vm = await db.get(inv.Asset, vmid)
    assert vm.parent_id == host1
    records[2]['data']['parent'] = 'host2'
    await observe(source, *records)
    await db.refresh(vm)
    assert vm.parent_id == host1
    await rec.apply(ids['vm'], await form_for(ids['vm'], apply_parent='1'))
    await db.refresh(vm)
    assert vm.parent_id == host2


async def test_attachment_and_missing_fields_preserve_manual_interface_data(db, source):
    ids = await observe(source, record('ap', name='AP', kind='network', mac='00:11:22:33:44:55'),
                        record(attachment='ap'))
    apid = await rec.apply(ids['ap'], await form_for(ids['ap']))
    aid = await rec.apply(ids['client'], await form_for(ids['client'], apply_interface='1',
                         apply_attachment='1', interface_name='wlan0'))
    link = await db.get(DiscoveryLink, ids['client'])
    iface = await db.get(inv.Interface, link.interface_id)
    assert iface.attached_to_id == apid
    await observe(source, record(medium='unknown', port='', attachment=''))
    await rec.apply(ids['client'], await form_for(ids['client'], apply_interface='1'))
    await db.refresh(iface)
    assert iface.attached_to_id == apid and iface.port == 'Home Wi-Fi' and iface.medium == 'wifi'
    assert iface.asset_id == aid


@pytest.mark.parametrize('change', ['source', 'manual'])
async def test_stale_review_rejected_after_refresh_or_manual_edit(db, source, change):
    a = await inv.save_asset(db, {'name': 'Manual', 'kind': 'device'})
    await db.commit()
    oid = (await observe(source, record()))['client']
    form = await form_for(oid, a.id, apply_name='1')
    if change == 'source':
        await observe(source, record(name='New source name'))
    else:
        a.name = 'Concurrent edit'
        await db.commit()
    with pytest.raises(disc.DiscoveryError, match='changed since'):
        await rec.apply(oid, form)
    await db.refresh(a)
    assert a.name != 'Observed device'


@pytest.mark.parametrize('state', ['old', 'missing', 'failed'])
async def test_unavailable_observations_cannot_be_imported(db, source, state):
    oid = (await observe(source, record()))['client']
    if state == 'old':
        o = await db.get(disc.Observation, oid)
        o.last_seen = now() - timedelta(days=2)
        await db.commit()
    elif state == 'missing':
        await observe(source)
    else:
        run_id, _ = await disc.start_run(source.id, 'omada')
        await disc.finish_run(run_id, error='Source offline')
    with pytest.raises(disc.DiscoveryError, match='Refresh this source'):
        await rec.apply(oid, await form_for(oid))
    assert await db.scalar(select(func.count()).select_from(inv.Asset)) == 0


async def test_unlink_preserves_inventory_and_deletion_guards_require_unlink(db, source):
    oid = (await observe(source, record()))['client']
    aid = await rec.apply(oid, await form_for(oid, apply_interface='1', interface_name='eth0'))
    link = await db.get(DiscoveryLink, oid)
    iid = link.interface_id
    with pytest.raises(inv.InventoryError, match='still in use'):
        await inv.delete_record(db, 'interface', iid)
    with pytest.raises(inv.InventoryError, match='still in use'):
        await inv.delete_record(db, 'asset', aid)
    await db.rollback()
    await rec.apply(oid, await form_for(oid, action='unlink'))
    db.expire_all()
    assert await db.get(DiscoveryLink, oid) is None
    assert await db.get(inv.Asset, aid) is not None and await db.get(inv.Interface, iid) is not None


async def test_review_routes_enforce_auth_origin_and_escape_source_text(db, source):
    from keywright_server.web import auth
    from keywright_server.web.app import create_app
    oid = (await observe(source, record(name='<script>unsafe</script>')))['client']
    await auth.set_password(db, 'adminpass123')
    path = f'/ui/inventory/discovery/{oid}/review'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url='http://gk.test') as client:
        assert (await client.get(path)).status_code == 303
        form = await form_for(oid)
        assert (await client.post(path, data=form, headers={'Origin': 'http://gk.test'})).status_code == 303
        await client.post('/ui/login', data={'password': 'adminpass123'}, headers={'Origin': 'http://gk.test'})
        page = await client.get(path)
        assert page.status_code == 200 and '&lt;script&gt;unsafe&lt;/script&gt;' in page.text
        assert (await client.post(path, data=form)).status_code == 403
        assert (await client.post(path, data=form, headers={'Origin': 'https://evil.test'})).status_code == 403
        response = await client.post(path, data=form, headers={'Origin': 'http://gk.test'})
        assert response.status_code == 303
        detail = await client.get(response.headers['location'])
        assert detail.status_code == 200 and 'Discovery sources' in detail.text
        queue = await client.get('/ui/inventory/discovery')
        assert 'Reviewed' in queue.text


async def test_source_connection_edits_invalidate_review_and_inflight_refresh(db, source):
    oid = (await observe(source, record()))['client']
    form = await form_for(oid)
    source.config = {**source.config, 'url': 'https://new-controller.example'}
    await db.commit()
    with pytest.raises(disc.DiscoveryError, match='changed since'):
        await rec.apply(oid, form)
    with pytest.raises(disc.DiscoveryError, match='Refresh this source'):
        await rec.apply(oid, await form_for(oid))
    run_id, _ = await disc.start_run(source.id, 'omada')
    source.config = {**source.config, 'url': 'https://third-controller.example'}
    await db.commit()
    result = await disc.finish_run(run_id, [record(name='wrong controller')])
    assert result.status == 'failed' and 'configuration changed' in result.error
    observation = await db.get(disc.Observation, oid)
    assert observation.data['name'] == 'Observed device'


async def test_interface_ownership_and_cycle_checks_apply_to_reviews(db, source):
    a = await inv.save_asset(db, {'name': 'Existing A', 'kind': 'physical'})
    b = await inv.save_asset(db, {'name': 'Existing B', 'kind': 'physical'})
    iface = await inv.save_interface(db, {'asset_id': b.id, 'name': 'eth0', 'medium': 'wired'})
    await db.commit()
    ids = await observe(source, record('parent', name='Parent'), record(parent='parent'))
    with pytest.raises(disc.DiscoveryError, match='belonging'):
        await form_for(ids['client'], a.id, iface.id)
    await rec.apply(ids['parent'], await form_for(ids['parent'], a.id))
    with pytest.raises(inv.InventoryError, match='cycle'):
        await rec.apply(ids['client'], await form_for(ids['client'], a.id, apply_parent='1'))
    assert await db.get(DiscoveryLink, ids['client']) is None


async def test_existing_allocation_keeps_its_state_and_notes(db, source):
    a = await inv.save_asset(db, {'name': 'Existing', 'kind': 'physical'})
    iface = await inv.save_interface(db, {'asset_id': a.id, 'name': 'eth0', 'medium': 'wired'})
    subnet = await inv.save_subnet(db, {'name': 'LAN', 'cidr': '192.168.1.0/24'})
    allocation = await inv.save_allocation(db, {'subnet_id': subnet.id, 'interface_id': iface.id,
                         'address': '192.168.1.9', 'state': 'reserved', 'notes': 'Keep reservation'})
    await db.commit()
    oid = (await observe(source, record()))['client']
    await rec.apply(oid, await form_for(oid, a.id, iface.id, address_0=subnet.id, confirm_addresses='1'))
    await db.refresh(allocation)
    assert allocation.state == 'reserved' and allocation.notes == 'Keep reservation'


async def test_preview_database_upgrade_preserves_observations_and_requires_refresh(db, source):
    from keywright_server.db import engine, init_db
    oid = (await observe(source, record()))['client']
    async with engine().begin() as conn:
        await conn.execute(text('ALTER TABLE inventory_discovery_runs DROP COLUMN source_fingerprint'))
        await conn.execute(text('DROP TABLE inventory_discovery_links'))
    await init_db()
    await init_db()
    async with session() as fresh_db:
        ctx = await rec.review(fresh_db, oid)
        assert ctx['observation'].data['name'] == 'Observed device' and not ctx['fresh']
    assert await db.scalar(select(func.count()).select_from(DiscoveryLink)) == 0


async def test_existing_resource_can_be_imported_from_empty_inventory(db, source):
    from keywright_server.web import auth
    from keywright_server.web.app import create_app
    oid = (await observe(source, record()))['client']
    resource = Resource(name='Existing SSH device', kind='ssh', config={'host': '192.168.1.9'}, default_mode='locked')
    db.add(resource)
    await db.commit()
    selection = f'resource:{resource.id}'
    await auth.set_password(db, 'adminpass123')
    path = f'/ui/inventory/discovery/{oid}/review'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url='http://gk.test') as client:
        await client.post('/ui/login', data={'password': 'adminpass123'}, headers={'Origin': 'http://gk.test'})
        page = await client.get(path)
        assert f'value="{selection}"' in page.text and 'Existing SSH device (SSH resource)' in page.text
        page = await client.get(path, params={'target_id': selection})
        assert f'name="target_id" value="{selection}"' in page.text
        assert 'Existing SSH device will be linked to the new inventory record' in page.text
        assert await db.scalar(select(func.count()).select_from(inv.Asset)) == 0
        response = await client.post(path, data=await form_for(oid, selection), headers={'Origin': 'http://gk.test'})
        assert response.status_code == 303 and '/ui/inventory/assets/' in response.headers['location']
    asset_id = (await db.get(DiscoveryLink, oid)).asset_id
    assert (await db.get(inv.ResourceLink, resource.id)).asset_id == asset_id
    assert await db.get(inv.ResourceLink, source.id) is None
    await db.refresh(resource)
    assert resource.config == {'host': '192.168.1.9'} and resource.default_mode == 'locked'
    assert await db.scalar(select(func.count()).select_from(Grant)) == 0
    audit = await db.scalar(select(AuditEvent).where(AuditEvent.tool == 'inventory.discovery.review'))
    assert audit.detail['linked_resource_id'] == resource.id


async def test_resource_selection_reuses_inventory_and_preserves_interface_choice(db, source):
    asset = await inv.save_asset(db, {'name': 'Manual name', 'kind': 'physical'})
    iface = await inv.save_interface(db, {'asset_id': asset.id, 'name': 'eth0', 'medium': 'wired'})
    await inv.link_resource(db, {'resource_id': source.id, 'asset_id': asset.id})
    await db.commit()
    oid = (await observe(source, record()))['client']
    selection = f'resource:{source.id}'
    form = await form_for(oid, selection, iface.id)
    assert form['target_id'] == selection and form['interface_id'] == iface.id
    assert await rec.apply(oid, form) == asset.id
    await db.refresh(asset)
    assert asset.name == 'Manual name'
    assert await db.scalar(select(func.count()).select_from(inv.Asset)) == 1
    assert (await db.get(DiscoveryLink, oid)).interface_id == iface.id


async def test_concurrent_resource_link_invalidates_review(db, source):
    asset = await inv.save_asset(db, {'name': 'Existing', 'kind': 'physical'})
    await db.commit()
    oid = (await observe(source, record()))['client']
    form = await form_for(oid, f'resource:{source.id}')
    await inv.link_resource(db, {'resource_id': source.id, 'asset_id': asset.id})
    await db.commit()
    with pytest.raises(disc.DiscoveryError, match='changed since'):
        await rec.apply(oid, form)
    assert await db.get(DiscoveryLink, oid) is None
    assert await db.scalar(select(func.count()).select_from(inv.Asset)) == 1


async def test_resource_link_is_rolled_back_when_review_fails(db, source):
    oid = (await observe(source, record()))['client']
    with pytest.raises(disc.DiscoveryError, match='parent host first'):
        await rec.apply(oid, await form_for(oid, f'resource:{source.id}', apply_parent='1'))
    # Fail after the resource link has been staged, too.
    with pytest.raises(disc.DiscoveryError, match='Choose an interface'):
        await rec.apply(oid, await form_for(oid, f'resource:{source.id}', apply_attachment='1'))
    for model in (inv.Asset, inv.ResourceLink, DiscoveryLink):
        assert await db.scalar(select(func.count()).select_from(model)) == 0


async def test_import_smart_type_then_refresh_preserves_manual_classification(db, source):
    oid = (await observe(source, record(name='Tapo-Vent')))['client']
    aid = await rec.apply(oid, await form_for(oid, kind='smart_vent'))
    imported = await db.get(inv.Asset, aid)
    assert imported.kind == 'smart_vent'
    # The controller still reports a generic device. Reviewing another field must keep our choice.
    await observe(source, record(name='Tapo-Vent', site='Bedroom'))
    await rec.apply(oid, await form_for(oid, apply_site='1'))
    await db.refresh(imported)
    assert imported.kind == 'smart_vent' and imported.site == 'Bedroom'
