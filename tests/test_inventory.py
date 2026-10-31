"""Inventory must remain an accurate manual record without altering authorization."""
import ipaddress

import httpx
import pytest
from sqlalchemy import func, select, text

from keywright_server import inventory as inv
from keywright_server.models import Agent, AuditEvent, Grant, Policy, Resource


async def asset(db, name="host", **kwargs):
    return await inv.save_asset(db, {"name": name, "kind": "physical", **kwargs})


async def subnet(db, **kwargs):
    return await inv.save_subnet(db, {"name": "LAN", "cidr": "192.168.1.0/24", **kwargs})


async def test_host_cycles_and_missing_parents_are_rejected(db):
    parent = await asset(db)
    child = await asset(db, "vm", kind="vm", parent_id=parent.id)
    for parent_id in (parent.id, child.id, "missing"):
        with pytest.raises(inv.InventoryError):
            await asset(db, id=parent.id, parent_id=parent_id)
    assert parent.parent_id is None
    assert child.parent_id == parent.id
    with pytest.raises(inv.InventoryError, match="already exists"):
        await asset(db)


async def test_interface_validation_and_resource_links(db):
    a, b = await asset(db), await asset(db, "other")
    i = await inv.save_interface(db, {"asset_id": a.id, "name": "eth0", "medium": "wired",
                                     "mac": "AA-BB-CC-DD-EE-FF", "attached_to_id": b.id, "port": "3"})
    assert i.mac == "aa:bb:cc:dd:ee:ff"
    for changes in ({"name": "eth0"}, {"name": "eth1", "attached_to_id": a.id},
                    {"name": "eth1", "medium": "bogus"}, {"name": "eth1", "mac": "invalid"}):
        with pytest.raises(inv.InventoryError):
            await inv.save_interface(db, {"asset_id": a.id, "medium": "wired", **changes})
    with pytest.raises(inv.InventoryError, match="different"):
        await inv.save_interface(db, {"id": i.id, "asset_id": b.id, "name": "eth0", "medium": "wired"})
    resource = Resource(kind="ssh", name="host", config={"host": "host.test"}, default_mode="locked")
    db.add(resource)
    await db.flush()
    await inv.link_resource(db, {"resource_id": resource.id, "asset_id": a.id})
    with pytest.raises(inv.InventoryError, match="already linked"):
        await inv.link_resource(db, {"resource_id": resource.id, "asset_id": b.id})
    assert resource.default_mode == "locked"
    assert await db.scalar(select(func.count()).select_from(Grant)) == 0
    assert await db.scalar(select(func.count()).select_from(Policy)) == 0


async def test_subnets_validate_overlap_gateway_pool_and_vlan(db):
    first = await subnet(db, gateway="192.168.1.1", dhcp_start="192.168.1.100", dhcp_end="192.168.1.200")
    for data in ({"cidr": "192.168.1.128/25"}, {"cidr": "192.168.1.1/24"},
                 {"cidr": "not-a-subnet"}, {"cidr": "192.168.2.0/24", "gateway": "192.168.3.1"},
                 {"cidr": "192.168.2.0/24", "vlan": "0"},
                 {"cidr": "192.168.2.0/24", "vlan": "4095"},
                 {"cidr": "192.168.2.0/24", "dhcp_start": "192.168.2.100"},
                 {"cidr": "192.168.2.0/24", "dhcp_start": "192.168.2.200", "dhcp_end": "192.168.2.100"},
                 {"cidr": "192.168.2.0/24", "dhcp_start": "192.168.2.10", "dhcp_end": "192.168.2.20",
                  "gateway": "192.168.2.15"}):
        with pytest.raises(inv.InventoryError):
            await subnet(db, **data)
    isolated = await subnet(db, scope="isolated")
    assert isolated.cidr == first.cidr
    assert (await subnet(db, cidr="2001:db8::/64")).cidr == "2001:db8::/64"


async def test_allocations_canonical_unique_usable_and_owned(db):
    s = await subnet(db, cidr="2001:db8::/64", gateway="2001:db8::1")
    row = await inv.save_allocation(db, {"subnet_id": s.id, "address": "2001:db8:0:0:0:0:0:10",
                                         "state": "reserved", "label": "future host"})
    assert row.address == "2001:db8::10"
    for ip in ("2001:db8::10", "2001:db8::", "2001:db8::1", "2001:db9::10", "192.168.1.10",
               "fe80::1%eth0", "invalid"):
        with pytest.raises(inv.InventoryError):
            await inv.save_allocation(db, {"subnet_id": s.id, "address": ip, "state": "reserved", "label": "test"})
    for changes in ({"state": "assigned"}, {"state": "unknown"}, {"label": ""}, {"interface_id": "missing"}):
        with pytest.raises(inv.InventoryError):
            await inv.save_allocation(db, {"subnet_id": s.id, "address": "2001:db8::20",
                                           "state": "reserved", "label": "test", **changes})
    s4 = await subnet(db)
    for ip in ("192.168.1.0", "192.168.1.255"):
        with pytest.raises(inv.InventoryError):
            await inv.save_allocation(db, {"subnet_id": s4.id, "address": ip, "state": "reserved", "label": "test"})


async def test_subnet_edit_keeps_allocations_valid(db):
    s = await subnet(db)
    await inv.save_allocation(db, {"subnet_id": s.id, "address": "192.168.1.200", "state": "planned", "label": "new"})
    for data in ({"cidr": "192.168.1.0/25"}, {"gateway": "192.168.1.200"}):
        with pytest.raises(inv.InventoryError):
            await subnet(db, id=s.id, **data)
    assert s.cidr == "192.168.1.0/24"


async def test_deletion_never_silently_releases_addresses_or_links(db):
    a = await asset(db)
    i = await inv.save_interface(db, {"asset_id": a.id, "name": "eth0", "medium": "wired"})
    s = await subnet(db)
    allocation = await inv.save_allocation(db, {"subnet_id": s.id, "interface_id": i.id,
                                                "address": "192.168.1.10", "state": "assigned"})
    for kind, row_id in (("asset", a.id), ("interface", i.id), ("subnet", s.id)):
        with pytest.raises(inv.InventoryError, match="still in use"):
            await inv.delete_record(db, kind, row_id)
    assert await db.get(inv.Allocation, allocation.id) is allocation
    await inv.delete_record(db, "allocation", allocation.id)
    await db.flush()
    await inv.delete_record(db, "interface", i.id)
    await db.flush()
    await inv.delete_record(db, "asset", a.id)
    await inv.delete_record(db, "subnet", s.id)
    await db.commit()


@pytest.mark.parametrize('cidr,count', [('192.0.2.0/31', 2), ('192.0.2.8/32', 1), ('192.0.2.0/30', 2),
                                       ('2001:db8::/127', 2), ('2001:db8::/128', 1),
                                       ('2001:db8::/64', 2**64-1)])
def test_address_counts_do_not_expand_networks(cidr, count):
    s = inv.Subnet(id='s', cidr=cidr, gateway='', dhcp_start='', dhcp_end='')
    result = inv.subnet_summary(s, [])
    assert result['capacity'] == count
    assert result['unrecorded'] == count
    assert len(result['gaps']) == 1
    assert inv.bounds(ipaddress.ip_network(cidr))[1] - inv.bounds(ipaddress.ip_network(cidr))[0] + 1 == count


def test_counts_merge_pool_gateway_and_allocations():
    s = inv.Subnet(id='s', cidr='192.168.1.0/24', gateway='192.168.1.1',
                   dhcp_start='192.168.1.100', dhcp_end='192.168.1.200')
    allocations = [inv.Allocation(subnet_id='s', address=ip) for ip in ['192.168.1.10', '192.168.1.150']]
    result = inv.subnet_summary(s, allocations)
    assert result['recorded'] == 2
    assert result['pool_size'] == 101
    assert result['unrecorded'] == 151
    assert result['gaps'] == [('192.168.1.2', '192.168.1.9'), ('192.168.1.11', '192.168.1.99'),
                              ('192.168.1.201', '192.168.1.254')]


async def test_numeric_sort_and_hosting_tree(db):
    parent = await asset(db, 'pve')
    s = await subnet(db)
    for name, ip in [('a', '192.168.1.100'), ('z', '192.168.1.9')]:
        a = await asset(db, name, kind='vm', parent_id=parent.id)
        i = await inv.save_interface(db, {'asset_id': a.id, 'name': 'eth0', 'medium': 'virtual'})
        await inv.save_allocation(db, {'subnet_id': s.id, 'interface_id': i.id, 'address': ip, 'state': 'assigned'})
    data = await inv.snapshot(db)
    rows = inv.asset_rows(data, sort='ip')
    assert [r['asset'].name for r in rows] == ['z', 'a', 'pve']
    assert len(inv.asset_rows(data, query='192.168.1.100')) == 1
    tree = inv.hosting_tree(data)
    assert [(r['asset'].name, r['depth']) for r in tree] == [('pve', 0), ('a', 1), ('z', 1)]
    assert tree[1]['ancestors'] == [parent.id]


async def test_resource_sorting_uses_inventory_addresses_then_ssh_host(db):
    a = await asset(db, 'VM')
    i = await inv.save_interface(db, {'asset_id': a.id, 'name': 'eth0', 'medium': 'virtual'})
    s = await subnet(db)
    await inv.save_allocation(db, {'subnet_id': s.id, 'interface_id': i.id,
                                    'address': '192.168.1.9', 'state': 'assigned'})
    linked = Resource(name='linked', kind='ssh', config={'host': 'vm.internal'}, default_mode='locked')
    literal = Resource(name='literal', kind='ssh', config={'host': '192.168.1.100'})
    unknown = Resource(name='unknown', kind='mcp', config={'url': 'https://service.internal'})
    db.add_all([linked, literal, unknown])
    await db.flush()
    await inv.link_resource(db, {'asset_id': a.id, 'resource_id': linked.id})
    data = await inv.snapshot(db)
    result = inv.resource_inventory(data, sort='ip')
    assert [r.name for r in result['rows']] == ['linked', 'literal', 'unknown']
    assert result['resource_assets'][linked.id] is a
    assert inv.resource_inventory(data, group='host')['resource_groups'][linked.id] == 'VM'
    groups = inv.resource_inventory(data, group='network')['resource_groups']
    assert groups[linked.id] == 'LAN' and groups[unknown.id] == 'No network recorded'
    assert linked.config == {'host': 'vm.internal'} and linked.default_mode == 'locked'


async def test_authenticated_ui_workflow_audit_and_csrf(live_server, db):
    async with httpx.AsyncClient(base_url=live_server, headers={'Origin': live_server}, follow_redirects=True) as http:
        page = await http.get('/ui/inventory')
        assert page.url.path == '/ui/login'
        await http.post('/ui/login', data={'password': 'adminpass123'})
        denied = await http.post('/ui/inventory/assets', data={'name': 'cross-origin', 'kind': 'physical'},
                                 headers={'Origin': 'https://evil.invalid'})
        assert denied.status_code == 403
        page = await http.post('/ui/inventory/assets', data={'name': 'pve', 'kind': 'physical', 'site': 'Rack'})
        assert 'pve' in page.text and page.url.path.startswith('/ui/inventory/assets/asset_')
        asset_id = page.url.path.rsplit('/', 1)[1]
        page = await http.post('/ui/inventory/interfaces', data={'asset_id': asset_id, 'name': 'eth0', 'medium': 'wired'})
        assert 'eth0' in page.text
        iface = await db.scalar(select(inv.Interface))
        page = await http.post('/ui/inventory/networks', data={'name': 'LAN', 'cidr': '192.168.1.0/24', 'vlan': '10'})
        subnet_id = page.url.path.rsplit('/', 1)[1]
        page = await http.post('/ui/inventory/allocations', data={'subnet_id': subnet_id, 'interface_id': iface.id,
                                                                'address': '192.168.1.9', 'state': 'assigned'})
        assert '192.168.1.9' in page.text and 'pve' in page.text
        for path in ['/ui/inventory', '/ui/inventory?sort=ip&group=network', '/ui/inventory/topology',
                     '/ui/inventory/networks', '/ui/inventory/assets/new', '/ui/inventory/networks/new',
                     '/ui/resources?sort=ip&group=host']:
            assert (await http.get(path)).status_code == 200, path
        page = await http.post('/ui/inventory/allocations', data={'subnet_id': subnet_id, 'label': 'preserve this',
                                                                'address': '192.168.1.9', 'state': 'reserved'})
        assert 'already has an allocation' in page.text and 'value="preserve this"' in page.text
        page = await http.post('/ui/inventory/assets', data={'id': asset_id, 'name': '<script>unsafe</script>',
                                                            'kind': 'physical', 'notes': 'a note'})
        assert '&lt;script&gt;unsafe&lt;/script&gt;' in page.text
        assert '<script>unsafe</script>' not in page.text
    assert await db.scalar(select(func.count()).select_from(AuditEvent).where(
        AuditEvent.tool.like('inventory.%'))) == 5
    assert await db.scalar(select(func.count()).select_from(Grant)) == 0
    assert await db.scalar(select(func.count()).select_from(Policy)) == 0
    assert await db.scalar(select(func.count()).select_from(Agent)) == 1


async def test_inventory_tables_upgrade_existing_database_without_altering_resources(db):
    from keywright_server.db import engine, init_db
    r = Resource(name='existing', kind='ssh', default_mode='locked', config={'host': '192.0.2.1'})
    db.add(r)
    await db.commit()
    async with engine().begin() as conn:
        for name in ['inventory_resource_links', 'inventory_allocations', 'inventory_interfaces',
                     'inventory_subnets', 'inventory_assets']:
            await conn.execute(text(f'DROP TABLE {name}'))
    await init_db()
    await init_db()
    await db.refresh(r)
    assert r.config == {'host': '192.0.2.1'} and r.default_mode == 'locked'
    assert await db.scalar(select(func.count()).select_from(inv.Asset)) == 0


async def test_smart_device_types_save_search_and_group_without_changing_legacy_ids(db):
    from keywright_server.inventory_mcp import Asset as MCPAsset

    assert {'physical', 'vm', 'container', 'network', 'device', 'service'} <= inv.KINDS.keys()
    assert set(MCPAsset.model_json_schema()['properties']['kind']['enum']) == set(inv.KINDS)
    for kind in ('smart_vent', 'smart_plug', 'presence_sensor', 'pet_feeder', 'ev_charger', 'light_switch'):
        row = await asset(db, name='Fixture ' + kind, kind=kind)
        assert MCPAsset(name=row.name, kind=kind).kind == kind
    await db.commit()
    data = await inv.snapshot(db)
    rows = inv.asset_rows(data, query='HVAC damper', group='kind')
    assert len(rows) == 1 and rows[0]['asset'].kind == 'smart_vent'
    assert rows[0]['group'] == 'Smart vent / HVAC damper'
    with pytest.raises(inv.InventoryError, match='valid kind'):
        await asset(db, name='Invalid', kind='invented-type')
