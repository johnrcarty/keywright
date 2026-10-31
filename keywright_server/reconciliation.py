"""Explicit, transactional review of discovered facts into manual inventory."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
from datetime import datetime, timedelta

from sqlalchemy import select

from . import audit
from . import discovery as disc
from . import inventory as inv
from .db import session
from .models import DiscoveryLink, now


def record_values(row):
    return {c.name: value.isoformat() if isinstance(value, datetime) else value
            for c in row.__table__.columns for value in [getattr(row, c.name)]}


def form_values(row):
    return {key: value if value is not None else '' for key, value in record_values(row).items()}


async def review(db, observation_id, target_id='', interface_id=''):
    observation = await inv.require(db, disc.Observation, observation_id)
    data = await inv.snapshot(db)
    links = list((await db.scalars(select(DiscoveryLink))).all())
    link_map = {r.observation_id: r for r in links}
    link = link_map.get(observation.id)
    selected_resource = None
    if target_id.startswith('resource:'):
        selected_resource = await inv.require(db, inv.Resource, target_id.removeprefix('resource:'))
        resource_link = next((r for r in data['links'] if r.resource_id == selected_resource.id), None)
        target_id = resource_link.asset_id if resource_link else ''
    if link:
        if target_id and target_id != link.asset_id:
            raise disc.DiscoveryError('Unlink this observation before choosing a different inventory record.')
        target_id = link.asset_id
    target = await inv.require(db, inv.Asset, target_id) if target_id else None
    target_selection = f'resource:{selected_resource.id}' if selected_resource else target_id
    selected = interface_id or (link.interface_id if link else '') or 'new'
    interface = await inv.require(db, inv.Interface, selected) if selected != 'new' else None
    if interface and (not target or interface.asset_id != target.id):
        raise disc.DiscoveryError('Choose an interface belonging to the selected inventory record.')
    latest = await db.scalar(select(disc.Run).where(disc.Run.resource_id == observation.resource_id,
                            disc.Run.provider == observation.provider).order_by(
                            disc.Run.started_at.desc(), disc.Run.id.desc()).limit(1))
    source_fingerprint = disc.source_fingerprint(data['resource_map'][observation.resource_id].config)
    fresh = bool(latest and latest.status == 'succeeded' and observation.run_id == latest.id
                 and latest.source_fingerprint == source_fingerprint
                 and observation.last_seen >= now() - timedelta(hours=24))
    related = {}
    for field in ('parent', 'attachment'):
        external_id = observation.data[field]
        source = await db.scalar(select(disc.Observation).where(
            disc.Observation.resource_id == observation.resource_id,
            disc.Observation.provider == observation.provider, disc.Observation.external_id == external_id)) if external_id else None
        mapping = link_map.get(source.id) if source else None
        related[field] = {'observation': source, 'asset': data['asset_map'].get(mapping.asset_id) if mapping else None}
    address_rows = []
    for index, address in enumerate(observation.data['addresses']):
        choices = []
        for subnet in data['subnets']:
            try:
                inv.host_address(address, ipaddress.ip_network(subnet.cidr))
            except inv.InventoryError:
                continue
            existing = next((a for a in data['allocations'] if a.subnet_id == subnet.id and a.address == address), None)
            pool = bool(subnet.dhcp_start and int(inv.address(subnet.dhcp_start)) <= int(inv.address(address))
                        <= int(inv.address(subnet.dhcp_end)))
            conflict = address == subnet.gateway or bool(existing and (not interface or existing.interface_id != interface.id))
            choices.append({'subnet': subnet, 'existing': existing, 'pool': pool, 'conflict': conflict})
        address_rows.append({'index': index, 'address': address, 'choices': choices})
    # Compare exactly the reviewed observation, target and dependencies under the write lock.
    # Include inventory state so concurrent manual edits, allocations or relationship changes reject stale forms.
    state = {'observation': record_values(observation), 'latest': record_values(latest) if latest else None,
             'source_fingerprint': source_fingerprint,
             'target_id': target_id, 'interface_id': selected,
             'selected_resource': {'id': selected_resource.id, 'name': selected_resource.name,
                                   'kind': selected_resource.kind} if selected_resource else None,
             'resource_links': sorted((record_values(r) for r in data['links']), key=lambda r: r['resource_id']),
             'links': sorted((record_values(r) for r in links), key=lambda r: r['observation_id'])}
    for key in ('assets', 'interfaces', 'subnets', 'allocations'):
        state[key] = sorted((record_values(r) for r in data[key]), key=lambda r: r['id'])
    token = hashlib.sha256(json.dumps(state, sort_keys=True, default=str).encode()).hexdigest()
    return {**data, 'observation': observation, 'discovery_link': link, 'target': target,
            'target_selection': target_selection, 'selected_resource': selected_resource,
            'selected_interface': interface, 'selected_interface_id': selected, 'fresh': fresh,
            'related': related, 'address_rows': address_rows, 'review_token': token,
            'candidates': disc.matches(observation, data), 'kinds': inv.KINDS, 'media': inv.MEDIA,
            'providers': disc.PROVIDERS}


async def apply(observation_id, form):
    async with session() as db:
        await inv.lock_writes(db)
        ctx = await review(db, observation_id, inv.value(form, 'target_id'), inv.value(form, 'interface_id'))
        if not hmac.compare_digest(inv.value(form, 'review_token').encode(), ctx['review_token'].encode()):
            raise disc.DiscoveryError('The source or inventory changed since this review. Review the latest values again.')
        observation, link = ctx['observation'], ctx['discovery_link']
        action = inv.choice(form, 'action', ('save', 'unlink'))
        if action == 'unlink':
            if not link:
                raise disc.DiscoveryError('This observation is not linked.')
            target_id = link.asset_id
            await db.delete(link)
            await audit.record(db, tool='inventory.discovery.unlink', decision='unlinked',
                               detail={'observation_id': observation.id, 'asset_id': target_id})
            return target_id
        if not ctx['fresh']:
            raise disc.DiscoveryError('Refresh this source successfully before importing or reviewing this observation.')
        observed = observation.data
        target, iface = ctx['target'], ctx['selected_interface']
        before = {'asset': record_values(target) if target else None,
                  'interface': record_values(iface) if iface else None}
        asset_data = form_values(target) if target else {
            'name': inv.value(form, 'name', required=True), 'kind': inv.choice(form, 'kind', inv.KINDS),
            'site': inv.value(form, 'site'), 'tags': '', 'notes': '', 'parent_id': ''}
        asset_changes = target is None
        for field in ('name', 'kind', 'site'):
            if target and form.get('apply_' + field) == '1':
                asset_data[field] = observed[field]
                asset_changes = True
        if form.get('apply_parent') == '1':
            parent = ctx['related']['parent']['asset']
            if not parent:
                raise disc.DiscoveryError('Import or link the observed parent host first.')
            asset_data['parent_id'] = parent.id
            asset_changes = True
        if asset_changes:
            target = await inv.save_asset(db, asset_data)
        if ctx['selected_resource']:
            await inv.link_resource(db, {'resource_id': ctx['selected_resource'].id, 'asset_id': target.id})
        if form.get('apply_interface') == '1':
            if not observed['mac']:
                raise disc.DiscoveryError('This observation does not report a network interface.')
            interface_data = form_values(iface) if iface else {
                'asset_id': target.id, 'name': inv.value(form, 'interface_name', required=True),
                'medium': 'unknown', 'mac': '', 'attached_to_id': '', 'port': ''}
            # Missing values are not instructions to erase manual inventory.
            interface_data['mac'] = observed['mac']
            if observed['medium'] != 'unknown':
                interface_data['medium'] = observed['medium']
            if observed['port']:
                interface_data['port'] = observed['port']
            iface = await inv.save_interface(db, interface_data)
        if form.get('apply_attachment') == '1':
            attachment = ctx['related']['attachment']['asset']
            if not iface or not attachment:
                raise disc.DiscoveryError('Choose an interface and import or link the connected device first.')
            iface = await inv.save_interface(db, {**form_values(iface), 'attached_to_id': attachment.id})
        allocations = []
        for address_row in ctx['address_rows']:
            subnet_id = inv.value(form, f"address_{address_row['index']}")
            if not subnet_id:
                continue
            if not iface:
                raise disc.DiscoveryError('Choose or create an interface before recording an address.')
            choice = next((c for c in address_row['choices'] if c['subnet'].id == subnet_id), None)
            if not choice:
                raise disc.DiscoveryError('Choose a recorded subnet containing this observed address.')
            existing = choice['existing']
            if address_row['address'] == choice['subnet'].gateway or (existing and existing.interface_id != iface.id):
                raise disc.DiscoveryError('This address is already allocated or recorded as a gateway. Resolve it in IP allocations.')
            if existing:
                continue  # Do not rewrite an existing allocation's state, owner, or notes.
            if form.get('confirm_addresses') != '1':
                raise disc.DiscoveryError('Confirm that the selected addresses are assigned to this interface before recording them.')
            allocations.append(await inv.save_allocation(db, {'subnet_id': subnet_id, 'interface_id': iface.id,
                               'address': address_row['address'], 'state': 'assigned'}))
        if link is None:
            link = DiscoveryLink(observation_id=observation.id, asset_id=target.id)
            db.add(link)
        link.interface_id = iface.id if iface else None
        link.reviewed_data, link.reviewed_at = dict(observed), now()
        await db.flush()
        await audit.record(db, tool='inventory.discovery.review', decision='saved', detail={
            'observation_id': observation.id, 'resource_id': observation.resource_id, 'run_id': observation.run_id,
            'asset_id': target.id, 'before': before,
            'linked_resource_id': ctx['selected_resource'].id if ctx['selected_resource'] else None,
            'after': {'asset': record_values(target), 'interface': record_values(iface) if iface else None},
            'allocations_added': [a.address for a in allocations],
        })
        return target.id
