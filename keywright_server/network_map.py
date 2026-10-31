"""Network graph from source observations, with explicit freshness and provenance."""
from collections import Counter
from datetime import timedelta

from sqlalchemy import select

from . import discovery
from .models import (
    DiscoveryLink,
    DiscoveryObservation,
    DiscoveryRun,
    InventoryAsset,
    InventoryInterface,
    Resource,
    now,
)

REFRESH_SECONDS = 60
FRESH_SECONDS = 180


def iso(value):
    return value.isoformat() if value else None


async def snapshot(db, source=''):
    resources = list((await db.scalars(select(Resource).order_by(Resource.name))).all())
    resources = [r for r in resources if r.kind == 'mcp' and r.config.get('adapter') == 'omada']
    selected = next((r for r in resources if r.id == source), None) if source else next(iter(resources), None)
    result = {'sources': [{'id': r.id, 'name': r.name} for r in resources],
              'source': selected.id if selected else '', 'nodes': [], 'edges': [], 'counts': {},
              'refresh_seconds': REFRESH_SECONDS, 'fresh_seconds': FRESH_SECONDS,
              'generated_at': iso(now()), 'last_success': None, 'latest_status': '', 'error': '',
              'fresh': False, 'configuration_changed': False}
    if not selected:
        return result
    recent_runs = select(DiscoveryRun).where(
        DiscoveryRun.resource_id == selected.id, DiscoveryRun.provider == 'omada').order_by(
        DiscoveryRun.started_at.desc(), DiscoveryRun.id.desc()).limit(1)
    latest = await db.scalar(recent_runs)
    success = await db.scalar(recent_runs.where(DiscoveryRun.status == 'succeeded'))
    at = now()
    changed = bool(success and success.source_fingerprint != discovery.source_fingerprint(selected.config))
    fresh = bool(success and success.finished_at and success.finished_at >= at - timedelta(seconds=FRESH_SECONDS)
                 and not changed and latest.status != 'failed')
    result.update(last_success=iso(success.finished_at) if success else None,
                  latest_status=latest.status if latest else '', error=latest.error if latest else '',
                  fresh=fresh, configuration_changed=changed)
    observations = list((await db.scalars(select(DiscoveryObservation).where(
        DiscoveryObservation.resource_id == selected.id, DiscoveryObservation.provider == 'omada'))).all())
    links = {r.observation_id: r for r in (await db.scalars(select(DiscoveryLink))).all()}
    by_identity = {r.external_id: r for r in observations}
    by_asset = {}
    for r in observations:
        if r.id in links:
            by_asset.setdefault(links[r.id].asset_id, []).append(r)
    interfaces = list((await db.scalars(select(InventoryInterface))).all())
    assets = {r.id: r for r in (await db.scalars(select(InventoryAsset))).all()}
    manual_nodes = {}
    for row in sorted(observations, key=lambda r: (r.data.get('name', '').casefold(), r.id)):
        data = row.data
        missing = bool(success and row.run_id != success.id)
        if not fresh:
            state = 'stale'
        elif missing:
            state = 'old' if row.last_seen < at - timedelta(hours=24) else 'missing'
        else:
            state = {'Active': 'online', 'Inactive': 'inactive'}.get(data.get('status'), 'unknown')
        link = links.get(row.id)
        site_id = row.external_id.split('/')[0]
        target = by_identity.get(data.get('attachment', ''))
        node = {'id': row.id, 'name': data.get('name') or data.get('mac') or 'Unnamed device',
                'site': data.get('site', ''), 'site_id': site_id,
                'mac': data.get('mac', ''), 'addresses': data.get('addresses', []),
                'medium': data.get('medium', 'unknown'), 'port': data.get('port', ''),
                'role': data.get('device_type') or ('network' if data.get('kind') == 'network' else 'client'),
                'uplink_note': data.get('uplink_note', ''),
                'model': data.get('model', ''), 'hub': data.get('kind') == 'network',
                'state': state, 'source_status': data.get('status', 'Unknown'),
                'missing': missing, 'last_observed': iso(row.last_seen), 'first_observed': iso(row.first_seen),
                'unreviewed': link is None, 'attachment': target.id if target and target.id != row.id else '',
                'attachment_label': target.data.get('name', '') if target else data.get('attachment', ''),
                'attachment_source': 'Omada' if data.get('attachment') else '',
                'review_url': f'/ui/inventory/discovery/{row.id}/review',
                'asset_url': f'/ui/inventory/assets/{link.asset_id}' if link else ''}
        result['nodes'].append(node)
        if target and target.id != row.id:
            result['edges'].append({'source': target.id, 'target': row.id, 'medium': node['medium'],
                                    'label': node['port'], 'provenance': 'Omada', 'historical': missing})
        elif link and not data.get('attachment'):
            # Only reviewed inventory links can supply a manual uplink; MAC/IP guesses are not topology.
            for iface in interfaces:
                if (iface.asset_id != link.asset_id or not iface.attached_to_id
                        or data.get('device_type') == 'ap' and data.get('medium') in ('wifi', 'wired')
                        and iface.medium != data['medium']):
                    continue
                targets = [r for r in by_asset.get(iface.attached_to_id, [])
                           if r.external_id.split('/')[0] == site_id and r.id != row.id]
                if not targets and iface.attached_to_id in assets and iface.attached_to_id not in by_asset:
                    # Explicit inventory connections can include an unmanaged WAN, modem, or switch.
                    parent = assets[iface.attached_to_id]
                    parent_id = f'inventory:{site_id}:{parent.id}'
                    manual_nodes[parent_id] = {
                        'id': parent_id, 'name': parent.name, 'site': data.get('site', ''), 'site_id': site_id,
                        'mac': '', 'addresses': [], 'medium': 'unknown', 'port': '',
                        'role': 'external' if parent.kind == 'service' else 'network', 'model': '',
                        'hub': True, 'virtual': True, 'state': 'unknown', 'source_status': 'Not monitored',
                        'missing': False, 'last_observed': None, 'first_observed': None, 'unreviewed': False,
                        'attachment': '', 'attachment_label': '', 'attachment_source': '', 'uplink_note': '',
                        'review_url': '', 'asset_url': f'/ui/inventory/assets/{parent.id}'}
                    result['edges'].append({'source': parent_id, 'target': row.id, 'medium': iface.medium,
                                            'label': iface.port, 'provenance': 'Inventory', 'historical': False})
                    if not node['attachment']:
                        node['attachment'], node['attachment_label'] = parent_id, parent.name
                        node['attachment_source'] = 'Inventory'
                        node['medium'], node['port'] = iface.medium, iface.port
                if len(targets) == 1:
                    parent = targets[0]
                    result['edges'].append({'source': parent.id, 'target': row.id, 'medium': iface.medium,
                                            'label': iface.port, 'provenance': 'Inventory', 'historical': False})
                    if not node['attachment']:
                        node['attachment'], node['attachment_label'] = parent.id, parent.data.get('name', '')
                        node['attachment_source'] = 'Inventory'
                        node['medium'], node['port'] = iface.medium, iface.port
    result['counts'] = dict(Counter(n['state'] for n in result['nodes']))
    result['nodes'].extend(manual_nodes.values())
    result['counts']['unreviewed'] = sum(n['unreviewed'] for n in result['nodes'])
    return result
