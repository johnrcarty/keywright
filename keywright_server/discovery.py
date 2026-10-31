"""Read-only source observations; explicit inventory imports live in reconciliation."""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
from datetime import timedelta

from sqlalchemy import select

from . import audit, omada, ssh
from . import inventory as inv
from .db import session
from .models import DiscoveryObservation as Observation
from .models import DiscoveryRun as Run
from .models import Resource, now

PROVIDERS = {'omada': 'Omada', 'proxmox': 'Proxmox'}
PVE_COMMAND = 'pvesh get /cluster/resources --output-format json'
MAX_ROWS = 10000
MAX_SECONDS = 180


class DiscoveryError(ValueError):
    pass


def source_fingerprint(config):
    """Detect source edits without retaining a second copy of its credentials."""
    keys = ('host', 'port', 'user', 'key_path', 'host_key', 'adapter', 'url', 'omada_id',
            'client_id', 'client_secret', 'verify_tls', 'ca_bundle')
    return hashlib.sha256(json.dumps({key: config[key] for key in keys if key in config},
                                    sort_keys=True).encode()).hexdigest()


def label(value, maximum=160):
    return ''.join(c for c in str(value or '') if ord(c) >= 32)[:maximum].strip()


def mac(value):
    value = label(value).lower().replace('-', ':')
    return value if re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value) else ''


def addresses(row):
    values = [row.get('ip'), *(row.get('ipv6List') or [])]
    result = set()
    for raw in values:
        try:
            ip = ipaddress.ip_address(raw)
            if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local:
                continue
            result.add(str(ip))
        except (ValueError, TypeError):
            continue
    return sorted(result, key=inv.address_key)


async def pages(config, tool, **args):
    rows, total = [], None
    for page in range(1, 102):
        result = await omada.request(config, tool, {**args, 'page': page, 'page_size': 100})
        if (not isinstance(result, dict) or not isinstance(result.get('data'), list)
                or type(result.get('totalRows')) is not int or not 0 <= result['totalRows'] <= MAX_ROWS
                or type(result.get('currentPage')) is not int or result['currentPage'] != page
                or any(not isinstance(r, dict) for r in result['data'])):
            raise DiscoveryError('The controller returned an invalid inventory page. No observations were replaced.')
        if total is not None and result['totalRows'] != total:
            raise DiscoveryError('The controller inventory changed during pagination. Refresh again.')
        total = result['totalRows']
        batch = result['data']
        rows.extend(batch)
        if len(rows) > total or len(rows) > MAX_ROWS:
            raise DiscoveryError('The controller returned inconsistent inventory counts.')
        if len(rows) == total:
            return rows
        if not batch:
            break
    raise DiscoveryError('The controller returned an incomplete inventory. Previous observations were retained.')


def omada_row(row, site, category):
    identity = mac(row.get('mac'))
    if not identity:
        raise DiscoveryError('An Omada record has no valid MAC identity. Previous observations were retained.')
    wireless = row.get('wireless')
    medium = ('wifi' if wireless else 'wired') if type(wireless) is bool else 'unknown'
    attachment = mac(row.get('apMac') if wireless else row.get('switchMac'))
    # Preserve explicit source state; numeric device status is deliberately not interpreted as a ping.
    status = ('Active' if row['active'] else 'Inactive') if type(row.get('active')) is bool else 'Unknown'
    return {'external_id': f"{site['siteId']}/{category}/{identity}", 'data': {
        'name': label(row.get('name') or row.get('hostName') or identity),
        'kind': 'network' if category == 'device' else 'device', 'site': label(site.get('name')),
        'mac': identity, 'addresses': addresses(row), 'medium': medium,
        'attachment': f"{site['siteId']}/device/{attachment}" if attachment else '',
        'port': label(row.get('ssid') if wireless else row.get('standardPort') or row.get('port')),
        'parent': '', 'status': status,
        'device_type': label(row.get('type')) if category == 'device' else 'client',
        'model': label(row.get('model')) if category == 'device' else '',
    }}


def ap_uplink(data, detail, site_id):
    """The AP detail endpoint distinguishes a wired AP from a wireless mesh uplink."""
    if not isinstance(detail, dict) or type(detail.get('wirelessLinked')) is not bool:
        data['uplink_note'] = 'The controller did not report this AP’s uplink type.'
        return
    wireless = detail['wirelessLinked']
    data['medium'] = 'wifi' if wireless else 'wired'
    data['uplink_note'] = ''
    if wireless:
        data['attachment'], data['port'] = '', ''
        uplink = detail.get('wirelessUplink')
        parent = mac(uplink.get('uplinkMac')) if isinstance(uplink, dict) else ''
        if parent and parent != data['mac']:
            data['attachment'] = f'{site_id}/device/{parent}'
            data['port'] = 'Mesh'
        else:
            data['uplink_note'] = 'Mesh uplink reported, but its parent AP was not identified.'
    else:
        data['uplink_note'] = 'Wired uplink; its upstream device is not reported by this endpoint.'


async def collect_omada(config):
    records = []
    for site in await pages(config, 'omada_list_sites'):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', str(site.get('siteId', ''))):
            raise DiscoveryError('The controller returned an invalid site identity.')
        for category, tool in [('device', 'omada_list_devices'), ('client', 'omada_list_clients')]:
            for row in await pages(config, tool, site_id=site['siteId']):
                record = omada_row(row, site, category)
                if category == 'device' and row.get('type') == 'ap':
                    try:
                        detail = await omada.request(config, 'omada_get_ap',
                                                     {'site_id': site['siteId'], 'ap_mac': row['mac']})
                    except omada.OmadaError:
                        # Older controllers or app permissions may omit details. Keep client discovery usable,
                        # but do not carry forward an old mesh parent as if it were freshly observed.
                        record['data']['uplink_note'] = 'AP uplink details are unavailable from the controller.'
                    else:
                        ap_uplink(record['data'], detail, site['siteId'])
                records.append(record)
        if len(records) > MAX_ROWS:
            raise DiscoveryError('Inventory exceeds the discovery limit; previous observations were retained.')
    return records


def proxmox_rows(rows):
    if not isinstance(rows, list) or len(rows) > MAX_ROWS or any(not isinstance(r, dict) for r in rows):
        raise DiscoveryError('Proxmox returned an invalid cluster inventory.')
    result = []
    for row in rows:
        kind = {'node': 'physical', 'qemu': 'vm', 'lxc': 'container'}.get(row.get('type'))
        if not kind:
            continue
        node = label(row.get('node'))
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', node):
            raise DiscoveryError('Proxmox returned an invalid node identity.')
        if kind != 'physical' and (type(row.get('vmid')) is not int or row['vmid'] < 1):
            raise DiscoveryError('Proxmox returned an invalid guest identity.')
        external_id = f"node/{node}" if kind == 'physical' else f"{row['type']}/{row['vmid']}"
        result.append({'external_id': external_id, 'data': {
            'name': label(row.get('name') or (node if kind == 'physical' else external_id)),
            'kind': kind, 'site': '', 'mac': '', 'addresses': [], 'medium': 'unknown',
            'attachment': '', 'port': '', 'parent': f'node/{node}' if kind != 'physical' else '',
            'status': label(row.get('status') or 'Unknown'),
        }})
    return result


async def collect(provider, config):
    if provider == 'omada':
        return await collect_omada(config)
    result = await ssh.run(config, PVE_COMMAND, timeout=60)
    if result.exit_code != 0 or result.truncated:
        raise DiscoveryError('Proxmox inventory could not be read completely. Check the SSH host and pvesh access.')
    try:
        return proxmox_rows(json.loads(result.stdout))
    except (ValueError, TypeError) as exc:
        if isinstance(exc, DiscoveryError):
            raise
        raise DiscoveryError('Proxmox returned invalid inventory JSON.') from None


async def start_run(resource_id, provider, *, min_interval=0):
    async with session() as db:
        await inv.lock_writes(db)
        res = await inv.require(db, Resource, resource_id)
        if (provider not in PROVIDERS or provider == 'omada' and
                (res.kind != 'mcp' or res.config.get('adapter') != 'omada') or
                provider == 'proxmox' and (res.kind != 'ssh' or not res.config.get('host_key'))):
            raise DiscoveryError('Choose an Omada controller or a Proxmox SSH resource with a pinned host key.')
        running = await db.scalar(select(Run).where(Run.resource_id == resource_id, Run.provider == provider,
                                  Run.status == 'running', Run.started_at > now() - timedelta(minutes=5)))
        if running:
            raise DiscoveryError('A refresh for this source is already running.')
        if min_interval:
            recent = await db.scalar(select(Run.id).where(
                Run.resource_id == resource_id, Run.provider == provider,
                Run.started_at > now() - timedelta(seconds=min_interval)))
            if recent:
                raise DiscoveryError(f'This source was refreshed recently. Wait {min_interval} seconds between refreshes.')
        run = Run(resource_id=resource_id, provider=provider, source_fingerprint=source_fingerprint(res.config))
        db.add(run)
        await db.flush()
        await audit.record(db, tool='inventory.discovery.start', decision='started',
                           detail={'run_id': run.id, 'resource_id': resource_id, 'provider': provider})
        return run.id, dict(res.config)


async def finish_run(run_id, records=None, error=''):
    async with session() as db:
        await inv.lock_writes(db)
        run = await inv.require(db, Run, run_id)
        resource = await inv.require(db, Resource, run.resource_id)
        if run.source_fingerprint != source_fingerprint(resource.config):
            error = 'The source configuration changed during refresh. Refresh again before reviewing its records.'
        latest = await db.scalar(select(Run.id).where(Run.resource_id == run.resource_id,
                               Run.provider == run.provider).order_by(Run.started_at.desc(), Run.id.desc()).limit(1))
        if latest != run.id:
            error = 'A newer refresh superseded this one; its results were not applied.'
        if not error:
            identities = [r['external_id'] for r in records]
            if len(identities) != len(set(identities)) or len(records) > MAX_ROWS:
                error = 'The source returned duplicate identities or too many records. Previous observations were retained.'
        if not error:
            existing = {r.external_id: r for r in (await db.scalars(select(Observation).where(
                Observation.resource_id == run.resource_id, Observation.provider == run.provider))).all()}
            at = now()
            for record in records:
                row = existing.get(record['external_id'])
                if row is None:
                    row = Observation(resource_id=run.resource_id, provider=run.provider,
                                      external_id=record['external_id'], first_seen=at)
                    db.add(row)
                elif row.data != record['data']:
                    row.previous, row.changed_at = row.data, at
                row.data, row.last_seen, row.run_id = record['data'], at, run.id
            run.count = len(records)
        run.status, run.error, run.finished_at = ('failed' if error else 'succeeded'), error, now()
        await audit.record(db, tool='inventory.discovery.finish', decision=run.status,
                           detail={'run_id': run.id, 'count': run.count, 'error': error})
        return run


async def refresh(resource_id, provider, *, min_interval=0):
    run_id, config = await start_run(resource_id, provider, min_interval=min_interval)
    try:
        records = await asyncio.wait_for(collect(provider, config), timeout=MAX_SECONDS)
    except (DiscoveryError, omada.OmadaError) as exc:
        return await finish_run(run_id, error=str(exc))
    except Exception:  # noqa: BLE001 — source failures must persist a safe error, never raw credentials.
        # SSH errors and upstream payloads can contain credentials or other unrelated data.
        return await finish_run(run_id, error='Discovery failed or timed out. Check source connectivity and access.')
    return await finish_run(run_id, records)


def matches(observation, data):
    """All plausible matches need review, including unique IPs (DHCP can reassign them)."""
    observed = observation.data
    reasons = {}
    def add(asset_id, reason):
        reasons.setdefault(asset_id, set()).add(reason)
    for asset in data['assets']:
        if asset.name.casefold() == observed['name'].casefold():
            add(asset.id, 'name')
    for iface in data['interfaces']:
        if observed['mac'] and mac(iface.mac) == observed['mac']:
            add(iface.asset_id, 'MAC')
    for allocation in data['allocations']:
        iface = data['interface_map'].get(allocation.interface_id)
        if iface and allocation.address in observed['addresses']:
            add(iface.asset_id, 'IP (unverified)')
    return [{'asset': data['asset_map'][key], 'reasons': ', '.join(sorted(value))}
            for key, value in sorted(reasons.items(), key=lambda x: data['asset_map'][x[0]].name.casefold())]
