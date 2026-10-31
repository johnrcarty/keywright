"""Admin-only discovery previews; all source reads are audited."""
from datetime import timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .. import discovery, inventory, reconciliation
from ..db import session
from ..models import DiscoveryLink, DiscoveryObservation, DiscoveryRun, now
from . import auth
from .admin import redirect, render
from .security import require_same_origin

router = APIRouter(dependencies=[Depends(require_same_origin), Depends(auth.require_admin)])


@router.get('/ui/inventory/discovery')
async def discovery_page(request: Request, source: str = '', q: str = '', page: int = 1, state: str = ''):
    async with session() as db:
        data = await inventory.snapshot(db)
        runs = list((await db.scalars(select(DiscoveryRun).order_by(DiscoveryRun.started_at.desc()))).all())
        observations = list((await db.scalars(select(DiscoveryObservation))).all())
        links = {r.observation_id: r for r in (await db.scalars(select(DiscoveryLink))).all()}
    latest, succeeded = {}, {}
    for run in runs:
        key = (run.resource_id, run.provider)
        latest.setdefault(key, run)
        if run.status == 'succeeded':
            succeeded.setdefault(key, run)
    by_identity = {(r.resource_id, r.provider, r.external_id): r for r in observations}
    def review_state(record):
        link = links.get(record.id)
        return ('changed' if link.reviewed_data != record.data else 'reviewed') if link else 'new'
    filtered = [r for r in observations if (not source or r.resource_id == source) and q.casefold() in
                ' '.join([r.data['name'], r.data['mac'], *r.data['addresses'], r.data['site']]).casefold()
                and (state not in ('new', 'changed', 'reviewed') or review_state(r) == state)]
    filtered.sort(key=lambda r: (r.data['name'].casefold(), r.resource_id, r.external_id))
    total_pages = max(1, (len(filtered) + 99) // 100)
    page = min(max(1, page), total_pages)
    rows = []
    for record in filtered[(page - 1) * 100:page * 100]:
        link = links.get(record.id)
        baseline = link.reviewed_data if link else record.previous
        key = (record.resource_id, record.provider)
        success = succeeded.get(key)
        parent = by_identity.get((*key, record.data['parent']))
        attachment = by_identity.get((*key, record.data['attachment']))
        labels = {'name': 'Name', 'kind': 'Device type', 'site': 'Site', 'mac': 'MAC address',
                  'addresses': 'IP addresses', 'medium': 'Connection', 'attachment': 'Connected to',
                  'port': 'Port / SSID', 'parent': 'Hosted on', 'status': 'Source state',
                  'device_type': 'Network device type', 'model': 'Model', 'uplink_note': 'Uplink details'}
        def display(field, value, source_key=key):
            if field in ('parent', 'attachment') and value:
                target = by_identity.get((*source_key, value))
                return target.data['name'] if target else value
            if field == 'medium':
                return inventory.MEDIA.get(value, 'Unknown')
            if field == 'kind':
                return inventory.KINDS.get(value, 'Unknown')
            return (', '.join(value) if isinstance(value, list) else value) or 'Not reported'
        rows.append({'record': record, 'matches': discovery.matches(record, data), 'link': link,
                     'review_state': ('Needs review' if link.reviewed_data != record.data else 'Reviewed') if link else 'New',
                     'parent': parent.data['name'] if parent else record.data['parent'],
                     'attachment': attachment.data['name'] if attachment else record.data['attachment'],
                     'missing': success is not None and record.run_id != success.id,
                     'stale': record.last_seen < now() - timedelta(hours=24),
                     'changes': [{'label': labels[k], 'before': display(k, baseline.get(k)),
                                  'after': display(k, v)} for k, v in record.data.items()
                                 if baseline is not None and baseline.get(k) != v]})
    return render(request, 'inventory_discovery.html', **data, rows=rows, latest=list(latest.values()),
                  kinds=inventory.KINDS, media=inventory.MEDIA, providers=discovery.PROVIDERS,
                  source=source, q=q, state=state, page=page, total_pages=total_pages, total_count=len(filtered),
                  previous_query=urlencode({'source': source, 'q': q, 'page': page - 1, 'state': state}),
                  next_query=urlencode({'source': source, 'q': q, 'page': page + 1, 'state': state}),
                  interrupted_before=now() - timedelta(minutes=5))


@router.post('/ui/inventory/discovery/refresh')
async def discovery_refresh(request: Request):
    form = await request.form()
    try:
        resource_id = inventory.value(form, 'resource_id', required=True)
        provider = inventory.value(form, 'provider', required=True)
        run = await discovery.refresh(resource_id, provider)
    except (discovery.DiscoveryError, inventory.InventoryError) as exc:
        return redirect('/ui/inventory/discovery', str(exc))
    message = f'Refreshed {run.count} observations. Inventory records are unchanged.' if run.status == 'succeeded' else run.error
    return redirect('/ui/inventory/discovery', message)


@router.get('/ui/inventory/discovery/{observation_id}/review')
async def observation_review(request: Request, observation_id: str, target_id: str = '', interface_id: str = ''):
    try:
        async with session() as db:
            ctx = await reconciliation.review(db, observation_id, target_id, interface_id)
    except (discovery.DiscoveryError, inventory.InventoryError) as exc:
        return redirect('/ui/inventory/discovery', str(exc))
    return render(request, 'inventory_discovery_review.html', **ctx)


@router.post('/ui/inventory/discovery/{observation_id}/review')
async def observation_apply(request: Request, observation_id: str):
    form = await request.form()
    try:
        asset_id = await reconciliation.apply(observation_id, form)
    except (discovery.DiscoveryError, inventory.InventoryError, IntegrityError) as exc:
        message = str(exc) if not isinstance(exc, IntegrityError) else 'A conflicting record was saved. Review again.'
        query = urlencode({'target_id': form.get('target_id', ''), 'interface_id': form.get('interface_id', '')})
        return redirect(f'/ui/inventory/discovery/{observation_id}/review?{query}', message)
    return redirect(f'/ui/inventory/assets/{asset_id}', 'Discovery review saved. Only the selected inventory changes were applied.')
