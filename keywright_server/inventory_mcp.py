"""Local inventory tools. The MCP broker gates calls before entering this module.

Writes use the caller's database transaction so the inventory and its audit event commit
atomically. Resource credentials and access settings are never serialized or changed here.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Annotated, Literal

import mcp_types as types
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select

from . import inventory as inv
from .models import DiscoveryLink, DiscoveryObservation

Text = Annotated[str, Field(max_length=160)]
Identifier = Annotated[str, Field(max_length=160)]
Kind = Literal[*inv.KINDS]
Medium = Literal['unknown', 'wired', 'wifi', 'virtual']
State = Literal['assigned', 'reserved', 'planned', 'excluded']


class Model(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class Page(Model):
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=500)


class InventoryQuery(Page):
    query: Text = ''
    asset_id: Identifier = ''


class IPQuery(Page):
    subnet_id: Identifier = ''
    asset_id: Identifier = ''
    address: Text = ''


class DiscoveryQuery(Page):
    resource_id: Identifier = ''
    query: Text = ''


class Asset(Model):
    id: Identifier = ''
    name: Text = ''
    kind: Kind = 'physical'
    parent_id: Identifier = ''
    site: Text = ''
    tags: Annotated[str, Field(max_length=500)] = ''
    notes: Annotated[str, Field(max_length=4000)] = ''


class Allocation(Model):
    id: Identifier = ''
    subnet_id: Identifier
    address: Text
    state: State = 'reserved'
    interface_id: Identifier = ''
    label: Text = ''
    notes: Annotated[str, Field(max_length=4000)] = ''


class Interface(Model):
    id: Identifier = ''
    name: Text = ''
    medium: Medium = 'unknown'
    mac: Text = ''
    attached_to_id: Identifier = ''
    port: Text = ''
    allocations: list[Allocation] = Field(default_factory=list, max_length=20)


class Write(Model):
    expected_revision: str = Field(pattern=r'^[a-f0-9]{64}$', description=
        'Inventory revision from a read or successful write. A concurrent change rejects this call; read again.')


class HostSetup(Write):
    asset: Asset
    interfaces: list[Interface] = Field(default_factory=list, max_length=20)
    resource_ids: list[Identifier] = Field(default_factory=list, max_length=20)


class Subnet(Model):
    id: Identifier = ''
    name: Text = ''
    cidr: Text = ''
    scope: Text = 'default'
    site: Text = ''
    vlan: Text = ''
    gateway: Text = ''
    dhcp_start: Text = ''
    dhcp_end: Text = ''
    notes: Annotated[str, Field(max_length=4000)] = ''


class SubnetSave(Write):
    subnet: Subnet


class IPSave(Write):
    allocation: Allocation


OPERATIONS = {
    'list_inventory': (InventoryQuery, True, ('Find inventory hosts, VMs, containers and services, their interfaces, '
        'IP allocations and linked resource IDs. Includes resource names/types, never connection credentials. '
        'Use query for name, IP or resource name, or asset_id for one record. Returns an inventory revision.')),
    'get_topology': (InventoryQuery, True, ('Read hosting and network attachment edges for inventory records. '
        'Paginated by asset; edges can reference assets on other pages. Returns an inventory revision.')),
    'list_subnets': (Page, True, ('List recorded subnets, gateways, DHCP pools, allocations and unrecorded ranges. '
        'Unrecorded ranges are candidates, not proof that an IP is unused on the network.')),
    'list_ips': (IPQuery, True, ('List recorded IP allocations and their interface/host ownership, optionally '
        'filtered by subnet_id, asset_id or exact address. These are inventory records, not a live IP scan.')),
    'list_discovery': (DiscoveryQuery, True, ('Read cached discovery observations with source, last-seen time and '
        'existing inventory links. Observations are evidence, not confirmed IP reservations. Does not refresh sources.')),
    'setup_host': (HostSetup, False, ('Create or update an inventory host, VM, container or service, its parent, '
        'interfaces, IP allocations and links to existing resources in one atomic operation. Use IDs to update; '
        'omitted fields on existing records are preserved. An interface allocation is tied to that interface. '
        'Use state=assigned for a confirmed assigned IP, reserved for a reservation. Resource links do not grant '
        'access. This records topology; use the brokered SSH tools to configure machines or deploy software. '
        'Read inventory first and supply expected_revision. Errors make no inventory changes.')),
    'save_subnet': (SubnetSave, False, ('Create or update a subnet and its gateway, DHCP pool and address space. '
        'Use subnet.id to update; omitted fields are preserved. Overlapping subnets in one scope are rejected. '
        'Read inventory first and supply expected_revision. Records inventory; does not configure a router.')),
    'save_ip': (IPSave, False, ('Reserve, plan or assign an explicit IP in a recorded subnet, or update an '
        'allocation by ID. Assigned IPs require interface_id; otherwise provide an ownership label. '
        'Duplicate allocations and gateway conflicts are rejected. Supply expected_revision from a read. '
        'This records inventory; it does not configure DHCP or the host.')),
}
READ_TOOLS = [name for name, (_, read, _) in OPERATIONS.items() if read]
WRITE_TOOLS = [name for name, (_, read, _) in OPERATIONS.items() if not read]
DEFAULT_BUNDLES = {'read-only': ['tools/' + n for n in READ_TOOLS],
                   'inventory-write': ['tools/' + n for n in WRITE_TOOLS]}


def list_tools():
    return [types.Tool(name=name, description=description, input_schema=model.model_json_schema(),
                       annotations=types.ToolAnnotations(read_only_hint=read, destructive_hint=False,
                                                         idempotent_hint=True))
            for name, (model, read, description) in OPERATIONS.items()]


def validate(tool, arguments):
    if tool not in OPERATIONS:
        raise inv.InventoryError('Unknown Keywright inventory tool.')
    try:
        return OPERATIONS[tool][0].model_validate(arguments)
    except ValidationError as exc:
        fields = ', '.join('.'.join(map(str, e['loc'])) for e in exc.errors(include_input=False))
        raise inv.InventoryError(f'Invalid inventory arguments: {fields}. Use the tool schema.') from None


def row_values(row):
    return {c.name: v.isoformat() if isinstance(v, datetime) else v
            for c in row.__table__.columns for v in [getattr(row, c.name)]}


def public_resource(row):
    return {'id': row.id, 'name': row.name, 'kind': row.kind}


def revision(data):
    records = {k: sorted((row_values(r) for r in data[k]), key=lambda r: json.dumps(r, sort_keys=True))
               for k in ('assets', 'interfaces', 'subnets', 'allocations', 'links')}
    records['resources'] = sorted((public_resource(r) for r in data['resources']), key=lambda r: r['id'])
    return hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()


def page(rows, args):
    end = args.offset + args.limit
    return {'rows': rows[args.offset:end], 'total': len(rows), 'offset': args.offset,
            'next_offset': end if end < len(rows) else None}


def allocation_values(row, data):
    iface = data['interface_map'].get(row.interface_id)
    asset = data['asset_map'].get(iface.asset_id) if iface else None
    subnet = data['subnet_map'][row.subnet_id]
    return {**row_values(row), 'asset_id': asset.id if asset else None, 'asset_name': asset.name if asset else None,
            'interface_name': iface.name if iface else None, 'subnet_name': subnet.name, 'scope': subnet.scope}


async def read(db, tool, args, data):
    if tool in ('list_inventory', 'get_topology'):
        rows = [r for r in inv.asset_rows(data, args.query) if not args.asset_id or r['asset'].id == args.asset_id]
        result = page(rows, args)
        if tool == 'list_inventory':
            result['rows'] = [{**row_values(r['asset']), 'interfaces': [row_values(i) for i in r['interfaces']],
                'allocations': [allocation_values(a, data) for a in r['allocations']],
                'resources': [public_resource(res) for res in r['resources']]} for r in result['rows']]
            result['resources'] = [public_resource(r) for r in data['resources'][:500]]
            result['resources_total'] = len(data['resources'])
        else:
            edges = []
            for r in result['rows']:
                a = r['asset']
                if a.parent_id:
                    edges.append({'type': 'hosted_on', 'from_asset_id': a.id, 'to_asset_id': a.parent_id})
                edges += [{'type': 'connected_to', 'from_asset_id': a.id, 'to_asset_id': i.attached_to_id,
                           'interface_id': i.id, 'medium': i.medium, 'port': i.port}
                          for i in r['interfaces'] if i.attached_to_id]
            result['rows'] = [row_values(r['asset']) for r in result['rows']]
            result['edges'] = edges
        return result
    if tool == 'list_subnets':
        result = page(data['subnets'], args)
        result['rows'] = [{**row_values(s), **{k: v for k, v in inv.subnet_summary(s, data['allocations']).items()
                                             if k != 'rows'}} for s in result['rows']]
        result['note'] = 'Unrecorded ranges exclude the gateway, DHCP pool and recorded allocations; verify before use.'
        return result
    if tool == 'list_ips':
        address = str(inv.address(args.address)) if args.address else ''
        rows = [allocation_values(a, data) for a in sorted(data['allocations'], key=lambda a: (a.subnet_id, inv.address_key(a.address)))]
        return page([r for r in rows if (not args.subnet_id or r['subnet_id'] == args.subnet_id)
                     and (not args.asset_id or r['asset_id'] == args.asset_id)
                     and (not address or r['address'] == address)], args)
    links = {r.observation_id: r for r in (await db.scalars(select(DiscoveryLink))).all()}
    observations = list((await db.scalars(select(DiscoveryObservation).order_by(DiscoveryObservation.id))).all())
    rows = [{**row_values(o), 'asset_id': links[o.id].asset_id if o.id in links else None,
             'source_name': data['resource_map'][o.resource_id].name}
            for o in observations if (not args.resource_id or o.resource_id == args.resource_id)
            and args.query.casefold() in json.dumps(o.data).casefold()]
    return page(rows, args)


async def merged(db, model, values, *, exclude=()):
    old = await inv.require(db, model, values.id) if values.id else None
    supplied = values.model_dump(exclude_unset=old is not None, exclude=set(exclude))
    before = row_values(old) if old else None
    return {**({k: v if v is not None else '' for k, v in before.items()} if old else {}), **supplied}, before


async def execute(db, tool, args):
    """Called only after the MCP gate, with no active transaction for write calls. Does not commit."""
    if not OPERATIONS[tool][1]:
        await inv.lock_writes(db)
    data = await inv.snapshot(db)
    current_revision = revision(data)
    if OPERATIONS[tool][1]:
        return {**await read(db, tool, args, data), 'revision': current_revision}, []
    if args.expected_revision != current_revision:
        raise inv.InventoryError('Inventory changed since it was read. Read again and review the updated operation.')
    changes = []

    async def save(model, values, fn, *, exclude=(), extra=None):
        fields, before = await merged(db, model, values, exclude=exclude)
        row = await fn(db, {**fields, **(extra or {})})
        changes.append({'record': model.__tablename__, 'before': before, 'after': row_values(row)})
        return row

    if tool == 'setup_host':
        asset = await save(inv.Asset, args.asset, inv.save_asset)
        for interface in args.interfaces:
            iface = await save(inv.Interface, interface, inv.save_interface, exclude=('allocations',),
                               extra={'asset_id': asset.id})
            for allocation in interface.allocations:
                if allocation.interface_id and allocation.interface_id != iface.id:
                    raise inv.InventoryError('The allocation must belong to the interface being set up.')
                if allocation.id:
                    existing = await inv.require(db, inv.Allocation, allocation.id)
                    if existing.interface_id != iface.id:
                        raise inv.InventoryError('This allocation belongs to a different interface; use save_ip to reassign it explicitly.')
                await save(inv.Allocation, allocation, inv.save_allocation, extra={'interface_id': iface.id})
        for rid in dict.fromkeys(args.resource_ids):
            old = await db.get(inv.ResourceLink, rid)
            before = row_values(old) if old else None
            row = await inv.link_resource(db, {'resource_id': rid, 'asset_id': asset.id})
            changes.append({'record': inv.ResourceLink.__tablename__, 'before': before, 'after': row_values(row)})
        result = {'asset_id': asset.id}
    elif tool == 'save_subnet':
        subnet = await save(inv.Subnet, args.subnet, inv.save_subnet)
        result = {'subnet_id': subnet.id}
    else:
        allocation = await save(inv.Allocation, args.allocation, inv.save_allocation)
        result = {'allocation_id': allocation.id}
    await db.flush()
    # Refresh collections after edits; the new revision permits the next explicit operation.
    return {**result, 'revision': revision(await inv.snapshot(db)), 'changes': changes}, changes
