"""Manual infrastructure inventory, independent of authorization and live discovery."""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from sqlalchemy import select, text

from .models import (
    DiscoveryLink,
    Resource,
)
from .models import (
    InventoryAllocation as Allocation,
)
from .models import (
    InventoryAsset as Asset,
)
from .models import (
    InventoryInterface as Interface,
)
from .models import (
    InventoryResourceLink as ResourceLink,
)
from .models import (
    InventorySubnet as Subnet,
)

# Stable persisted IDs, shared by forms, discovery review and the MCP schema.
KINDS = {
    "physical": "Physical host", "vm": "Virtual machine", "container": "Container",
    "network": "Network device", "device": "Other device", "service": "Service",
    "router": "Router / gateway", "switch": "Network switch",
    "access_point": "Wi-Fi access point", "modem": "Modem / ONT",
    "firewall": "Firewall", "network_bridge": "Network bridge / extender",
    "smart_hub": "Smart-home hub / controller", "zigbee_coordinator": "Zigbee coordinator",
    "zwave_controller": "Z-Wave controller", "thread_router": "Thread border router",
    "desktop": "Desktop computer", "laptop": "Laptop", "server": "Server",
    "nas": "NAS / network storage", "phone": "Phone", "tablet": "Tablet",
    "watch": "Smartwatch / wearable", "printer": "Printer", "scanner": "Scanner",
    "smart_plug": "Smart plug / outlet", "power_strip": "Smart power strip",
    "relay": "Smart relay", "light_switch": "Smart light switch",
    "dimmer": "Dimmer", "light_bulb": "Smart light bulb", "light_strip": "LED light strip",
    "light_fixture": "Smart light fixture / lamp", "lighting_controller": "Lighting controller",
    "thermostat": "Thermostat", "smart_vent": "Smart vent / HVAC damper",
    "hvac": "HVAC / air conditioner / heat pump", "heater": "Heater / radiator valve",
    "fan": "Fan / ceiling fan", "air_purifier": "Air purifier",
    "humidifier": "Humidifier", "dehumidifier": "Dehumidifier",
    "camera": "Camera / security camera", "doorbell": "Video doorbell",
    "smart_lock": "Smart door lock", "garage_door": "Garage door / gate opener",
    "alarm": "Alarm panel / security system", "siren": "Siren / chime",
    "motion_sensor": "Motion sensor", "presence_sensor": "Presence / occupancy sensor",
    "contact_sensor": "Door / window contact sensor", "temperature_sensor": "Temperature / humidity sensor",
    "leak_sensor": "Water leak sensor", "smoke_detector": "Smoke detector",
    "co_detector": "Carbon monoxide detector", "air_quality_sensor": "Air quality / CO2 sensor",
    "light_sensor": "Light / illuminance sensor", "weather_station": "Weather station",
    "sensor": "Other sensor", "button": "Smart button / remote control",
    "blinds": "Blinds / shades / curtains", "tv": "TV / projector",
    "streamer": "Streaming player / set-top box", "speaker": "Smart speaker",
    "audio": "Amplifier / receiver / soundbar", "smart_display": "Smart display",
    "game_console": "Game console", "vr_headset": "VR headset",
    "vacuum": "Robot vacuum / mop", "lawn_mower": "Robot lawn mower",
    "refrigerator": "Refrigerator / freezer", "oven": "Oven / stove / microwave",
    "dishwasher": "Dishwasher", "washer": "Washing machine", "dryer": "Clothes dryer",
    "coffee_maker": "Coffee maker / kettle", "appliance": "Other smart appliance",
    "pet_feeder": "Pet feeder / fountain", "litter_box": "Smart litter box",
    "irrigation": "Irrigation / sprinkler controller", "pool_controller": "Pool / spa controller",
    "water_valve": "Water valve / shutoff", "water_heater": "Water heater",
    "energy_meter": "Energy meter / power monitor", "ev_charger": "EV charger",
    "solar_inverter": "Solar inverter", "battery": "Battery / home energy storage",
    "ups": "UPS / battery backup", "fitness": "Fitness equipment / exercise bike",
    "scale": "Smart scale", "bed": "Smart bed / sleep monitor",
}

MEDIA = {"unknown": "Unknown", "wired": "Wired", "wifi": "Wi-Fi", "virtual": "Virtual"}
STATES = {"assigned": "Assigned", "reserved": "Reserved", "planned": "Planned", "excluded": "Excluded"}


class InventoryError(ValueError):
    pass


def value(data, key, maximum=160, required=False):
    result = str(data.get(key, "")).strip()
    if required and not result:
        raise InventoryError(f"{key.replace('_', ' ').capitalize()} is required.")
    if len(result) > maximum or any(ord(c) < 32 and c not in '\n\t\r' for c in result):
        raise InventoryError(f"{key.replace('_', ' ').capitalize()} must be at most {maximum} characters.")
    return result


def choice(data, key, options):
    result = value(data, key)
    if result not in options:
        raise InventoryError(f"Choose a valid {key}.")
    return result


def address(value):
    try:
        if '%' in value:
            raise ValueError
        return ipaddress.ip_address(value)
    except ValueError:
        raise InventoryError("Enter a valid IPv4 or IPv6 address without a zone or prefix.") from None


def bounds(network):
    """Usable host bounds, without enumerating even very large IPv6 networks."""
    start, end = int(network.network_address), int(network.broadcast_address)
    if network.version == 4 and network.prefixlen < 31:
        start, end = start + 1, end - 1
    elif network.version == 6 and network.prefixlen < 127:
        start += 1  # subnet-router anycast
    return start, end


def host_address(raw, network):
    ip = address(raw)
    lo, hi = bounds(network)
    if ip.version != network.version or not lo <= int(ip) <= hi:
        raise InventoryError("Address must be a usable host address inside this subnet.")
    return str(ip)


async def require(db, model, row_id):
    row = await db.get(model, row_id)
    if row is None:
        raise InventoryError("That record no longer exists. Refresh and try again.")
    return row


async def lock_writes(db):
    # Serialize parent-cycle and subnet-overlap checks with writes, including multiple workers.
    if db.bind.dialect.name == "sqlite":
        await db.execute(text("BEGIN IMMEDIATE"))
    else:
        for model in (Asset, Subnet):
            await db.execute(select(model).with_for_update())


async def save_asset(db, data):
    row_id = value(data, "id")
    row = await require(db, Asset, row_id) if row_id else Asset()
    name = value(data, "name", required=True)
    other = await db.scalar(select(Asset).where(Asset.name == name))
    if other and other.id != row_id:
        raise InventoryError("An infrastructure record with this name already exists.")
    kind = choice(data, "kind", KINDS)
    parent_id = value(data, "parent_id") or None
    cursor, visited = parent_id, set()
    while cursor:
        if cursor == row_id or cursor in visited:
            raise InventoryError("A host relationship cannot contain a cycle.")
        visited.add(cursor)
        cursor = (await require(db, Asset, cursor)).parent_id
    row.name, row.kind, row.parent_id = name, kind, parent_id
    row.site, row.tags = value(data, "site"), value(data, "tags", 500)
    row.notes = value(data, "notes", 4000)
    db.add(row)
    await db.flush()
    return row


async def save_interface(db, data):
    row_id, asset_id = value(data, "id"), value(data, "asset_id", required=True)
    await require(db, Asset, asset_id)
    row = await require(db, Interface, row_id) if row_id else Interface(asset_id=asset_id)
    if row.asset_id != asset_id:
        raise InventoryError("This interface belongs to a different infrastructure record.")
    name = value(data, "name", required=True)
    other = await db.scalar(select(Interface).where(Interface.asset_id == asset_id, Interface.name == name))
    if other and other.id != row_id:
        raise InventoryError("This host already has an interface with that name.")
    mac = value(data, "mac").lower().replace('-', ':')
    if mac and not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac):
        raise InventoryError("Use a MAC address such as 00:11:22:33:44:55.")
    attached = value(data, "attached_to_id") or None
    if attached:
        await require(db, Asset, attached)
        if attached == asset_id:
            raise InventoryError("An interface cannot connect to its own host.")
    row.name, row.medium, row.mac = name, choice(data, "medium", MEDIA), mac
    row.attached_to_id, row.port = attached, value(data, "port")
    db.add(row)
    await db.flush()
    return row


async def save_subnet(db, data):
    row_id = value(data, "id")
    row = await require(db, Subnet, row_id) if row_id else Subnet()
    try:
        network = ipaddress.ip_network(value(data, "cidr", required=True), strict=True)
    except ValueError:
        raise InventoryError("Enter a network in CIDR notation, with no host bits (e.g. 192.168.1.0/24).") from None
    scope = value(data, "scope") or "default"
    for other in (await db.scalars(select(Subnet).where(Subnet.scope == scope))).all():
        if other.id != row_id and network.overlaps(ipaddress.ip_network(other.cidr)):
            raise InventoryError("This network overlaps another subnet in the same address space.")
    vlan = value(data, "vlan")
    if vlan and (not vlan.isascii() or not vlan.isdigit() or not 1 <= int(vlan) <= 4094):
        raise InventoryError("VLAN must be between 1 and 4094, or left blank.")
    gateway = value(data, "gateway")
    if gateway:
        gateway = host_address(gateway, network)
    start, end = value(data, "dhcp_start"), value(data, "dhcp_end")
    if bool(start) != bool(end):
        raise InventoryError("Specify both DHCP pool endpoints, or leave both blank.")
    if start:
        start, end = host_address(start, network), host_address(end, network)
        if int(address(start)) > int(address(end)):
            raise InventoryError("DHCP pool start must precede its end.")
        if gateway and int(address(start)) <= int(address(gateway)) <= int(address(end)):
            raise InventoryError("The gateway cannot be inside the DHCP pool.")
    allocations = (await db.scalars(select(Allocation).where(Allocation.subnet_id == row_id))).all() if row_id else []
    for allocation in allocations:
        host_address(allocation.address, network)
        if allocation.address == gateway:
            raise InventoryError("The gateway already has an allocation. Keep the allocation or the gateway entry.")
    row.name, row.cidr, row.scope = value(data, "name", required=True), str(network), scope
    row.site, row.vlan = value(data, "site"), int(vlan) if vlan else None
    row.gateway, row.dhcp_start, row.dhcp_end = gateway, start, end
    row.notes = value(data, "notes", 4000)
    db.add(row)
    await db.flush()
    return row


async def save_allocation(db, data):
    row_id, subnet_id = value(data, "id"), value(data, "subnet_id", required=True)
    subnet = await require(db, Subnet, subnet_id)
    row = await require(db, Allocation, row_id) if row_id else Allocation(subnet_id=subnet_id)
    if row.subnet_id != subnet_id:
        raise InventoryError("This allocation belongs to a different subnet.")
    ip = host_address(value(data, "address", required=True), ipaddress.ip_network(subnet.cidr))
    if ip == subnet.gateway:
        raise InventoryError("This address is already recorded as the subnet gateway.")
    other = await db.scalar(select(Allocation).where(Allocation.subnet_id == subnet_id, Allocation.address == ip))
    if other and other.id != row_id:
        raise InventoryError("This address already has an allocation in this subnet.")
    state, interface_id = choice(data, "state", STATES), value(data, "interface_id") or None
    if interface_id:
        await require(db, Interface, interface_id)
    if state == "assigned" and not interface_id:
        raise InventoryError("An assigned address must be linked to an interface.")
    label = value(data, "label")
    if not interface_id and not label:
        raise InventoryError("Add a label or choose an interface so this allocation has an owner or purpose.")
    row.address, row.state, row.interface_id = ip, state, interface_id
    row.label, row.notes = label, value(data, "notes", 4000)
    db.add(row)
    await db.flush()
    return row


async def link_resource(db, data):
    resource_id, asset_id = value(data, "resource_id", required=True), value(data, "asset_id", required=True)
    await require(db, Resource, resource_id)
    await require(db, Asset, asset_id)
    row = await db.get(ResourceLink, resource_id)
    if row and row.asset_id != asset_id:
        raise InventoryError("This resource is already linked to another host. Unlink it there first.")
    if not row:
        row = ResourceLink(resource_id=resource_id, asset_id=asset_id)
        db.add(row)
    await db.flush()
    return row


async def delete_record(db, kind, row_id):
    models = {"asset": Asset, "interface": Interface, "subnet": Subnet, "allocation": Allocation,
              "link": ResourceLink}
    if kind not in models:
        raise InventoryError("Unknown inventory record type.")
    row = await require(db, models[kind], row_id)
    checks = {
        "asset": [(Asset, Asset.parent_id), (Interface, Interface.asset_id),
                  (Interface, Interface.attached_to_id), (ResourceLink, ResourceLink.asset_id),
                  (DiscoveryLink, DiscoveryLink.asset_id)],
        "interface": [(Allocation, Allocation.interface_id), (DiscoveryLink, DiscoveryLink.interface_id)],
        "subnet": [(Allocation, Allocation.subnet_id)],
    }
    for model, field in checks.get(kind, []):
        if await db.scalar(select(model).where(field == row_id).limit(1)):
            raise InventoryError("This record is still in use. Remove or reassign its links and allocations first.")
    await db.delete(row)
    return row


async def snapshot(db):
    result = {}
    for key, model in (("assets", Asset), ("interfaces", Interface), ("subnets", Subnet),
                       ("allocations", Allocation), ("links", ResourceLink), ("resources", Resource)):
        result[key] = list((await db.scalars(select(model))).all())
    result["assets"].sort(key=lambda x: x.name.casefold())
    result["subnets"].sort(key=lambda x: (x.scope, address_key(x.cidr.split('/')[0])))
    result["resources"].sort(key=lambda x: x.name.casefold())
    result["asset_map"] = {x.id: x for x in result["assets"]}
    result["interface_map"] = {x.id: x for x in result["interfaces"]}
    result["subnet_map"] = {x.id: x for x in result["subnets"]}
    result["resource_map"] = {x.id: x for x in result["resources"]}
    return result


def address_key(ip):
    if not ip:
        return 9, 0
    parsed = address(ip)
    return parsed.version, int(parsed)


def asset_rows(data, query="", sort="name", group="none"):
    interfaces, allocations, links = defaultdict(list), defaultdict(list), defaultdict(list)
    for row in data["interfaces"]:
        interfaces[row.asset_id].append(row)
    for row in data["allocations"]:
        interface = data["interface_map"].get(row.interface_id)
        if interface:
            allocations[interface.asset_id].append(row)
    for row in data["links"]:
        if row.resource_id in data["resource_map"]:
            links[row.asset_id].append(data["resource_map"][row.resource_id])
    rows = []
    for asset in data["assets"]:
        ips = sorted(allocations[asset.id], key=lambda a: address_key(a.address))
        networks = sorted({data["subnet_map"][a.subnet_id].name for a in ips})
        parent = data["asset_map"].get(asset.parent_id)
        media = sorted({MEDIA[i.medium] for i in interfaces[asset.id]})
        row = {"asset": asset, "interfaces": interfaces[asset.id], "allocations": ips,
               "parent": parent, "media": media, "networks": networks, "resources": links[asset.id]}
        haystack = ' '.join([asset.name, KINDS[asset.kind], asset.site, asset.tags,
                            parent.name if parent else '', *media, *networks,
                            *(a.address for a in ips), *(r.name for r in links[asset.id])])
        if query.casefold() not in haystack.casefold():
            continue
        row["group"] = {"host": parent.name if parent else "No parent host", "site": asset.site or "No site",
                        "kind": KINDS[asset.kind], "network": ', '.join(networks) or "No network",
                        "medium": ', '.join(media) or "Unknown"}.get(group, "Infrastructure")
        rows.append(row)
    def key(row):
        a = row["asset"]
        primary = {"name": a.name.casefold(), "ip": address_key(row["allocations"][0].address if row["allocations"] else ''),
                   "kind": KINDS[a.kind], "site": a.site.casefold()}.get(sort, a.name.casefold())
        return row["group"].casefold(), primary, a.name.casefold()
    return sorted(rows, key=key)


def hosting_tree(data):
    """An iterative outline avoids recursion limits for imported or deep hierarchies."""
    children = defaultdict(list)
    for asset in data["assets"]:
        children[asset.parent_id if asset.parent_id in data["asset_map"] else None].append(asset)
    rows, visited = [], set()
    stack = [(asset, 0, []) for asset in reversed(children[None])]
    while stack:
        asset, depth, ancestors = stack.pop()
        if asset.id in visited:
            continue
        visited.add(asset.id)
        rows.append({"asset": asset, "depth": depth, "ancestors": ancestors,
                     "children": bool(children[asset.id])})
        stack.extend((child, depth + 1, [*ancestors, asset.id]) for child in reversed(children[asset.id]))
    return rows


def subnet_summary(subnet, allocations):
    network = ipaddress.ip_network(subnet.cidr)
    lo, hi = bounds(network)
    rows = sorted((x for x in allocations if x.subnet_id == subnet.id), key=lambda x: address_key(x.address))
    occupied = [(int(address(x.address)), int(address(x.address))) for x in rows]
    if subnet.gateway:
        occupied.append((int(address(subnet.gateway)), int(address(subnet.gateway))))
    pool_size = 0
    if subnet.dhcp_start:
        start, end = int(address(subnet.dhcp_start)), int(address(subnet.dhcp_end))
        occupied.append((start, end))
        pool_size = end - start + 1
    # Gaps are unrecorded, never proof of availability. Merge intervals rather than enumerate hosts.
    cursor, gaps = lo, []
    for start, end in sorted(occupied):
        if start > cursor:
            gaps.append((cursor, start - 1))
        cursor = max(cursor, end + 1)
    if cursor <= hi:
        gaps.append((cursor, hi))
    constructor = ipaddress.IPv4Address if network.version == 4 else ipaddress.IPv6Address
    return {"rows": rows, "capacity": hi - lo + 1, "recorded": len(rows), "pool_size": pool_size,
            "unrecorded": sum(end - start + 1 for start, end in gaps),
            "gaps": [(str(constructor(start)), str(constructor(end))) for start, end in gaps]}


def resource_inventory(data, sort="type", group="none"):
    assets = {link.resource_id: data["asset_map"].get(link.asset_id) for link in data["links"]}
    details = {row["asset"].id: row for row in asset_rows(data)}
    labels = {}
    def ip_key(resource):
        asset = assets.get(resource.id)
        if asset and details[asset.id]["allocations"]:
            return address_key(details[asset.id]["allocations"][0].address)
        try:
            return address_key(resource.config.get("host", ""))
        except InventoryError:
            return 9, 0
    for resource in data["resources"]:
        asset = assets.get(resource.id)
        detail = details.get(asset.id) if asset else None
        labels[resource.id] = ({"host": asset.name if asset else "Not linked to inventory",
                               "network": ', '.join(detail["networks"]) if detail and detail["networks"]
                               else "No network recorded"}.get(group, "Resources"))
    rows = sorted(data["resources"], key=lambda r: (
        labels[r.id].casefold(),
        ip_key(r) if sort == "ip" else (r.name.casefold() if sort == "name" else r.kind), r.name.casefold()))
    return {"rows": rows, "resource_assets": assets, "resource_groups": labels, "sort": sort, "group": group}
