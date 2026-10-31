"""Authenticated inventory forms; manual changes are recorded in the existing audit log."""
from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .. import audit
from .. import inventory as inv
from ..db import session
from ..models import DiscoveryLink, DiscoveryObservation, Resource
from . import auth
from .admin import redirect, render
from .security import require_same_origin

router = APIRouter(dependencies=[Depends(require_same_origin), Depends(auth.require_admin)])


async def context():
    async with session() as db:
        data = await inv.snapshot(db)
        sources = (await db.execute(select(DiscoveryLink, DiscoveryObservation, Resource)
                   .join(DiscoveryObservation, DiscoveryLink.observation_id == DiscoveryObservation.id)
                   .join(Resource, DiscoveryObservation.resource_id == Resource.id))).all()
        data['discovery_sources'] = {}
        for link, observation, resource in sources:
            data['discovery_sources'].setdefault(link.asset_id, []).append(
                {'link': link, 'observation': observation, 'resource': resource})
    return {**data, "kinds": inv.KINDS, "media": inv.MEDIA, "states": inv.STATES}


@router.get("/ui/inventory")
async def inventory_page(request: Request, q: str = "", sort: str = "name", group: str = "none"):
    data = await context()
    return render(request, "inventory.html", **data, rows=inv.asset_rows(data, q, sort, group),
                  q=q, sort=sort, group=group)


@router.get("/ui/inventory/topology")
async def topology_page(request: Request):
    data = await context()
    return render(request, "inventory_topology.html", **data, tree=inv.hosting_tree(data))


@router.get("/ui/inventory/networks")
async def networks_page(request: Request):
    data = await context()
    summaries = {s.id: inv.subnet_summary(s, data["allocations"]) for s in data["subnets"]}
    return render(request, "inventory_networks.html", **data, summaries=summaries)


def asset_context(data, asset, values=None):
    asset_id = asset.id if asset else None
    interfaces = [i for i in data["interfaces"] if i.asset_id == asset_id]
    linked_ids = {x.resource_id for x in data["links"]}
    return {**data, "asset": asset, "values": values or {}, "asset_interfaces": interfaces,
            "asset_allocations": [a for a in data["allocations"] if a.interface_id in {i.id for i in interfaces}],
            "asset_resources": [data["resource_map"][x.resource_id] for x in data["links"]
                                if x.asset_id == asset_id and x.resource_id in data["resource_map"]],
            "unlinked_resources": [r for r in data["resources"] if r.id not in linked_ids],
            "children": [a for a in data["assets"] if a.parent_id == asset_id] if asset else []}


@router.get("/ui/inventory/assets/new")
async def asset_new(request: Request, resource: str = ""):
    data = await context()
    res = data["resource_map"].get(resource)
    values = {"name": res.name, "resource_id": res.id} if res else {}
    return render(request, "inventory_asset.html", **asset_context(data, None, values))


@router.get("/ui/inventory/assets/{asset_id}")
async def asset_page(request: Request, asset_id: str):
    data = await context()
    asset = data["asset_map"].get(asset_id)
    if not asset:
        return redirect("/ui/inventory", "Infrastructure record not found.")
    return render(request, "inventory_asset.html", **asset_context(data, asset))


@router.get("/ui/inventory/networks/new")
async def network_new(request: Request):
    return render(request, "inventory_subnet.html", **await context(), subnet=None, values={}, summary=None)


@router.get("/ui/inventory/networks/{subnet_id}")
async def network_page(request: Request, subnet_id: str):
    data = await context()
    subnet = data["subnet_map"].get(subnet_id)
    if not subnet:
        return redirect("/ui/inventory/networks", "Subnet not found.")
    summary = inv.subnet_summary(subnet, data["allocations"])
    return render(request, "inventory_subnet.html", **data, subnet=subnet, values={}, summary=summary)


@router.post("/ui/inventory/assets")
async def asset_save(request: Request):
    form = await request.form()
    try:
        async with session() as db:
            await inv.lock_writes(db)
            asset = await inv.save_asset(db, form)
            if form.get("resource_id"):
                await inv.link_resource(db, {"asset_id": asset.id, "resource_id": form["resource_id"]})
            await audit.record(db, tool="inventory.asset.save", decision="saved",
                               detail={"id": asset.id, "name": asset.name})
            asset_id = asset.id
    except (inv.InventoryError, IntegrityError) as exc:
        data = await context()
        error = str(exc) if isinstance(exc, inv.InventoryError) else "A conflicting record was saved. Refresh and try again."
        return render(request, "inventory_asset.html", error=error,
                      **asset_context(data, data["asset_map"].get(form.get("id")), dict(form)))
    return redirect(f"/ui/inventory/assets/{asset_id}", "Infrastructure record saved.")


@router.post("/ui/inventory/networks")
async def network_save(request: Request):
    form = await request.form()
    try:
        async with session() as db:
            await inv.lock_writes(db)
            subnet = await inv.save_subnet(db, form)
            await audit.record(db, tool="inventory.subnet.save", decision="saved",
                               detail={"id": subnet.id, "cidr": subnet.cidr, "scope": subnet.scope})
            subnet_id = subnet.id
    except (inv.InventoryError, IntegrityError) as exc:
        data = await context()
        subnet = data["subnet_map"].get(form.get("id"))
        error = str(exc) if isinstance(exc, inv.InventoryError) else "A conflicting subnet was saved. Refresh and try again."
        return render(request, "inventory_subnet.html", **data, subnet=subnet, values=dict(form), error=error,
                      summary=inv.subnet_summary(subnet, data["allocations"]) if subnet else None)
    return redirect(f"/ui/inventory/networks/{subnet_id}", "Subnet saved.")


@router.post("/ui/inventory/interfaces")
async def interface_save(request: Request):
    return await detail_save(request, "interface", inv.save_interface)


@router.post("/ui/inventory/allocations")
async def allocation_save(request: Request):
    return await detail_save(request, "allocation", inv.save_allocation)


@router.post("/ui/inventory/links")
async def link_save(request: Request):
    return await detail_save(request, "link", inv.link_resource)


async def detail_save(request, kind, save):
    form = await request.form()
    try:
        async with session() as db:
            await inv.lock_writes(db)
            row = await save(db, form)
            row_id = row.resource_id if kind == "link" else row.id
            await audit.record(db, tool=f"inventory.{kind}.save", decision="saved",
                               detail={"id": row_id, "record": dict(form)})
    except (inv.InventoryError, IntegrityError) as exc:
        error = str(exc) if isinstance(exc, inv.InventoryError) else "A conflicting record was saved. Refresh and try again."
        data = await context()
        if kind == "allocation":
            subnet = data["subnet_map"].get(form.get("subnet_id"))
            if subnet:
                return render(request, "inventory_subnet.html", **data, subnet=subnet, values={},
                              summary=inv.subnet_summary(subnet, data["allocations"]), error=error,
                              allocation_values=dict(form))
        else:
            asset = data["asset_map"].get(form.get("asset_id"))
            if asset:
                return render(request, "inventory_asset.html", **asset_context(data, asset), error=error,
                              interface_values=dict(form) if kind == "interface" else {})
        return redirect("/ui/inventory", error)
    destination = (f"/ui/inventory/networks/{row.subnet_id}" if kind == "allocation"
                   else f"/ui/inventory/assets/{row.asset_id}")
    return redirect(destination, f"{kind.capitalize()} saved.")


@router.post("/ui/inventory/{kind}/{row_id}/delete")
async def record_delete(request: Request, kind: str, row_id: str):
    form = await request.form()
    try:
        async with session() as db:
            await inv.lock_writes(db)
            row = await inv.delete_record(db, kind, row_id)
            destination = {"asset": "/ui/inventory", "subnet": "/ui/inventory/networks"}.get(kind)
            if destination is None:
                destination = (f"/ui/inventory/networks/{row.subnet_id}" if kind == "allocation"
                               else f"/ui/inventory/assets/{row.asset_id}")
            await audit.record(db, tool=f"inventory.{kind}.delete", decision="deleted", detail={"id": row_id})
    except (inv.InventoryError, IntegrityError) as exc:
        error = str(exc) if isinstance(exc, inv.InventoryError) else "This record is still in use."
        return redirect(str(form.get("next", "/ui/inventory")), error)
    return redirect(destination, "Record removed from inventory.")
