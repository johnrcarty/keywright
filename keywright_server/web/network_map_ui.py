"""Admin-only network map; controller reads share discovery's audit and locking."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from .. import discovery, inventory, network_map
from ..db import session
from . import auth
from .admin import render
from .security import require_same_origin

router = APIRouter(dependencies=[Depends(require_same_origin), Depends(auth.require_admin)])


@router.get('/ui/inventory/map')
async def network_map_page(request: Request, source: str = ''):
    async with session() as db:
        graph = await network_map.snapshot(db, source)
    return render(request, 'inventory_map.html', graph=graph)


@router.get('/ui/inventory/map/data')
async def network_map_data(source: str = ''):
    async with session() as db:
        return await network_map.snapshot(db, source)


@router.post('/ui/inventory/map/refresh')
async def network_map_refresh(request: Request):
    form = await request.form()
    try:
        source = inventory.value(form, 'resource_id', required=True)
        run = await discovery.refresh(source, 'omada', min_interval=network_map.REFRESH_SECONDS)
    except (discovery.DiscoveryError, inventory.InventoryError) as exc:
        return JSONResponse({'error': str(exc)}, status_code=409)
    async with session() as db:
        graph = await network_map.snapshot(db, source)
    return JSONResponse(graph, status_code=200 if run.status == 'succeeded' else 502)
