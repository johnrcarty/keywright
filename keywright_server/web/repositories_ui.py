"""Owner-only repository configuration and explicit host verification."""
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from pydantic import ValidationError
from sqlalchemy import select

from .. import github, tasks
from .. import repositories as repos
from ..db import session
from ..models import Board, GitHubSync, InventoryAsset, Project, RepositoryLocation, Resource
from . import auth
from .admin import redirect, render
from .security import require_same_origin
from .work_ui import error

router = APIRouter(dependencies=[Depends(require_same_origin), Depends(auth.require_admin)])
ERRORS = (tasks.TaskError, ValidationError, ValueError, KeyError)


async def body(request):
    data = await request.json()
    if not isinstance(data, dict):
        raise tasks.TaskError('invalid_arguments', 'Expected a JSON object.')
    return data


async def projects(db):
    return list(await db.scalars(select(Project).order_by(Project.name).limit(500)))


@router.get('/ui/work/repositories')
async def home(request: Request):
    try:
        data = repos.RepositoryFilter(**{k: v for k, v in request.query_params.items() if v})
        async with session() as db:
            result = await repos.list_repositories(db, data)
            options = await projects(db)
            board = await db.scalar(select(Board).where(Board.project_id == data.project_id)) if data.project_id else None
        return render(request, 'work_repositories.html', result=result, filters=data, projects=options, board=board,
                      page_url=lambda offset: '/ui/work/repositories?' + urlencode({**dict(request.query_params), 'offset': offset}))
    except ERRORS as exc:
        return error(exc)


@router.get('/ui/work/repositories/{repository_id}')
async def detail(request: Request, repository_id: str):
    try:
        args = repos.Locations(repository_id=repository_id, **{k: v for k, v in request.query_params.items()
                                                              if k in ('offset', 'limit', 'environment') and v})
        async with session() as db:
            repo = repos.repo_values(await repos.require_repo(db, repository_id), True)
            locations = await repos.list_locations(db, args)
            sync = await db.get(GitHubSync, repository_id)
            sync_paused = bool(repo["provider_id"] and not await github.eligible(db, await repos.require_repo(db, repository_id)))
            connections = await github.connections(db)
            options = await projects(db)
            assets = list(await db.scalars(select(InventoryAsset).order_by(InventoryAsset.name).limit(500)))
            resources = list(await db.scalars(select(Resource).where(Resource.kind == 'ssh').order_by(Resource.name).limit(500)))
            board = await db.scalar(select(Board).where(Board.project_id == repo['project_id'])) if repo['project_id'] else None
            edit = None
            if request.query_params.get('edit'):
                row = await db.get(RepositoryLocation, request.query_params['edit'])
                if not row or row.repository_id != repository_id:
                    raise tasks.TaskError('not_found', 'Location not found.')
                edit = await repos.location_values(db, row, await repos.require_repo(db, repository_id))
        return render(request, 'work_repository.html', repo=repo, locations=locations, projects=options, board=board,
                      assets=assets, resources=resources, edit=edit, args=args, sync=sync, sync_paused=sync_paused, connections=connections,
                      page_url=lambda offset: f'/ui/work/repositories/{repository_id}?' + urlencode({
                          'offset': offset, 'environment': args.environment or ''}))
    except ERRORS as exc:
        return error(exc)


def repository_form(form):
    values = dict(form)
    values['project_id'] = values.get('project_id') or None
    values['archived'] = values.get('archived') == 'on'
    return repos.RepositorySave(**values)


def location_form(form):
    values = dict(form)
    values['asset_id'], values['resource_id'] = values.get('asset_id') or None, values.get('resource_id') or None
    values['is_primary'] = values.get('is_primary') == 'on'
    return repos.LocationSave(**values)


@router.post('/ui/work/repositories')
@router.post('/ui/work/repositories/{repository_id}')
async def save_repo(request: Request, repository_id: str | None = None):
    try:
        data = repository_form(await request.form())
        async with session() as db:
            result = await repos.save_repository(db, data, repository_id)
        return redirect('/ui/work/repositories/' + result['id'], 'Repository saved.')
    except ERRORS as exc:
        return error(exc)


@router.post('/ui/work/repositories/{repository_id}/locations')
@router.post('/ui/work/repositories/{repository_id}/locations/{location_id}')
async def save_location(request: Request, repository_id: str, location_id: str | None = None):
    try:
        data = location_form(await request.form())
        async with session() as db:
            await repos.save_location(db, repository_id, data, location_id)
        return redirect('/ui/work/repositories/' + repository_id, 'Location saved. No commands were run.')
    except ERRORS as exc:
        return error(exc)


@router.post('/ui/work/locations/{location_id}/verify')
async def verify(request: Request, location_id: str):
    try:
        form = await request.form()
        result = await repos.verify_location(location_id, int(str(form['expected_version'])))
        return redirect('/ui/work/repositories/' + result['repository_id'], result['verification_message'])
    except ERRORS as exc:
        return error(exc)


@router.get('/api/work/repositories')
async def api_list(request: Request):
    try:
        data = repos.RepositoryFilter(**dict(request.query_params))
        async with session() as db:
            return await repos.list_repositories(db, data)
    except ERRORS as exc:
        return error(exc)


@router.get('/api/work/repositories/{repository_id}')
async def api_get(repository_id: str):
    try:
        async with session() as db:
            return repos.repo_values(await repos.require_repo(db, repository_id), True)
    except ERRORS as exc:
        return error(exc)


@router.post('/api/work/repositories')
@router.put('/api/work/repositories/{repository_id}')
async def api_save(request: Request, repository_id: str | None = None):
    try:
        data = repos.RepositorySave(**await body(request))
        async with session() as db:
            return await repos.save_repository(db, data, repository_id)
    except ERRORS as exc:
        return error(exc)


@router.get('/api/work/repositories/{repository_id}/locations')
async def api_locations(request: Request, repository_id: str):
    try:
        data = repos.Locations(repository_id=repository_id, **dict(request.query_params))
        async with session() as db:
            return await repos.list_locations(db, data)
    except ERRORS as exc:
        return error(exc)


@router.post('/api/work/repositories/{repository_id}/locations')
@router.put('/api/work/repositories/{repository_id}/locations/{location_id}')
async def api_save_location(request: Request, repository_id: str, location_id: str | None = None):
    try:
        data = repos.LocationSave(**await body(request))
        async with session() as db:
            return await repos.save_location(db, repository_id, data, location_id)
    except ERRORS as exc:
        return error(exc)


@router.post('/api/work/locations/{location_id}/verify')
async def api_verify(request: Request, location_id: str):
    try:
        class Verify(tasks.Input):
            expected_version: int
        data = Verify(**await body(request))
        return await repos.verify_location(location_id, data.expected_version)
    except ERRORS as exc:
        return error(exc)
