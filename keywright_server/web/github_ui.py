"""Authenticated owner controls for inbound GitHub connections and synchronization."""
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from pydantic import ValidationError

from .. import github, tasks
from ..db import session
from ..github_client import GitHubError
from ..models import GitHubSync
from . import auth
from .admin import redirect, render
from .security import require_same_origin
from .work_ui import error

router = APIRouter(dependencies=[Depends(require_same_origin), Depends(auth.require_admin)])
ERRORS = (tasks.TaskError, ValidationError, ValueError, KeyError)


def failure(exc):
    if isinstance(exc, GitHubError):
        return error(tasks.TaskError(exc.code, str(exc)))
    return error(exc)


@router.get('/ui/work/github')
@router.get('/ui/integrations/github')
async def home(request: Request):
    if request.url.path == '/ui/work/github':
        return redirect('/ui/integrations/github')
    async with session() as db:
        connections = await github.connections(db)
    return render(request, 'work_github.html', connections=connections)


@router.post('/ui/work/github/connections')
@router.post('/ui/integrations/github/connections')
@router.post('/ui/work/github/connections/{connection_id}')
@router.post('/ui/integrations/github/connections/{connection_id}')
async def save(request: Request, connection_id: str | None = None):
    try:
        form = dict(await request.form())
        form['enabled'] = form.get('enabled') == 'on'
        async with session() as db:
            await github.save_connection(db, github.ConnectionSave(**form), connection_id)
        return redirect('/ui/integrations/github', 'GitHub connection saved.')
    except ERRORS as exc:
        return failure(exc)


@router.post('/ui/work/github/connections/{connection_id}/test')
@router.post('/ui/integrations/github/connections/{connection_id}/test')
async def test(connection_id: str):
    try:
        message = await github.test_connection(connection_id)
        return redirect('/ui/integrations/github', message)
    except ERRORS as exc:
        return failure(exc)


@router.get('/ui/work/github/connections/{connection_id}/repositories')
@router.get('/ui/integrations/github/connections/{connection_id}/repositories')
async def picker(request: Request, connection_id: str, page: int = 1, q: str = '', owner: str = '',
                 show_ignored: bool = False):
    if request.url.path.startswith('/ui/work/github/'):
        return redirect(f'/ui/integrations/github/connections/{connection_id}/repositories?' +
                        urlencode({'page': page, 'q': q[:120], 'owner': owner[:100], 'show_ignored': str(show_ignored).lower()}))
    try:
        result = await github.discover(connection_id, page, q[:120], owner[:100], show_ignored)
        def page_url(number):
            return '?' + urlencode({'page': number, 'q': q[:120], 'owner': owner[:100],
                                    'show_ignored': str(show_ignored).lower()})
        return render(request, 'work_github_picker.html', result=result, connection_id=connection_id,
                      q=q[:120], owner=owner[:100], show_ignored=show_ignored, page_url=page_url)
    except ERRORS as exc:
        return failure(exc)


@router.post('/ui/integrations/github/connections/{connection_id}/repositories/actions')
async def picker_action(request: Request, connection_id: str):
    try:
        form = await request.form()
        action, _, row_id = str(form.get('action', '')).partition(':')
        ids = [row_id] if row_id else form.getlist('selected')
        data = github.PickerAction(action=action, provider_ids=ids, page=int(str(form.get('page', '1'))))
        results = await github.picker_action(connection_id, data)
        labels = {'added': 'added', 'ignored': 'ignored', 'restored': 'restored',
                  'already_added': 'already added (unchanged)', 'failed': 'could not be added'}
        counts = {key: sum(r['status'] == key for r in results) for key in labels}
        message = '; '.join(f'{count} {labels[key]}' for key, count in counts.items() if count) + '.'
        if counts['added']:
            message += ' Optional settings are blank; choose a project and enable issue import when ready.'
        if counts['failed']:
            message += ' Unadded rows remain available. Refresh and retry.'
        query = urlencode({'page': data.page, 'q': str(form.get('q', ''))[:120],
                           'owner': str(form.get('owner', ''))[:100],
                           'show_ignored': str(form.get('show_ignored', 'false') == 'true').lower()})
        return redirect(f'/ui/integrations/github/connections/{connection_id}/repositories?' + query, message)
    except ERRORS as exc:
        return failure(exc)


@router.post('/ui/work/github/connections/{connection_id}/select')
@router.post('/ui/integrations/github/connections/{connection_id}/select')
async def select_repository(request: Request, connection_id: str):
    try:
        form = dict(await request.form())
        for key in ('project_id', 'local_repository_id'):
            form[key] = form.get(key) or None
        for key in ('import_enabled', 'include_closed'):
            form[key] = form.get(key) == 'on'
        result = await github.select_repository(connection_id, github.Selection(**form))
        return redirect('/ui/work/repositories/' + result['id'],
                        'Already registered; existing ownership and sync connection were retained.' if result['existing'] else 'Repository selected.')
    except ERRORS as exc:
        return failure(exc)


@router.post('/ui/work/repositories/{repository_id}/github')
async def configure(request: Request, repository_id: str):
    try:
        form = dict(await request.form())
        for key in ('import_enabled', 'include_closed'):
            form[key] = form.get(key) == 'on'
        async with session() as db:
            await github.configure_import(db, repository_id, github.ImportSettings(**form))
        return redirect('/ui/work/repositories/' + repository_id, 'GitHub import settings saved.')
    except ERRORS as exc:
        return failure(exc)


@router.post('/ui/work/repositories/{repository_id}/sync')
async def sync(request: Request, repository_id: str):
    try:
        form = await request.form()
        async with session() as db:
            await github.enqueue(db, repository_id, full=form.get('full') == 'on')
        return redirect('/ui/work/repositories/' + repository_id, 'Synchronization queued; refresh this page for progress.')
    except ERRORS as exc:
        return failure(exc)


@router.get('/api/work/repositories/{repository_id}/sync')
async def sync_status(repository_id: str):
    async with session() as db:
        job = await db.get(GitHubSync, repository_id)
        if not job:
            return error(tasks.TaskError('not_found', 'No GitHub sync is configured.'))
        return {key: getattr(job, key) for key in ('status', 'last_success', 'started_at', 'watermark',
                                                  'imported', 'updated', 'error', 'next_attempt')}


@router.get('/ui/work/tasks/{task_id}/github-discussion')
async def discussion(request: Request, task_id: str, page: int = 1):
    try:
        if not 1 <= page <= 1000:
            raise ValueError
        async with session() as db:
            task = await tasks.get_task(db, task_id)
            data = await github.discussion(db, task_id, page)
        return render(request, 'work_github_discussion.html', task=task, discussion=data)
    except ERRORS as exc:
        return failure(exc)


@router.post('/ui/work/tasks/{task_id}/github-discussion')
async def refresh_discussion(request: Request, task_id: str):
    try:
        form = await request.form()
        page = int(str(form.get('page', '1')))
        await github.refresh_discussion(task_id, page)
        return redirect(f'/ui/work/tasks/{task_id}/github-discussion?page={page}', 'GitHub discussion refreshed.')
    except ERRORS as exc:
        return failure(exc)
