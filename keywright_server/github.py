"""Selected repository imports and recoverable inbound-only GitHub synchronization."""
import asyncio
import logging
import random
import re
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import urlencode

from pydantic import Field
from sqlalchemy import delete, func, select

from . import audit, mcp_oauth, repositories, tasks
from .db import session
from .github_client import Client, GitHubError
from .models import (
    Board,
    ExternalIssue,
    GitHubCache,
    GitHubConnection,
    GitHubDiscussionPage,
    GitHubIgnoredRepository,
    GitHubSync,
    Project,
    Repository,
    Task,
    TaskActivity,
    new_id,
    now,
)

log = logging.getLogger(__name__)


class ConnectionSave(tasks.Input):
    name: str = Field(min_length=1, max_length=120)
    token: str = Field(default='', max_length=512)
    enabled: bool = True
    expected_version: int | None = Field(default=None, ge=1)


class Selection(tasks.Input):
    owner: str = Field(pattern=r'^[A-Za-z0-9_.-]{1,100}$')
    name: str = Field(pattern=r'^[A-Za-z0-9_.-]{1,100}$')
    provider_id: str = Field(pattern=r'^\d{1,30}$')
    project_id: str | None = None
    local_repository_id: str | None = None
    new_project_key: str = ''
    new_project_name: str = ''
    import_enabled: bool = True
    include_closed: bool = False


class ImportSettings(tasks.Input):
    expected_version: int = Field(ge=1)
    sync_connection_id: str
    import_enabled: bool = False
    include_closed: bool = False
    poll_seconds: int = Field(default=300, ge=60, le=86400)


def connection_values(row):
    return {key: getattr(row, key) for key in ('id', 'name', 'enabled', 'version', 'status', 'error')}


async def connections(db):
    return [connection_values(row) for row in await db.scalars(select(GitHubConnection).order_by(GitHubConnection.name).limit(50))]


async def save_connection(db, data, connection_id=None):
    await tasks.lock(db)
    if not data.name.strip() or any(ord(c) < 32 for c in data.name + data.token):
        raise tasks.TaskError('invalid_arguments', 'Use a name and a token without control characters.')
    row = await db.get(GitHubConnection, connection_id) if connection_id else GitHubConnection()
    if connection_id and (not row or row.version != data.expected_version):
        raise tasks.TaskError('stale_version', 'Connection changed. Refresh and retry.')
    if not connection_id and await db.scalar(select(func.count()).select_from(GitHubConnection)) >= 50:
        raise tasks.TaskError('invalid_arguments', 'This installation supports up to 50 named connections.')
    if not data.token and not connection_id:
        raise tasks.TaskError('invalid_arguments', 'Provide a fine-grained personal access token.')
    row.name, row.enabled = data.name.strip(), data.enabled
    if data.token:
        row.sealed_data = mcp_oauth.seal({'token': data.token})
    row.version = row.version + 1 if connection_id else 1
    row.status, row.error, row.retry_at = 'untested' if row.enabled else 'disabled', '', None
    db.add(row)
    await db.flush()
    await db.execute(delete(GitHubCache).where(GitHubCache.connection_id == row.id))
    await audit.record(db, tool='work.github.connection', decision='saved', detail={'connection_id': row.id}, commit=False)
    await tasks.commit(db, 'github')
    return connection_values(row)


async def test_connection(connection_id):
    client = Client(connection_id)
    payload, _ = await client.get('/user/repos?per_page=1')
    if not isinstance(payload, list):
        raise GitHubError('invalid_response', 'GitHub returned invalid repository data.')
    async with session() as db:
        row = await db.get(GitHubConnection, connection_id)
        if row.version != client.version:
            raise GitHubError('changed', 'Connection changed. Test again.')
        row.tested_at = now()
        await audit.record(db, tool='work.github.test', decision='success', detail={'connection_id': row.id})
    return 'Connection works. Verify Issues read access by importing a selected repository.'


def identifier(value):
    value = str(value)
    if not re.fullmatch(r'\d{1,30}', value):
        raise GitHubError('invalid_response', 'GitHub returned an invalid source identity.')
    return value


def slug(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', value):
        raise GitHubError('invalid_response', 'GitHub returned an invalid repository name.')
    return value


def text(value, limit=4000):
    return str(value or '')[:limit]


def metadata(data):
    owner, name = slug(data['owner']['login']), slug(data['name'])
    return {'id': identifier(data['id']), 'node_id': text(data.get('node_id'), 240), 'owner': owner, 'name': name,
            'full_name': owner + '/' + name, 'description': text(data.get('description')),
            'web_url': f'https://github.com/{owner}/{name}',
            'clone_url': f'https://github.com/{owner}/{name}.git', 'ssh_url': f'git@github.com:{owner}/{name}.git',
            'default_branch': text(data.get('default_branch'), 240),
            'visibility': 'private' if data.get('private') else 'public',
            'archived': bool(data.get('archived')), 'disabled': bool(data.get('disabled'))}


async def catalog_page(connection_id, page):
    if not 1 <= page <= 10000:
        raise tasks.TaskError('invalid_arguments', 'Invalid repository page.')
    client = Client(connection_id)
    payload, next_url = await client.get('/user/repos?' + urlencode({
        'per_page': 100, 'page': page, 'sort': 'full_name', 'direction': 'asc'}))
    if not isinstance(payload, list) or len(payload) > 100:
        raise GitHubError('invalid_response', 'GitHub returned invalid repository data.')
    return [metadata(r) for r in payload], next_url, client.version


async def discover(connection_id, page=1, q='', owner='', show_ignored=False):
    rows, next_url, _ = await catalog_page(connection_id, page)
    ids = [r['id'] for r in rows]
    async with session() as db:
        ignored = set(await db.scalars(select(GitHubIgnoredRepository.provider_id).where(
            GitHubIgnoredRepository.provider_host == 'github.com', GitHubIgnoredRepository.provider_id.in_(ids))))
        registered = {r.provider_id: r.id for r in await db.scalars(select(Repository).where(
            Repository.provider_host == 'github.com', Repository.provider_id.in_(ids)))}
    return {'repositories': [{**r, 'ignored': r['id'] in ignored, 'registered_id': registered.get(r['id'])}
                            for r in rows if (show_ignored or r['id'] not in ignored)
                            and q.casefold() in (r['full_name'] + ' ' + r['description']).casefold()
                            and (not owner or owner.casefold() == r['owner'].casefold())],
            'next_page': page + 1 if next_url else None, 'page': page,
            'ignored_on_page': len(ignored)}


async def select_repository(connection_id, data: Selection):
    client = Client(connection_id)
    source, _ = await client.get(f'/repos/{data.owner}/{data.name}')
    meta = metadata(source)
    if meta['id'] != data.provider_id:
        raise tasks.TaskError('conflict', 'Repository identity changed. Refresh the picker.')
    async with session() as db:
        return await register_repository(db, connection_id, client.version, meta, data)


async def register_repository(db, connection_id, connection_version, meta, data, *, minimal=False):
    await tasks.lock(db)
    connection = await db.get(GitHubConnection, connection_id)
    if not connection or not connection.enabled or connection.version != connection_version:
        raise tasks.TaskError('conflict', 'Connection changed. Refresh the picker.')
    row = await db.scalar(select(Repository).where(Repository.provider_host == 'github.com', Repository.provider_id == meta['id']))
    if row:
        # Discovering through another connection must not reassign ownership or credentials.
        await db.execute(delete(GitHubIgnoredRepository).where(
            GitHubIgnoredRepository.provider_host == 'github.com', GitHubIgnoredRepository.provider_id == meta['id']))
        await tasks.commit(db, 'github')
        return {'id': row.id, 'existing': True}
    if data.new_project_key:
        if data.project_id:
            raise tasks.TaskError('invalid_arguments', 'Choose an existing project or create a new one.')
        project_data = tasks.ProjectCreate(key=data.new_project_key, name=data.new_project_name)
        if await db.scalar(select(Project.id).where(Project.key == project_data.key)):
            raise tasks.TaskError('conflict', 'Project key is already in use.')
        project = Project(**project_data.model_dump())
        db.add(project)
        await db.flush()
        db.add(Board(key='project_' + project.id, name=project.name, kind='project', project_id=project.id))
        project_id = project.id
    else:
        project_id = data.project_id
    if project_id:
        project = await db.get(Project, project_id)
        if not project or project.archived:
            raise tasks.TaskError('invalid_arguments', 'Choose an active project.')
    row = await db.get(Repository, data.local_repository_id) if data.local_repository_id else None
    if data.local_repository_id and (not row or row.provider_id):
        raise tasks.TaskError('invalid_arguments', 'Choose a manually registered repository without a provider identity.')
    if row:
        # Explicitly attach to manual metadata to preserve all environment location IDs.
        if not project_id:
            project_id = row.project_id
        row.version += 1
    else:
        row = Repository(name=meta['name'] if minimal else meta['full_name'][:120],
                         description='' if minimal else meta['description'], project_id=project_id)
        db.add(row)
    row.project_id, row.web_url = project_id, meta['web_url']
    row.provider_host, row.provider_id, row.sync_connection_id = 'github.com', meta['id'], connection_id
    row.source_metadata, row.last_refreshed_at = meta, now()
    row.import_enabled, row.include_closed = bool(project_id and data.import_enabled), data.include_closed
    await db.flush()
    db.add(GitHubSync(repository_id=row.id, status='queued' if row.import_enabled else 'paused'))
    await db.execute(delete(GitHubIgnoredRepository).where(
        GitHubIgnoredRepository.provider_host == 'github.com', GitHubIgnoredRepository.provider_id == meta['id']))
    await audit.record(db, tool='work.github.select', decision='saved', detail={'repository_id': row.id}, commit=False)
    await tasks.commit(db, 'repository', repository_id=row.id)
    return {'id': row.id, 'existing': False}

class PickerAction(tasks.Input):
    action: Literal['add', 'ignore', 'restore']
    provider_ids: list[str] = Field(min_length=1, max_length=100)
    page: int = Field(default=1, ge=1, le=10000)


async def picker_action(connection_id, data: PickerAction):
    ids = list(dict.fromkeys(identifier(value) for value in data.provider_ids))
    if data.action == 'add':
        # One authenticated catalog request for the whole batch, never one request per row.
        rows, _, version = await catalog_page(connection_id, data.page)
        by_id = {r['id']: r for r in rows}
        results = []
        for provider_id in ids:
            meta = by_id.get(provider_id)
            if meta is None:
                results.append({'id': provider_id, 'status': 'failed', 'message': 'Repository moved off this page. Refresh and retry.'})
                continue
            try:
                async with session() as db:
                    result = await register_repository(db, connection_id, version, meta, Selection(
                        owner=meta['owner'], name=meta['name'], provider_id=provider_id, import_enabled=False), minimal=True)
                results.append({'id': provider_id, 'status': 'already_added' if result['existing'] else 'added'})
            except tasks.TaskError as exc:
                results.append({'id': provider_id, 'status': 'failed', 'message': str(exc)})
        return results
    async with session() as db:
        await tasks.lock(db)
        if not await db.get(GitHubConnection, connection_id):
            raise tasks.TaskError('not_found', 'GitHub connection not found.')
        results = []
        for provider_id in ids:
            row = await db.get(GitHubIgnoredRepository, ('github.com', provider_id))
            if data.action == 'restore':
                if row:
                    await db.delete(row)
                status = 'restored'
            else:
                if row is None:
                    db.add(GitHubIgnoredRepository(provider_id=provider_id))
                status = 'ignored'
            results.append({'id': provider_id, 'status': status})
        await audit.record(db, tool='work.github.picker.' + data.action, decision='saved',
                           detail={'connection_id': connection_id, 'count': len(ids)}, commit=False)
        await tasks.commit(db, 'github')
        return results


async def configure_import(db, repository_id, data: ImportSettings):
    await tasks.lock(db)
    row = await repositories.require_repo(db, repository_id)
    if row.version != data.expected_version:
        raise tasks.TaskError('stale_version', 'Repository changed. Refresh and retry.', row.version)
    connection = await db.get(GitHubConnection, data.sync_connection_id)
    if not connection or not row.provider_id:
        raise tasks.TaskError('invalid_arguments', 'Select a GitHub connection for an imported repository.')
    if data.import_enabled and not row.project_id:
        raise tasks.TaskError('invalid_arguments', 'Select an owning project before enabling issue import.')
    for key, value in data.model_dump(exclude={'expected_version'}).items():
        setattr(row, key, value)
    row.version += 1
    job = await db.get(GitHubSync, row.id)
    # Changing configuration fences any running request/page before its next commit.
    job.status, job.run_id, job.force_full, job.next_attempt = 'queued' if row.import_enabled else 'paused', '', True, now()
    await audit.record(db, tool='work.github.configure', decision='saved', detail={'repository_id': row.id}, commit=False)
    await tasks.commit(db, 'repository', repository_id=row.id)


async def eligible(db, repo):
    project = await db.get(Project, repo.project_id) if repo.project_id else None
    connection = await db.get(GitHubConnection, repo.sync_connection_id) if repo.sync_connection_id else None
    return bool(repo.import_enabled and not repo.archived and project and not project.archived and connection and connection.enabled)


async def enqueue(db, repository_id, full=False):
    await tasks.lock(db)
    repo = await repositories.require_repo(db, repository_id)
    if not await eligible(db, repo):
        raise tasks.TaskError('invalid_transition', 'Enable import on an active project and GitHub connection first.')
    job = await db.get(GitHubSync, repo.id)
    if job.status not in ('queued', 'running'):
        job.status, job.next_attempt, job.error = 'queued', now(), ''
    if full:
        job.force_full = True
    await tasks.commit(db, 'github', repository_id=repo.id)


def timestamp(value):
    try:
        at = datetime.fromisoformat(value)
        if at.tzinfo is None:
            raise ValueError
        return at.astimezone(UTC)
    except (ValueError, AttributeError):
        raise GitHubError('invalid_response', 'GitHub returned an invalid issue timestamp.') from None


def issue_snapshot(data, repo):
    number = int(data['number'])
    if number <= 0 or data.get('state') not in ('open', 'closed'):
        raise GitHubError('invalid_response', 'GitHub returned invalid issue data.')
    meta = repo.source_metadata
    milestone = data.get('milestone') or {}
    return {'id': identifier(data['id']), 'node_id': text(data.get('node_id'), 240), 'number': number,
            'url': f"https://github.com/{meta['owner']}/{meta['name']}/issues/{number}",
            'title': text(data.get('title'), 240) or f'Issue #{number}', 'body': text(data.get('body'), 64000),
            'body_truncated': len(str(data.get('body') or '')) > 64000,
            'state': data['state'], 'state_reason': text(data.get('state_reason'), 100),
            'author': text((data.get('user') or {}).get('login'), 100),
            'labels': [text(label.get('name') if isinstance(label, dict) else label, 100) for label in data.get('labels', [])[:100]],
            'assignees': [text(a.get('login'), 100) for a in data.get('assignees', [])[:100]],
            'milestone': {'id': str(milestone.get('id', '')), 'title': text(milestone.get('title'), 240),
                          'state': text(milestone.get('state'), 100)},
            'created_at': text(data.get('created_at'), 60), 'updated_at': text(data.get('updated_at'), 60),
            'closed_at': text(data.get('closed_at'), 60)}


async def apply_issue(db, repo, raw):
    if 'pull_request' in raw:
        return 0, 0
    snapshot = issue_snapshot(raw, repo)
    updated_at = timestamp(raw['updated_at'])
    source = await db.scalar(select(ExternalIssue).where(ExternalIssue.provider_host == 'github.com',
                                                       ExternalIssue.provider_id == snapshot['id']))
    if source and updated_at < source.source_updated_at:
        return 0, 0
    changed = bool(source and (source.snapshot != snapshot or source.repository_id != repo.id))
    old_state = source.snapshot['state'] if source else None
    if source is None:
        source = ExternalIssue(provider_id=snapshot['id'], repository_id=repo.id, number=snapshot['number'],
                               source_updated_at=updated_at, snapshot=snapshot)
        db.add(source)
    source.snapshot, source.source_updated_at, source.refreshed_at = snapshot, updated_at, now()
    source.repository_id, source.number = repo.id, snapshot['number']
    imported = 0
    if not source.task_id and (snapshot['state'] == 'open' or repo.include_closed):
        board = await db.scalar(select(Board).where(Board.project_id == repo.project_id))
        status = 'done' if snapshot['state'] == 'closed' else 'backlog'
        position = await db.scalar(select(func.max(Task.position)).where(Task.board_id == board.id, Task.status == status))
        task = Task(board_id=board.id, title=snapshot['title'], creator='github', status=status, position=(position or 0) + 1024)
        db.add(task)
        await db.flush()
        source.task_id = task.id
        db.add(TaskActivity(task_id=task.id, actor='github', kind='imported', data={'source_state': snapshot['state']}))
        imported = 1
    elif source.task_id:
        task = await db.get(Task, source.task_id)
        task.title = snapshot['title']  # Source title is mirrored for search; local version is untouched.
        if old_state != snapshot['state']:
            db.add(TaskActivity(task_id=task.id, actor='github', kind='source_state',
                               data={'from': old_state, 'to': snapshot['state'], 'reason': snapshot['state_reason']}))
    return imported, int(changed)


async def check_run(db, repository_id, run_id, repo_version, connection_version):
    repo = await db.get(Repository, repository_id, populate_existing=True)
    job = await db.get(GitHubSync, repository_id, populate_existing=True)
    connection = await db.get(GitHubConnection, repo.sync_connection_id) if repo else None
    if (not repo or not job or job.run_id != run_id or job.status != 'running' or repo.version != repo_version
            or not connection or connection.version != connection_version or not await eligible(db, repo)):
        raise GitHubError('changed', 'Synchronization paused or configuration changed. Retry when ready.')
    return repo, job


async def run_sync(repository_id):
    async with session() as db:
        await tasks.lock(db)
        repo = await repositories.require_repo(db, repository_id)
        job = await db.get(GitHubSync, repo.id)
        if not job or job.status == 'running' or job.next_attempt > now() or not await eligible(db, repo):
            return
        connection = await db.get(GitHubConnection, repo.sync_connection_id)
        if connection.retry_at and connection.retry_at > now():
            job.next_attempt = connection.retry_at
            await db.commit()
            return
        run_id, started = new_id('ghrun'), now()
        full = job.force_full or not job.last_full or job.last_full < started - timedelta(days=1)
        since = job.watermark - timedelta(minutes=5) if job.watermark and not full else None
        job.run_id, job.status, job.started_at, job.imported, job.updated = run_id, 'running', started, 0, 0
        job.error, job.force_full = '', False
        repo_version, connection_version = repo.version, connection.version
        connection_id, meta, provider_id = repo.sync_connection_id, repo.source_metadata, repo.provider_id
        await tasks.commit(db, 'github', repository_id=repo.id)
    client = Client(connection_id)
    client.version = connection_version
    try:
        raw, _ = await client.get(f"/repos/{slug(meta['owner'])}/{slug(meta['name'])}")
        refreshed = metadata(raw)
        if refreshed['id'] != provider_id:
            raise GitHubError('unavailable', 'Repository identity changed. Review its GitHub configuration.')
        async with session() as db:
            await tasks.lock(db)
            repo, job = await check_run(db, repository_id, run_id, repo_version, connection_version)
            repo.source_metadata, repo.web_url, repo.last_refreshed_at = refreshed, refreshed['web_url'], now()
            await db.commit()
        params = {'state': 'all', 'sort': 'updated', 'direction': 'asc', 'per_page': 100}
        if since:
            params['since'] = since.isoformat()
        url = f"/repos/{refreshed['owner']}/{refreshed['name']}/issues?" + urlencode(params)
        seen = set()
        for _ in range(1000):
            if url in seen:
                raise GitHubError('invalid_response', 'GitHub pagination repeated a page. Retry the sync.')
            seen.add(url)
            payload, next_url = await client.get(url)
            if not isinstance(payload, list) or len(payload) > 100:
                raise GitHubError('invalid_response', 'GitHub returned an invalid issue page.')
            async with session() as db:
                await tasks.lock(db)
                repo, job = await check_run(db, repository_id, run_id, repo_version, connection_version)
                for issue in payload:
                    imported, updated = await apply_issue(db, repo, issue)
                    job.imported += imported
                    job.updated += updated
                await tasks.commit(db, 'github', repository_id=repo.id)
            if not next_url:
                break
            url = next_url
        else:
            raise GitHubError('invalid_response', 'Sync exceeded 1,000 pages; narrow the repository scope and retry.')
        async with session() as db:
            await tasks.lock(db)
            repo, job = await check_run(db, repository_id, run_id, repo_version, connection_version)
            job.status, job.watermark, job.last_success, job.failures = 'success', started, now(), 0
            if full:
                job.last_full = started
            job.source_available, job.next_attempt = True, now() + timedelta(seconds=repo.poll_seconds)
            await audit.record(db, tool='work.github.sync', decision='success', detail={
                'repository_id': repo.id, 'imported': job.imported, 'updated': job.updated}, commit=False)
            await tasks.commit(db, 'github', repository_id=repo.id)
    except Exception as exc:  # noqa: BLE001 — preserve work and redact transport/source diagnostics.
        error = exc if isinstance(exc, GitHubError) else GitHubError('transient', 'GitHub synchronization failed. Retry or check the source.')
        async with session() as db:
            await tasks.lock(db)
            job = await db.get(GitHubSync, repository_id)
            if job and job.run_id == run_id:
                job.failures += 1
                job.status, job.error = 'error', str(error)
                job.source_available = error.code not in ('credentials', 'unavailable', 'paused')
                job.next_attempt = error.retry_at or now() + timedelta(seconds=min(3600, 30 * 2 ** min(job.failures, 7)) + random.uniform(0, 10))
                # A failed full scan must remain full on retry, including after restart.
                job.force_full = job.force_full or full
                await audit.record(db, tool='work.github.sync', decision='error', detail={
                    'repository_id': repository_id, 'code': error.code}, commit=False)
                await tasks.commit(db, 'github', repository_id=repository_id)


async def recover_jobs():
    async with session() as db:
        await tasks.lock(db)
        for job in await db.scalars(select(GitHubSync).where(GitHubSync.status == 'running')):
            job.status, job.error, job.next_attempt, job.force_full = 'queued', 'Interrupted sync will retry.', now(), True
        await db.commit()


async def poll_once():
    async with session() as db:
        ids = list(await db.scalars(select(GitHubSync.repository_id).join(
            Repository, Repository.id == GitHubSync.repository_id).join(Project, Project.id == Repository.project_id)
            .join(GitHubConnection, GitHubConnection.id == Repository.sync_connection_id).where(
            GitHubSync.next_attempt <= now(), GitHubSync.status != 'running', Repository.import_enabled.is_(True),
            Repository.archived.is_(False), Project.archived.is_(False), GitHubConnection.enabled.is_(True))
            .order_by(GitHubSync.next_attempt).limit(20)))
    for repository_id in ids:
        async with session() as db:
            repo = await db.get(Repository, repository_id)
            if not await eligible(db, repo):
                continue
        await run_sync(repository_id)


async def worker():
    await recover_jobs()
    while True:
        try:
            await poll_once()
        except Exception:  # noqa: BLE001 — do not log private transport details.
            log.warning('GitHub worker interrupted; retrying on the next pass')
        await asyncio.sleep(15)


async def discussion(db, task_id, page=1, agent=None):
    await tasks.get_task(db, task_id, agent)
    source = await db.scalar(select(ExternalIssue).where(ExternalIssue.task_id == task_id))
    if not source:
        raise tasks.TaskError('not_found', 'Task has no GitHub issue.')
    row = await db.scalar(select(GitHubDiscussionPage).where(GitHubDiscussionPage.issue_id == source.id,
                                                          GitHubDiscussionPage.page == page))
    return {'comments': row.comments if row else [], 'has_next': row.has_next if row else False,
            'refreshed_at': row.refreshed_at.isoformat() if row else None, 'page': page}


async def refresh_discussion(task_id, page=1):
    if not 1 <= page <= 1000:
        raise tasks.TaskError('invalid_arguments', 'Discussion page must be between 1 and 1,000.')
    async with session() as db:
        await tasks.get_task(db, task_id)
        source = await db.scalar(select(ExternalIssue).where(ExternalIssue.task_id == task_id))
        if not source:
            raise tasks.TaskError('not_found', 'Task has no GitHub issue.')
        repo = await db.get(Repository, source.repository_id)
        source_id, repo_id, number, version = source.id, repo.id, source.number, repo.version
        meta = repo.source_metadata
        client = Client(repo.sync_connection_id)
    # Construct all URLs from validated identities, never from source bodies/links.
    raw, next_url = await client.get(f"/repos/{slug(meta['owner'])}/{slug(meta['name'])}/issues/{number}/comments?per_page=100&page={page}")
    if not isinstance(raw, list) or len(raw) > 100:
        raise GitHubError('invalid_response', 'GitHub returned invalid discussion data.')
    comments = [{'id': identifier(c['id']), 'author': text((c.get('user') or {}).get('login'), 100),
                 'body': text(c.get('body'), 64000), 'updated_at': text(c.get('updated_at'), 60)} for c in raw]
    async with session() as db:
        await tasks.lock(db)
        repo = await db.get(Repository, repo_id)
        connection = await db.get(GitHubConnection, repo.sync_connection_id)
        source = await db.get(ExternalIssue, source_id)
        if repo.version != version or connection.version != client.version or not connection.enabled or source.repository_id != repo_id:
            raise tasks.TaskError('conflict', 'Source changed during discussion refresh. Retry.')
        row = await db.scalar(select(GitHubDiscussionPage).where(GitHubDiscussionPage.issue_id == source_id,
                                                              GitHubDiscussionPage.page == page))
        if row is None:
            row = GitHubDiscussionPage(issue_id=source_id, page=page)
            db.add(row)
        row.comments, row.has_next, row.refreshed_at = comments, bool(next_url), now()
        await db.flush()
        # Cache at most ten discussion pages per issue; older pages may be loaded again.
        old = list(await db.scalars(select(GitHubDiscussionPage.id).where(GitHubDiscussionPage.issue_id == source_id)
                    .order_by(GitHubDiscussionPage.refreshed_at.desc()).offset(10).limit(1000)))
        if old:
            await db.execute(delete(GitHubDiscussionPage).where(GitHubDiscussionPage.id.in_(old)))
        await audit.record(db, tool='work.github.discussion', decision='refreshed', detail={'task_id': task_id}, commit=False)
        await tasks.commit(db, 'github', task_id=task_id)
