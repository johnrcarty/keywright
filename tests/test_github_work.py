"""Inbound GitHub invariants: credentials, pagination, identity, recovery and ownership."""
import asyncio
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select

from keywright_server import db as dbm
from keywright_server import github as gh
from keywright_server import repositories, tasks
from keywright_server.github_client import API_VERSION, Client, GitHubError
from keywright_server.models import (
    ExternalIssue,
    GitHubConnection,
    GitHubSync,
    Repository,
    RepositoryLocation,
    Resource,
    Task,
    TaskActivity,
    TaskNotification,
    now,
)


def repository(name='app'):
    return {'id': 123456789012345678, 'node_id': 'repo-node', 'owner': {'login': 'owner'}, 'name': name,
            'description': 'Example repository', 'default_branch': 'main', 'private': True, 'archived': False}


def issue(number=1, state='open', updated='2026-11-01T00:00:00Z', **extra):
    return {'id': 9000 + number, 'node_id': 'node-' + str(number), 'number': number, 'title': 'Issue ' + str(number),
            'body': '<script>danger()</script> ![image](https://tracking.invalid/image)', 'state': state,
            'state_reason': 'completed' if state == 'closed' else None,
            'updated_at': updated, 'created_at': '2026-10-01T00:00:00Z', 'user': {'login': 'author'},
            'labels': [{'name': 'bug'}], 'assignees': [{'login': 'github-user'}], **extra}


async def setup(db, monkeypatch, handler, include_closed=False):
    monkeypatch.setattr(gh, 'Client', lambda connection_id: Client(connection_id, transport=httpx.MockTransport(handler)))
    connection = await gh.save_connection(db, gh.ConnectionSave(name='Personal', token='TEST_PRIVATE_PAT'))
    project = await tasks.create_project(db, tasks.ProjectCreate(key='app', name='Application'))
    selected = await gh.select_repository(connection['id'], gh.Selection(owner='owner', name='app',
        provider_id=str(repository()['id']), project_id=project['project_id'], include_closed=include_closed))
    return connection, project, selected['id']


async def sync(db, repository_id):
    await gh.enqueue(db, repository_id)
    await gh.run_sync(repository_id)
    db.expire_all()
    return await db.get(GitHubSync, repository_id)


async def test_paginated_import_excludes_prs_deduplicates_and_keeps_closed_snapshots(db, monkeypatch):
    requests = []
    def handler(request):
        requests.append(request)
        assert request.method == 'GET' and request.headers['X-GitHub-Api-Version'] == API_VERSION
        assert request.headers['Authorization'] == 'Bearer TEST_PRIVATE_PAT'
        if request.url.path == '/repos/owner/app':
            return httpx.Response(200, json=repository())
        if request.url.params.get('page') != '2':
            assert request.url.params['state'] == 'all' and request.url.params['sort'] == 'updated'
        if request.url.params.get('page') == '2':
            return httpx.Response(200, json=[issue(3), issue(4, pull_request={'url': 'ignored'})])
        return httpx.Response(200, json=[issue(1), issue(2, state='closed')], headers={
            'Link': '<https://api.github.com/repos/owner/app/issues?page=2>; rel="next"'})
    connection, _, repo_id = await setup(db, monkeypatch, handler)
    result = await sync(db, repo_id)
    assert result.status == 'success' and result.imported == 2 and result.watermark
    assert await db.scalar(select(func.count()).select_from(ExternalIssue)) == 3
    assert await db.scalar(select(func.count()).select_from(Task)) == 2
    assert await db.scalar(select(func.count()).select_from(TaskNotification)) == 0
    assert (await gh.connections(db))[0] == connection | {'status': 'connected'}
    row = await db.get(GitHubConnection, connection['id'])
    assert 'TEST_PRIVATE_PAT' not in row.sealed_data
    assert (await sync(db, repo_id)).imported == 0
    assert await db.scalar(select(func.count()).select_from(Task)) == 2
    assert any('since' in req.url.params for req in requests)


async def test_mid_page_failure_does_not_advance_watermark_and_retries_after_restart(db, monkeypatch):
    fail = True
    def handler(request):
        if request.url.path == '/repos/owner/app':
            return httpx.Response(200, json=repository())
        if request.url.params.get('page') == '2':
            return httpx.Response(503) if fail else httpx.Response(200, json=[issue(2)])
        return httpx.Response(200, json=[issue(1)], headers={
            'Link': '<https://api.github.com/repos/owner/app/issues?page=2>; rel="next"'})
    _, _, repo_id = await setup(db, monkeypatch, handler)
    job = await sync(db, repo_id)
    assert job.status == 'error' and job.watermark is None
    assert await db.scalar(select(func.count()).select_from(Task)) == 1
    job.status = 'running'
    await db.commit()
    await gh.recover_jobs()
    fail = False
    await gh.run_sync(repo_id)
    db.expire_all()
    job = await db.get(GitHubSync, repo_id)
    assert job.status == 'success' and job.watermark
    assert await db.scalar(select(func.count()).select_from(Task)) == 2


async def test_source_refresh_preserves_local_fields_moves_archives_and_version(db, monkeypatch):
    current = issue()
    def handler(request):
        return httpx.Response(200, json=repository() if request.url.path == '/repos/owner/app' else [current])
    _, _, repo_id = await setup(db, monkeypatch, handler)
    await sync(db, repo_id)
    task = await db.scalar(select(Task))
    task_id = task.id
    edited = await tasks.update_task(db, task_id, tasks.TaskPatch(expected_version=1, notes='Local plan',
                                    assignee='owner', status='in_progress', priority=1))
    assert edited['source']['provider'] == 'github'
    moved = await tasks.move_task(db, task_id, 'brd_kw', edited['version'])
    current = issue(state='closed', updated='2026-11-02T00:00:00Z', title='Remote title')
    await sync(db, repo_id)
    detail = await tasks.get_task(db, task_id)
    assert detail['title'] == 'Remote title' and detail['source']['state'] == 'closed'
    assert detail['notes'] == 'Local plan' and detail['assignee'] == 'owner' and detail['status'] == 'in_progress'
    assert detail['version'] == moved['version'] and detail['board_id'] == 'brd_kw'
    assert any(a['kind'] == 'source_state' for a in detail['activity'])
    with pytest.raises(tasks.TaskError, match='GitHub owns'):
        await tasks.update_task(db, task_id, tasks.TaskPatch(expected_version=detail['version'], title='Forbidden'))
    await db.rollback()
    await tasks.update_task(db, task_id, tasks.TaskPatch(expected_version=detail['version'], archived=True))
    current = issue(updated='2026-11-03T00:00:00Z')
    await sync(db, repo_id)
    detail = await tasks.get_task(db, task_id)
    assert detail['archived'] and detail['board_id'] == 'brd_kw' and detail['source']['state'] == 'open'
    assert await db.scalar(select(func.count()).select_from(TaskNotification)) == 1
    assert await db.scalar(select(func.count()).select_from(Task)) == 1


async def test_closed_history_reopening_and_older_snapshots(db, monkeypatch):
    data = [issue(1, state='closed'), issue(2, state='closed')]
    def handler(request):
        return httpx.Response(200, json=repository() if request.url.path == '/repos/owner/app' else data)
    connection, _, repo_id = await setup(db, monkeypatch, handler)
    await sync(db, repo_id)
    assert await db.scalar(select(func.count()).select_from(Task)) == 0
    data[0] = issue(1, updated='2026-11-03T00:00:00Z')
    await sync(db, repo_id)
    assert await db.scalar(select(func.count()).select_from(Task)) == 1
    repo = await db.get(Repository, repo_id)
    await gh.configure_import(db, repo_id, gh.ImportSettings(expected_version=repo.version,
        sync_connection_id=connection['id'], import_enabled=True, include_closed=True))
    data[0] = issue(1, state='closed')  # older than the stored reopening
    await sync(db, repo_id)
    tasks_result = await tasks.list_tasks(db, tasks.TaskFilter(include_done=True, source='github'))
    assert {t['status'] for t in tasks_result['tasks']} == {'backlog', 'done'}
    assert (await tasks.list_tasks(db, tasks.TaskFilter(source='local')))['total'] == 0


async def test_rename_replacement_second_connection_and_manual_location_identity(db, monkeypatch):
    name = 'app'
    def handler(request):
        return httpx.Response(200, json=repository(name) if '/issues' not in request.url.path else [issue()])
    monkeypatch.setattr(gh, 'Client', lambda cid: Client(cid, transport=httpx.MockTransport(handler)))
    connection = await gh.save_connection(db, gh.ConnectionSave(name='One', token='OLD'))
    project = await tasks.create_project(db, tasks.ProjectCreate(key='app', name='App'))
    repo = await repositories.save_repository(db, repositories.RepositorySave(name='Manual', project_id=project['project_id']))
    host = Resource(name='Dev', kind='ssh', config={})
    db.add(host)
    await db.commit()
    loc = await repositories.save_location(db, repo['id'], repositories.LocationSave(environment='dev', name='Main',
        resource_id=host.id, directory='/app'))
    selected = await gh.select_repository(connection['id'], gh.Selection(owner='owner', name='app',
        provider_id=str(repository()['id']), local_repository_id=repo['id']))
    assert selected['id'] == repo['id']
    await sync(db, repo['id'])
    original_task = await db.scalar(select(Task.id))
    await gh.save_connection(db, gh.ConnectionSave(name='One', token='NEW', expected_version=1), connection['id'])
    name = 'renamed'
    await sync(db, repo['id'])
    second = await gh.save_connection(db, gh.ConnectionSave(name='Two', token='SECOND'))
    again = await gh.select_repository(second['id'], gh.Selection(owner='owner', name='renamed', provider_id=str(repository()['id'])))
    assert again['id'] == repo['id']
    assert (await db.get(Repository, repo['id'])).sync_connection_id == connection['id']
    assert (await db.get(RepositoryLocation, loc['id'])).repository_id == repo['id']
    assert await db.scalar(select(Task.id)) == original_task


async def test_revoked_token_preserves_tasks_and_unauthorized_agent_cannot_read_source(db, monkeypatch, agent):
    revoked = False
    def handler(request):
        return httpx.Response(401) if revoked else httpx.Response(200, json=repository() if '/issues' not in request.url.path else [issue()])
    _, project, repo_id = await setup(db, monkeypatch, handler)
    await sync(db, repo_id)
    task_id = await db.scalar(select(Task.id))
    await db.refresh(agent)
    assert not (await tasks.list_tasks(db, tasks.TaskFilter(source='github'), agent))['tasks']
    with pytest.raises(tasks.TaskError, match='access'):
        await tasks.get_task(db, task_id, agent)
    await tasks.set_access(db, project['board_id'], agent.id, {'read': True})
    assert (await tasks.get_task(db, task_id, agent))['source']['body'].startswith('<script>')
    revoked = True
    job = await sync(db, repo_id)
    assert job.status == 'error' and not job.source_available and job.last_success
    assert await db.scalar(select(func.count()).select_from(Task)) == 1


async def test_transport_cache_origin_and_rate_limit_handling(db):
    connection = await gh.save_connection(db, gh.ConnectionSave(name='Test', token='TOPSECRET'))
    calls = []
    def handler(request):
        calls.append(request)
        if 'if-none-match' in request.headers:
            return httpx.Response(304)
        return httpx.Response(200, json=[repository()], headers={'ETag': 'abc',
            'Link': '<https://api.github.com/user/repos?page=2>; rel="next"'})
    client = Client(connection['id'], transport=httpx.MockTransport(handler))
    first = await client.get('/user/repos?page=1')
    assert await client.get('/user/repos?page=1') == first
    await client.get('/user/repos?page=2')
    assert 'if-none-match' not in calls[-1].headers
    for link in ('https://evil.invalid/steal', 'https://api.github.com@evil.invalid/steal'):
        client = Client(connection['id'], transport=httpx.MockTransport(lambda req, link=link: httpx.Response(302, headers={'Location': link})))
        with pytest.raises(GitHubError, match='unapproved'):
            await client.get('/redirect')
    client = Client(connection['id'], transport=httpx.MockTransport(lambda req: httpx.Response(403, json={'message': 'not authorized'})))
    with pytest.raises(GitHubError) as exc:
        await client.get('/forbidden')
    assert exc.value.code == 'unavailable' and exc.value.retry_at is None
    client = Client(connection['id'], transport=httpx.MockTransport(lambda req: httpx.Response(429, headers={'Retry-After': '120'})))
    with pytest.raises(GitHubError) as exc:
        await client.get('/limited')
    assert exc.value.code == 'rate_limit' and exc.value.retry_at >= now() + timedelta(seconds=119)


async def test_concurrent_jobs_are_guarded_and_archived_projects_pause(db, monkeypatch):
    started, finish = asyncio.Event(), asyncio.Event()
    block = False
    async def handler(request):
        if '/issues' in request.url.path and block:
            started.set()
            await finish.wait()
        return httpx.Response(200, json=repository() if '/issues' not in request.url.path else [issue()])
    _, project, repo_id = await setup(db, monkeypatch, handler)
    block = True
    first = asyncio.create_task(gh.run_sync(repo_id))
    await asyncio.wait_for(started.wait(), 3)
    await gh.run_sync(repo_id)
    finish.set()
    await first
    assert await db.scalar(select(func.count()).select_from(Task)) == 1
    await tasks.archive_project(db, project['project_id'], 1, True)
    with pytest.raises(tasks.TaskError, match='active project'):
        await gh.enqueue(db, repo_id)


async def test_discussion_separate_paginated_and_ui_escapes_source(db, monkeypatch, live_server):
    def handler(request):
        if request.url.path.endswith('/comments'):
            return httpx.Response(200, json=[{'id': 123, 'body': '<img src=x onerror=evil()>', 'user': {'login': 'commenter'}}],
                                  headers={'Link': '<https://api.github.com/repos/owner/app/issues/1/comments?page=2>; rel="next"'})
        return httpx.Response(200, json=repository() if '/issues' not in request.url.path else [issue()])
    connection, _, repo_id = await setup(db, monkeypatch, handler)
    await sync(db, repo_id)
    task_id = await db.scalar(select(Task.id))
    await gh.refresh_discussion(task_id)
    comments = await gh.discussion(db, task_id)
    assert comments['has_next'] and comments['refreshed_at']
    assert not (await tasks.get_task(db, task_id))['comments']
    async with httpx.AsyncClient(base_url=live_server, headers={'Origin': live_server}) as client:
        await client.post('/ui/login', data={'password': 'adminpass123'})
        page = await client.get('/ui/work/tasks/' + task_id)
        assert page.status_code == 200 and '&lt;script&gt;' in page.text and '<script>danger()' not in page.text
        assert 'name="title"' not in page.text
        page = await client.get('/ui/integrations/github')
        assert 'TEST_PRIVATE_PAT' not in page.text and connection['id'] in page.text
        page = await client.get('/ui/work/repositories/' + repo_id)
        assert page.status_code == 200 and 'GitHub synchronization' in page.text
        assert (await client.get('/ui/work?source=github')).status_code == 200
        assert (await client.get('/ui/work/tasks/' + task_id + '/github-discussion')).status_code == 200
    assert await db.scalar(select(func.count()).select_from(TaskActivity)) >= 1


async def test_upgrade_from_manual_repository_schema_preserves_identity(db):
    from sqlalchemy import text
    # An older slice-two database has manual repositories without any GitHub columns.
    await db.execute(text('DROP TABLE work_repositories'))
    await db.execute(text('''CREATE TABLE work_repositories (
        id VARCHAR PRIMARY KEY, project_id VARCHAR REFERENCES work_projects(id), name VARCHAR NOT NULL,
        description TEXT NOT NULL, web_url VARCHAR NOT NULL, provider_host VARCHAR, provider_id VARCHAR,
        archived BOOLEAN NOT NULL, version INTEGER NOT NULL, created_at TIMESTAMP NOT NULL)'''))
    await db.execute(text("""INSERT INTO work_repositories
        (id,name,description,web_url,archived,version,created_at) VALUES
        ('repo_existing','Existing','','',0,1,'2026-11-01 00:00:00')"""))
    await db.commit()
    await dbm.init_db()
    await dbm.init_db()
    existing = await db.get(Repository, 'repo_existing')
    assert existing.name == 'Existing' and existing.source_metadata == {} and existing.poll_seconds == 300
    assert not existing.import_enabled and existing.sync_connection_id is None


async def test_poll_interval_applies_to_exact_endpoint_not_next_page(db):
    connection = await gh.save_connection(db, gh.ConnectionSave(name='Poll', token='SYNTHETIC'))
    client = Client(connection['id'], transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=[], headers={'X-Poll-Interval': '300'})))
    await client.get('/user/repos?page=1')
    await client.get('/user/repos?page=2')
    with pytest.raises(GitHubError) as exc:
        await client.get('/user/repos?page=1')
    assert exc.value.retry_at > now() + timedelta(seconds=290)
