"""Repository triage is durable, minimal by default, bounded and owner-only."""
import httpx
import pytest
from sqlalchemy import func, select

from keywright_server import db as dbm
from keywright_server import github as gh
from keywright_server.github_client import Client
from keywright_server.models import GitHubIgnoredRepository, GitHubSync, Project, Repository, Task
from keywright_server.web import auth
from keywright_server.web.app import create_app


@pytest.fixture
async def catalog(db, monkeypatch):
    rows = [{'id': 123456789012345670 + i, 'owner': {'login': 'owner'}, 'name': name,
             'description': 'Source description', 'default_branch': 'main', 'private': i == 1}
            for i, name in enumerate(('OldSchoolwork', 'CurrentApp', 'Archive'), 1)]
    requests = []
    def handler(request):
        requests.append(request)
        assert request.method == 'GET' and request.url.path == '/user/repos'
        return httpx.Response(200, json=rows, headers={'Link': '<https://api.github.com/user/repos?page=2>; rel="next"'})
    monkeypatch.setattr(gh, 'Client', lambda cid: Client(cid, transport=httpx.MockTransport(handler)))
    connection = await gh.save_connection(db, gh.ConnectionSave(name='Personal', token='SYNTHETIC_PRIVATE'))
    return connection['id'], rows, requests


async def test_quick_bulk_add_is_minimal_and_repeatable(db, catalog):
    cid, rows, requests = catalog
    ids = [str(r['id']) for r in rows[:2]]
    result = await gh.picker_action(cid, gh.PickerAction(action='add', provider_ids=[*ids, ids[0]]))
    assert [r['status'] for r in result] == ['added', 'added']
    assert len(requests) == 1
    repos = list(await db.scalars(select(Repository).order_by(Repository.provider_id)))
    assert [r.name for r in repos] == ['OldSchoolwork', 'CurrentApp']
    for repo in repos:
        assert repo.project_id is None and repo.description == '' and not repo.import_enabled
        assert not repo.include_closed and repo.source_metadata['description'] == 'Source description'
        assert (await db.get(GitHubSync, repo.id)).status == 'paused'
    assert await db.scalar(select(func.count()).select_from(Project)) == 0
    assert await db.scalar(select(func.count()).select_from(Task)) == 0
    repos[0].name, repos[0].description = 'Custom name', 'Manually entered'
    await db.commit()
    again = await gh.picker_action(cid, gh.PickerAction(action='add', provider_ids=ids))
    assert all(r['status'] == 'already_added' for r in again)
    await db.refresh(repos[0])
    assert repos[0].name == 'Custom name' and repos[0].description == 'Manually entered'
    assert await db.scalar(select(func.count()).select_from(Repository)) == 2


async def test_ignore_survives_rename_replacement_other_connections_and_restart(db, catalog):
    cid, rows, requests = catalog
    provider_id = str(rows[0]['id'])
    for _ in range(2):
        await gh.picker_action(cid, gh.PickerAction(action='ignore', provider_ids=[provider_id]))
    assert not requests  # Hiding a catalog row needs no GitHub or host operation.
    assert await db.scalar(select(func.count()).select_from(GitHubIgnoredRepository)) == 1
    assert await db.scalar(select(func.count()).select_from(Repository)) == 0
    rows[0]['name'] = 'RenamedSchoolwork'
    await gh.save_connection(db, gh.ConnectionSave(name='Personal', token='REPLACEMENT', expected_version=1), cid)
    second = await gh.save_connection(db, gh.ConnectionSave(name='Other', token='OTHER'))
    await dbm.init_db()
    await dbm.init_db()
    page = await gh.discover(second['id'])
    assert provider_id not in [r['id'] for r in page['repositories']]
    page = await gh.discover(cid, show_ignored=True)
    assert page['repositories'][0]['ignored'] and page['repositories'][0]['name'] == 'RenamedSchoolwork'
    await gh.picker_action(cid, gh.PickerAction(action='restore', provider_ids=[provider_id]))
    assert provider_id in [r['id'] for r in (await gh.discover(cid))['repositories']]


async def test_adding_ignored_row_restores_it_and_ignore_does_not_change_added_repo(db, catalog):
    cid, rows, _ = catalog
    provider_id = str(rows[0]['id'])
    await gh.picker_action(cid, gh.PickerAction(action='ignore', provider_ids=[provider_id]))
    await gh.picker_action(cid, gh.PickerAction(action='add', provider_ids=[provider_id]))
    assert await db.scalar(select(func.count()).select_from(GitHubIgnoredRepository)) == 0
    repo = await db.scalar(select(Repository))
    previous = (repo.version, repo.archived, repo.import_enabled, repo.project_id, repo.sync_connection_id)
    result = await gh.picker_action(cid, gh.PickerAction(action='ignore', provider_ids=[provider_id]))
    assert result[0]['status'] == 'already_added'
    assert await db.scalar(select(func.count()).select_from(GitHubIgnoredRepository)) == 0
    await db.refresh(repo)
    assert (repo.version, repo.archived, repo.import_enabled, repo.project_id, repo.sync_connection_id) == previous
    assert (await gh.discover(cid, show_ignored=True))['repositories'][0]['registered_id'] == repo.id


async def test_bulk_reports_missing_rows_and_retries_without_duplicates(db, catalog):
    cid, rows, _ = catalog
    ids = [str(rows[0]['id']), '999999999999999999']
    result = await gh.picker_action(cid, gh.PickerAction(action='add', provider_ids=ids))
    assert [r['status'] for r in result] == ['added', 'failed']
    again = await gh.picker_action(cid, gh.PickerAction(action='add', provider_ids=ids))
    assert [r['status'] for r in again] == ['already_added', 'failed']
    assert await db.scalar(select(func.count()).select_from(Repository)) == 1


async def test_picker_http_single_bulk_protection_and_filter_preservation(db, catalog):
    cid, rows, _ = catalog
    first, second = (str(r['id']) for r in rows[:2])
    url = f'/ui/integrations/github/connections/{cid}/repositories'
    await auth.set_password(db, 'fixture-password')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url='http://gk.test',
                                headers={'Origin': 'http://gk.test'}) as browser:
        assert (await browser.post(url + '/actions', data={'action': 'ignore:' + first})).status_code in (303, 401)
        assert await db.scalar(select(func.count()).select_from(GitHubIgnoredRepository)) == 0
        await browser.post('/ui/login', data={'password': 'fixture-password'})
        assert (await browser.post(url + '/actions', data={'action': 'ignore:' + first},
                                  headers={'Origin': 'http://evil.test'})).status_code == 403
        result = await browser.post(url + '/actions', data={'action': 'ignore:' + first, 'selected': second,
                                    'q': 'School', 'owner': 'owner', 'page': '1'})
        assert result.status_code == 303 and 'q=School' in result.headers['location']
        assert await db.get(GitHubIgnoredRepository, ('github.com', first))
        assert not await db.get(GitHubIgnoredRepository, ('github.com', second))
        page = await browser.get(url, params={'show_ignored': 'true', 'q': 'School', 'owner': 'owner'})
        assert page.status_code == 200 and 'Show ignored' in page.text
        assert 'page=2&amp;q=School&amp;owner=owner&amp;show_ignored=true' in page.text
        added = await browser.post(url + '/actions', data={'action': 'add', 'selected': [first, second], 'page': '1'})
        assert added.status_code == 303
        assert await db.scalar(select(func.count()).select_from(Repository)) == 2
        resources = await browser.get('/ui/resources')
        assert url in resources.text and 'Browse repositories' in resources.text
