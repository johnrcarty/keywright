"""Environment context: persistence, authorization, safe probes and concurrent edits."""
import asyncio
import json
import shlex
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import delete, event, select
from sqlalchemy.exc import IntegrityError

from keywright_server import db as dbm
from keywright_server import repositories as r
from keywright_server import ssh, tasks, tasks_mcp
from keywright_server.models import InventoryAsset, InventoryResourceLink, RepositoryLocation, Resource


@pytest.fixture(autouse=True)
def production_foreign_keys(db):
    # reset_for_tests omits production pragmas. Exercise these new FK contracts
    # with the same enforcement used by the actual SQLite installation.
    engine = dbm.engine().sync_engine
    def enforce(connection, record, proxy):
        cursor = connection.cursor()
        cursor.execute('PRAGMA foreign_keys=ON')
        cursor.close()
    event.listen(engine, 'checkout', enforce)
    yield
    event.remove(engine, 'checkout', enforce)


async def setup(db, agent=None):
    project = await tasks.create_project(db, tasks.ProjectCreate(key='app', name='Application'))
    if agent:
        await tasks.set_access(db, project['board_id'], agent.id, {'read': True})
    repo = await r.save_repository(db, r.RepositorySave(name='Application', project_id=project['project_id'],
                                                      web_url='https://github.com/owner/app'))
    asset = InventoryAsset(name='Test VM')
    resource = Resource(kind='ssh', name='VM', default_mode='approval', config={'host': '192.0.2.1', 'host_key': 'pinned'})
    db.add_all([asset, resource])
    await db.flush()
    db.add(InventoryResourceLink(resource_id=resource.id, asset_id=asset.id))
    await db.commit()
    return project, repo, asset, resource


async def location(db, repo, asset=None, resource=None, **kwargs):
    return await r.save_location(db, repo['id'], r.LocationSave(
        name=kwargs.pop('name', 'Main'), environment=kwargs.pop('environment', 'dev'),
        asset_id=asset.id if asset else None, resource_id=resource.id if resource else None,
        directory=kwargs.pop('directory', '/srv/app'), **kwargs))


async def test_metadata_saves_multiple_environments_primary_and_missing_dev(db, monkeypatch):
    probe = AsyncMock(side_effect=AssertionError('Saving must not execute'))
    monkeypatch.setattr(ssh, 'run', probe)
    _, repo, asset, resource = await setup(db)
    prod = await location(db, repo, asset, environment='prod', directory_kind='deployment_directory')
    assert not prod['can_verify'] and prod['verification_status'] == 'unverified'
    with pytest.raises(tasks.TaskError, match='No dev location'):
        await r.context(db, r.Context(repository_id=repo['id'], environment='dev'))
    first = await location(db, repo, resource=resource)
    second = await location(db, repo, asset, resource, name='Another')
    with pytest.raises(tasks.TaskError, match='Multiple locations'):
        await r.context(db, r.Context(repository_id=repo['id'], environment='dev'))
    result = await r.context(db, r.Context(repository_id=repo['id'], environment='dev', location_id=first['id']))
    assert result['id'] == first['id']
    primary = await location(db, repo, resource=resource, is_primary=True)
    replacement = await location(db, repo, resource=resource, is_primary=True)
    assert (await r.context(db, r.Context(repository_id=repo['id'], environment='dev')))['id'] == replacement['id']
    await db.refresh(await db.get(RepositoryLocation, primary['id']))
    assert not (await db.get(RepositoryLocation, primary['id'])).is_primary
    assert (await r.list_locations(db, r.Locations(repository_id=repo['id'], environment='prod')))['locations'][0]['id'] == prod['id']
    assert second['id'] != first['id']
    probe.assert_not_called()


@pytest.mark.parametrize('field,value', [
    ('directory', 'relative'), ('directory', '/a/../b'), ('directory', '/x\ny'), ('directory', '/$HOME'),
    ('directory', '/$(touch bad)'), ('directory', '/a`id`'), ('directory', '/%HOME%'),
    ('subdirectory', '/absolute'), ('subdirectory', '../escape'), ('subdirectory', 'x/../../escape'),
    ('application_url', 'javascript:alert(1)'), ('application_url', 'https://user:pass@example.com'),
])
def test_reject_paths_and_urls(field, value):
    args = {'environment': 'dev', 'name': 'Main', 'resource_id': 'res_example', 'directory': '/srv/app'}
    args[field] = value
    with pytest.raises(ValidationError):
        r.LocationSave(**args)


async def test_association_required_and_deleted_references_preserved(db):
    _, repo, asset, resource = await setup(db)
    other = InventoryAsset(name='Other')
    db.add(other)
    await db.commit()
    with pytest.raises(tasks.TaskError, match='linked'):
        await location(db, repo, other, resource)
    await db.rollback()
    # Re-fetch after rollback expires fixture entities.
    asset = await db.scalar(select(InventoryAsset).where(InventoryAsset.name == 'Test VM'))
    resource = await db.scalar(select(Resource))
    loc = await location(db, repo, asset, resource)
    resource_id = resource.id
    await db.execute(delete(Resource).where(Resource.id == resource_id))
    await db.commit()
    db.expire_all()
    result = (await r.list_locations(db, r.Locations(repository_id=repo['id'])))['locations'][0]
    assert result['id'] == loc['id'] and result['resource_id'] is None
    assert result['resource_ref'] == resource_id and result['verification_status'] == 'unavailable'
    with pytest.raises(tasks.TaskError, match='unavailable'):
        await r.context(db, r.Context(repository_id=repo['id'], environment='dev'))


async def test_board_and_host_permissions_are_separate(db, agent):
    agent_id = agent.id
    project, repo, asset, resource = await setup(db, agent)
    loc = await location(db, repo, asset, resource, notes='private path notes')
    public = await tasks_mcp.execute(db, agent, 'work_list_repositories', {})
    assert [row['id'] for row in public['repositories']] == [repo['id']]
    result = await tasks_mcp.execute(db, agent, 'work_list_locations', {'repository_id': repo['id']})
    assert result['locations'] == [{'id': loc['id'], 'environment': 'dev', 'restricted': True}]
    with pytest.raises(tasks.TaskError, match='SSH permission'):
        await r.context(db, r.Context(repository_id=repo['id'], environment='dev'), agent)
    resource.default_mode = 'open'
    await db.commit()
    result = await r.context(db, r.Context(repository_id=repo['id'], environment='dev'), agent)
    assert result['directory'] == '/srv/app' and 'config' not in result
    await tasks.set_access(db, project['board_id'], agent_id, {'read': False})
    assert not (await r.list_repositories(db, r.RepositoryFilter(), agent))['repositories']
    with pytest.raises(tasks.TaskError, match='access'):
        await r.list_locations(db, r.Locations(repository_id=repo['id']), agent)


async def test_primary_database_constraint_and_stale_edit(db):
    _, repo, asset, _ = await setup(db)
    loc = await location(db, repo, asset, is_primary=True)
    row = RepositoryLocation(repository_id=repo['id'], environment='dev', name='Duplicate',
                             asset_id=asset.id, asset_ref=asset.id, directory='/different', is_primary=True)
    db.add(row)
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()
    asset = await db.scalar(select(InventoryAsset))
    await r.save_location(db, repo['id'], r.LocationSave(name='New', environment='dev', asset_id=asset.id,
        directory='/new', expected_version=loc['version']), loc['id'])
    with pytest.raises(tasks.TaskError) as exc:
        await r.save_location(db, repo['id'], r.LocationSave(name='Stale', environment='dev', asset_id=asset.id,
            directory='/stale', expected_version=loc['version']), loc['id'])
    assert exc.value.code == 'stale_version'


async def test_explicit_verification_is_quoted_redacted_and_source_changes_rejected(db, monkeypatch):
    _, repo, _, resource = await setup(db)
    loc = await location(db, repo, resource=resource, directory="/srv/app'; touch injected; '", expected_ref='main')
    commit = 'a' * 40
    async def run(config, command, timeout):
        args = shlex.split(command)
        assert args[:2] == ['python3', '-c'] and len(args) == 4
        assert json.loads(args[3])['directory'] == loc['directory']
        return ssh.RunResult(0, json.dumps({'exists': True, 'application_exists': True, 'contained': True,
            'ref': 'main', 'commit': commit, 'expected_commit': commit, 'remote': 'https://TOKEN@github.com/owner/app.git'}), '', False, 1)
    monkeypatch.setattr(ssh, 'run', run)
    result = await r.verify_location(loc['id'], loc['version'])
    assert result['verification_status'] == 'verified' and 'TOKEN' not in json.dumps(result)
    assert result['observed']['repository'] == 'https://github.com/owner/app'
    # Editing the resource while the remote operation runs invalidates its result.
    async def changed(*args, **kwargs):
        async with dbm.session() as other:
            target = await other.get(Resource, resource.id)
            target.config = {**target.config, 'host': '192.0.2.99'}
            await other.commit()
        return await run(*args, **kwargs)
    monkeypatch.setattr(ssh, 'run', changed)
    with pytest.raises(tasks.TaskError, match='changed during'):
        await r.verify_location(loc['id'], result['version'])


async def test_deployment_probe_needs_no_git_and_errors_redacted(db, monkeypatch):
    _, repo, _, resource = await setup(db)
    loc = await location(db, repo, resource=resource, directory_kind='deployment_directory')
    monkeypatch.setattr(ssh, 'run', AsyncMock(return_value=ssh.RunResult(0, json.dumps(
        {'exists': True, 'application_exists': True, 'contained': True}), '', False, 1)))
    result = await r.verify_location(loc['id'], loc['version'])
    assert result['verification_status'] == 'verified' and result['observed'] == {}
    monkeypatch.setattr(ssh, 'run', AsyncMock(side_effect=RuntimeError('SECRET')))
    result = await r.verify_location(loc['id'], result['version'])
    assert result['verification_status'] == 'failed' and 'SECRET' not in json.dumps(result)


async def test_concurrent_location_edits_one_winner(db):
    _, repo, asset, _ = await setup(db)
    loc = await location(db, repo, asset)
    asset_id = asset.id
    async def save(name):
        async with dbm.session() as other:
            try:
                await r.save_location(other, repo['id'], r.LocationSave(name=name, environment='dev',
                    asset_id=asset_id, directory='/app', expected_version=loc['version']), loc['id'])
                return 'saved'
            except tasks.TaskError as exc:
                return exc.code
    assert sorted(await asyncio.gather(save('A'), save('B'))) == ['saved', 'stale_version']


async def test_admin_ui_api_auth_and_forms(db, live_server):
    _, repo, asset, _ = await setup(db)
    async with httpx.AsyncClient(base_url=live_server, headers={'Origin': live_server}) as client:
        assert (await client.get('/api/work/repositories')).status_code in (303, 401)
        await client.post('/ui/login', data={'password': 'adminpass123'})
        assert (await client.get('/ui/work/repositories')).status_code == 200
        assert (await client.get('/ui/work/repositories/' + repo['id'])).status_code == 200
        response = await client.post('/ui/work/repositories/' + repo['id'] + '/locations', data={
            'name': 'Production', 'environment': 'prod', 'asset_id': asset.id, 'resource_id': '',
            'directory': '/opt/app', 'directory_kind': 'deployment_directory'})
        assert response.status_code == 303
        response = await client.get('/api/work/repositories/' + repo['id'] + '/locations')
        assert response.status_code == 200 and response.json()['locations'][0]['directory'] == '/opt/app'
        denied = await client.post('/api/work/repositories', json={'name': 'Bad'}, headers={'Origin': 'http://evil.test'})
        assert denied.status_code == 403


async def test_changed_inventory_association_and_disabled_agent(db, agent):
    _, repo, asset, resource = await setup(db, agent)
    loc = await location(db, repo, asset, resource)
    other = InventoryAsset(name='Replacement')
    db.add(other)
    await db.flush()
    link = await db.get(InventoryResourceLink, resource.id)
    link.asset_id = other.id
    await db.commit()
    result = (await r.list_locations(db, r.Locations(repository_id=repo['id'])))['locations'][0]
    assert result['verification_status'] == 'unavailable' and not result['can_verify']
    agent.disabled_at = r.now()
    await db.commit()
    with pytest.raises(tasks.TaskError, match='disabled'):
        await r.list_repositories(db, r.RepositoryFilter(), agent)
    with pytest.raises(tasks.TaskError, match='linked SSH'):
        await r.verify_location(loc['id'], loc['version'])


def test_real_read_only_probe_handles_literal_paths_and_symlink_escape(tmp_path):
    import subprocess
    import sys
    directory = tmp_path / "app'; touch injected; '"
    directory.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    (directory / 'escape').symlink_to(outside, target_is_directory=True)
    values = {'directory': str(directory), 'subdirectory': '', 'directory_kind': 'deployment_directory', 'expected_ref': ''}
    # Execute the same shell-quoted boundary used by SSH against isolated local data.
    command = shlex.quote(sys.executable) + ' -c ' + shlex.quote(r.PROBE) + ' ' + shlex.quote(json.dumps(values))
    result = subprocess.run(['/bin/sh', '-c', command], cwd=tmp_path, capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == {'exists': True, 'application_exists': True, 'contained': True}
    assert not (tmp_path / 'injected').exists()
    values['subdirectory'] = 'escape'
    result = subprocess.run([sys.executable, '-c', r.PROBE, json.dumps(values)], capture_output=True, text=True, check=True)
    assert not json.loads(result.stdout)['contained']
