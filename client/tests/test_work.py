"""CLI work calls use the native authenticated MCP path and retain typed failures."""
import json

import pytest
from keywright_server import tasks

from keywright import cli


@pytest.fixture
async def work_access(db, agent):
    await tasks.set_access(db, "brd_kw", agent.id, {"read": True, "write": True})


def test_work_cli_round_trip(live_server, work_access, monkeypatch, capsys):
    monkeypatch.setenv("KW_URL", live_server)
    monkeypatch.setenv("KW_TOKEN", "gk_testtoken")
    monkeypatch.setenv("KW_SESSION", "work-test")
    assert cli.main(["work", "create", "--data", '{"title":"CLI work","assignee":"owner"}', "--json"]) == 0
    task = json.loads(capsys.readouterr().out)
    assert task["board_id"] == "brd_kw" and task["creator"].startswith("agent:")
    assert cli.main(["work", "list", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["total"] == 1
    assert cli.main(["work", "update", task["id"], "--data", '{"expected_version":1,"notes":"Plan"}', "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["version"] == 2
    assert cli.main(["work", "update", task["id"], "--data", '{"expected_version":1,"notes":"Stale"}', "--json"]) == 7
    assert json.loads(capsys.readouterr().out)["error"] == "stale_version"
    for _ in range(2):
        assert cli.main(["work", "comment", task["id"], "--data", '{"body":"One comment","idempotency_key":"same"}', "--json"]) == 0
        capsys.readouterr()
    assert cli.main(["work", "get", task["id"], "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["comments"]) == 1


def test_work_cli_denied_without_board_grant(live_server, monkeypatch, capsys):
    monkeypatch.setenv("KW_URL", live_server)
    monkeypatch.setenv("KW_TOKEN", "gk_testtoken")
    assert cli.main(["work", "create", "--data", '{"title":"Denied"}', "--json"]) == 4
    assert json.loads(capsys.readouterr().out)["error"] == "forbidden"


@pytest.mark.parametrize("args", [["get"], ["create", "--data", "[]"], ["list", "unexpected"]])
def test_work_cli_rejects_invalid_arguments(args, capsys):
    assert cli.main(["work", *args]) == 2


@pytest.fixture
async def repository_context(db, agent):
    from keywright_server import repositories
    from keywright_server.models import Resource
    project = await tasks.create_project(db, tasks.ProjectCreate(key='context', name='Context'))
    await tasks.set_access(db, project['board_id'], agent.id, {'read': True})
    repo = await repositories.save_repository(db, repositories.RepositorySave(name='App', project_id=project['project_id']))
    host = Resource(name='ContextHost', kind='ssh', default_mode='open', config={})
    db.add(host)
    await db.commit()
    await repositories.save_location(db, repo['id'], repositories.LocationSave(
        name='Dev', environment='dev', resource_id=host.id, directory='/srv/app'))
    return repo


def test_repository_cli_uses_authenticated_mcp(live_server, repository_context, monkeypatch, capsys):
    monkeypatch.setenv('KW_URL', live_server)
    monkeypatch.setenv('KW_TOKEN', 'gk_testtoken')
    repo = repository_context
    assert cli.main(['work', 'repositories', '--json']) == 0
    assert json.loads(capsys.readouterr().out)['repositories'][0]['id'] == repo['id']
    assert cli.main(['work', 'repository', repo['id'], '--json']) == 0
    assert json.loads(capsys.readouterr().out)['name'] == 'App'
    assert cli.main(['work', 'locations', repo['id'], '--json']) == 0
    assert json.loads(capsys.readouterr().out)['locations'][0]['directory'] == '/srv/app'
    assert cli.main(['work', 'context', repo['id'], '--data', '{"environment":"dev"}', '--json']) == 0
    assert json.loads(capsys.readouterr().out)['environment'] == 'dev'
