"""Work invariants: shared views, default-deny permissions, stale edits and durable notifications."""
import asyncio
from datetime import timedelta

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from keywright_server import db as dbm
from keywright_server import task_notifications, tasks, tasks_mcp
from keywright_server.models import Board, Task, TaskComment, TaskNotification, now


async def new_task(db, **kwargs):
    return await tasks.create_task(db, tasks.TaskCreate(title=kwargs.pop("title", "Test task"), **kwargs))


async def test_general_seed_survives_repeat_and_name_change(db):
    board = await db.get(Board, "brd_kw")
    board.name = "My general work"
    await db.commit()
    for _ in range(2):
        async with dbm.engine().begin() as conn:
            await tasks.seed(conn)
    assert await db.scalar(select(func.count()).select_from(Board)) == 1
    assert (await new_task(db))["board_id"] == board.id
    assert board.name == "My general work"


async def test_general_constraint_and_task_status_constraints(db):
    db.add(Board(key="another-general", name="Bad", kind="general"))
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()
    task = await new_task(db)
    row = await db.get(Task, task["id"])
    row.status = "invented"
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()


async def test_aggregate_views_edit_original_and_hide_completed(db):
    project = await tasks.create_project(db, tasks.ProjectCreate(key="app", name="Application"))
    general = await new_task(db, assignee="owner")
    local = await new_task(db, project_id=project["project_id"], assignee="owner", status="review")
    done = await new_task(db, status="done")
    all_tasks = await tasks.list_tasks(db, tasks.TaskFilter())
    assert {t["id"] for t in all_tasks["tasks"]} == {general["id"], local["id"]}
    needs = await tasks.list_tasks(db, tasks.TaskFilter(needs_you=True))
    assert needs["tasks"][0]["id"] == local["id"]
    assert "description" not in all_tasks["tasks"][0]
    edited = await tasks.update_task(db, local["id"], tasks.TaskPatch(expected_version=1, status="done"))
    assert edited["version"] == 2 and edited["board_id"] == project["board_id"]
    assert (await tasks.list_tasks(db, tasks.TaskFilter(needs_you=True)))["total"] == 1
    assert (await tasks.list_tasks(db, tasks.TaskFilter(include_done=True)))["total"] == 3
    assert done["id"]


async def test_conflicting_destination_and_unknown_assignee(db):
    p = await tasks.create_project(db, tasks.ProjectCreate(key="local", name="Local"))
    with pytest.raises(tasks.TaskError, match="disagree"):
        await new_task(db, project_id=p["project_id"], board_id="brd_kw")
    await db.rollback()
    with pytest.raises(tasks.TaskError) as exc:
        await new_task(db, assignee="agent:missing")
    assert exc.value.code == "invalid_assignee"
    await db.rollback()
    assert await db.scalar(select(func.count()).select_from(Task)) == 0


async def test_stale_update_preserves_task_activity_and_notification(db):
    task = await new_task(db, assignee="owner")
    await tasks.update_task(db, task["id"], tasks.TaskPatch(expected_version=1, title="Fresh"))
    with pytest.raises(tasks.TaskError) as exc:
        await tasks.update_task(db, task["id"], tasks.TaskPatch(expected_version=1, title="Stale"))
    assert exc.value.code == "stale_version" and exc.value.latest_version == 2
    await db.rollback()
    detail = await tasks.get_task(db, task["id"])
    assert detail["title"] == "Fresh" and len(detail["activity"]) == 2
    assert await db.scalar(select(func.count()).select_from(TaskNotification)) == 1


async def test_concurrent_updates_only_one_wins(db):
    task = await new_task(db)
    async def change(title):
        async with dbm.session() as connection:
            try:
                await tasks.update_task(connection, task["id"], tasks.TaskPatch(expected_version=1, title=title))
                return "ok"
            except tasks.TaskError as exc:
                return exc.code
    assert sorted(await asyncio.gather(change("One"), change("Two"))) == ["ok", "stale_version"]


async def test_board_permissions_apply_to_lists_details_comments_and_mutations(db, agent):
    p = await tasks.create_project(db, tasks.ProjectCreate(key="private", name="Private"))
    secret = await new_task(db, board_id=p["board_id"], title="Private issue")
    general = await new_task(db)
    assert (await tasks.list_tasks(db, tasks.TaskFilter(), agent))["total"] == 0
    assert not (await tasks.list_boards(db, agent))["boards"]
    with pytest.raises(tasks.TaskError) as exc:
        await tasks.get_task(db, secret["id"], agent)
    assert exc.value.code == "forbidden"
    await db.rollback()
    await db.refresh(agent)
    await tasks.set_access(db, "brd_kw", agent.id, {"read": True})
    visible = await tasks.list_tasks(db, tasks.TaskFilter(), agent)
    assert visible["total"] == 1 and visible["tasks"][0]["id"] == general["id"]
    with pytest.raises(tasks.TaskError):
        await tasks.comment(db, general["id"], "Not allowed", "one", agent)
    await db.rollback()
    await db.refresh(agent)
    await tasks.set_access(db, "brd_kw", agent.id, {"read": True, "write": True})
    created = await tasks.create_task(db, tasks.TaskCreate(title="Agent plan"), agent)
    assert created["creator"] == "agent:" + agent.id
    await tasks.comment(db, created["id"], "Plan", "one", agent)
    with pytest.raises(tasks.TaskError):
        await tasks.update_task(db, created["id"], tasks.TaskPatch(expected_version=1, status="in_progress"), agent)
    await db.rollback()
    await db.refresh(agent)
    await tasks.set_access(db, "brd_kw", agent.id, {})
    assert not (await tasks.list_tasks(db, tasks.TaskFilter(), agent))["tasks"]


async def test_comment_retry_does_not_conflict_with_task_version(db):
    task = await new_task(db)
    first = await tasks.comment(db, task["id"], "Evidence", "retry")
    await tasks.update_task(db, task["id"], tasks.TaskPatch(expected_version=1, status="ready"))
    assert await tasks.comment(db, task["id"], "Evidence", "retry") == first
    with pytest.raises(tasks.TaskError) as exc:
        await tasks.comment(db, task["id"], "Different", "retry")
    assert exc.value.code == "conflict"
    await db.rollback()
    assert await db.scalar(select(func.count()).select_from(TaskComment)) == 1


async def test_archive_project_and_task_restore_without_duplicates(db):
    project = await tasks.create_project(db, tasks.ProjectCreate(key="archive", name="Archive"))
    task = await new_task(db, project_id=project["project_id"])
    await tasks.archive_project(db, project["project_id"], 1, True)
    assert (await tasks.list_tasks(db, tasks.TaskFilter()))["total"] == 0
    assert (await tasks.list_tasks(db, tasks.TaskFilter(include_archived=True)))["total"] == 1
    with pytest.raises(tasks.TaskError):
        await tasks.update_task(db, task["id"], tasks.TaskPatch(expected_version=1, title="No"))
    await db.rollback()
    await tasks.archive_project(db, project["project_id"], 2, False)
    await tasks.update_task(db, task["id"], tasks.TaskPatch(expected_version=1, archived=True))
    assert (await tasks.list_tasks(db, tasks.TaskFilter()))["total"] == 0
    await tasks.update_task(db, task["id"], tasks.TaskPatch(expected_version=2, archived=False))
    assert (await tasks.list_tasks(db, tasks.TaskFilter()))["total"] == 1


async def test_move_preserves_id_comments_activity_and_changes_visibility(db, agent):
    project = await tasks.create_project(db, tasks.ProjectCreate(key="destination", name="Destination"))
    await tasks.set_access(db, project["board_id"], agent.id, {"read": True})
    task = await new_task(db)
    await tasks.comment(db, task["id"], "Keep this", "one")
    assert not (await tasks.list_tasks(db, tasks.TaskFilter(), agent))["tasks"]
    moved = await tasks.move_task(db, task["id"], project["board_id"], 1)
    assert moved["id"] == task["id"]
    read = await tasks.get_task(db, task["id"], agent)
    assert read["comments"][0]["body"] == "Keep this" and len(read["activity"]) == 3


async def test_ordering_and_aggregate_sort_are_independent(db):
    low = await new_task(db, priority=3)
    high = await new_task(db, priority=0)
    await tasks.update_task(db, high["id"], tasks.TaskPatch(expected_version=1, before_id=low["id"]))
    board = await tasks.list_tasks(db, tasks.TaskFilter(board_id="brd_kw"))
    assert [t["id"] for t in board["tasks"]] == [high["id"], low["id"]]
    await tasks.update_task(db, high["id"], tasks.TaskPatch(expected_version=2, before_id=None))
    board = await tasks.list_tasks(db, tasks.TaskFilter(board_id="brd_kw"))
    assert [t["id"] for t in board["tasks"]] == [low["id"], high["id"]]
    assert (await tasks.list_tasks(db, tasks.TaskFilter(limit=1)))["next_offset"] == 1
    assert (await tasks.list_tasks(db, tasks.TaskFilter(q="%")))["total"] == 0


async def test_notifications_are_durable_and_do_not_repeat_on_unchanged_assignment(db, monkeypatch, log_notifier):
    task = await new_task(db, assignee="owner")
    await tasks.update_task(db, task["id"], tasks.TaskPatch(expected_version=1, assignee="owner", status="review"))
    await tasks.update_task(db, task["id"], tasks.TaskPatch(expected_version=2, assignee="owner", status="review"))
    assert await db.scalar(select(func.count()).select_from(TaskNotification)) == 2
    async def fail(*args):
        raise RuntimeError("secret-token-never-log")
    monkeypatch.setattr(log_notifier.active, "send_task", fail)
    await task_notifications.deliver_pending()
    notices = list(await db.scalars(select(TaskNotification)))
    assert all(n.attempts == 1 and "secret" not in n.error for n in notices)
    assert await db.get(Task, task["id"])
    calls = []
    async def succeed(*args):
        calls.append(args)
    monkeypatch.setattr(log_notifier.active, "send_task", succeed)
    for n in notices:
        n.next_attempt_at = now() - timedelta(seconds=1)
    await db.commit()
    await task_notifications.deliver_pending()
    await task_notifications.deliver_pending()
    assert len(calls) == 2
    assert all(task["title"] not in str(args) for args in calls)


async def test_native_tools_reject_actor_injection_and_default_to_general(db, agent):
    with pytest.raises(tasks.TaskError):
        await tasks_mcp.execute(db, agent, "work_create_task", {"title": "No grant"})
    await db.rollback()
    await db.refresh(agent)
    await tasks.set_access(db, "brd_kw", agent.id, {"read": True, "write": True})
    with pytest.raises(tasks.TaskError) as exc:
        await tasks_mcp.execute(db, agent, "work_create_task", {"title": "Spoof", "actor": "owner"})
    assert exc.value.code == "invalid_arguments"
    task = await tasks_mcp.execute(db, agent, "work_create_task", {"title": "Valid"})
    assert task["board_id"] == "brd_kw"
    updated = await tasks_mcp.execute(db, agent, "work_update_task",
                                     {"task_id": task["id"], "expected_version": 1, "notes": "Plan"})
    assert updated["notes"] == "Plan" and updated["title"] == "Valid"


async def test_ui_api_auth_accessible_status_and_escaping(db, live_server):
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as client:
        response = await client.get("/api/work/tasks")
        assert response.status_code in (303, 401)
        await client.post("/ui/login", data={"password": "adminpass123"})
        created = await client.post("/api/work/tasks", json={"title": "<script>bad()</script>", "assignee": "owner"})
        assert created.status_code == 200, created.text
        task = created.json()
        for url in ("/ui/work", "/ui/work?view=needs_you&mode=list", "/ui/work/tasks/" + task["id"]):
            response = await client.get(url)
            assert response.status_code == 200, response.text
            assert "&lt;script&gt;bad()&lt;/script&gt;" in response.text
            assert "<script>bad()</script>" not in response.text
        response = await client.post("/ui/work/tasks/" + task["id"],
                                     data={"expected_version": "1", "status": "ready", "return_to": "/ui/work"})
        assert response.status_code == 303
        response = await client.patch("/api/work/tasks/" + task["id"], json={"expected_version": 1, "title": "Stale"})
        assert response.status_code == 409
        response = await client.post("/api/work/tasks", headers={"Origin": "https://evil.example"}, json={"title": "No"})
        assert response.status_code == 403


@pytest.mark.parametrize("data", [{"title": ""}, {"title": "x", "priority": 9}, {"title": "x", "status": "unknown"}])
def test_validation(data):
    with pytest.raises(ValidationError):
        tasks.TaskCreate(**data)


async def test_startup_migration_preserves_existing_data_and_seeds_once(db, seeded):
    from keywright_server.models import Resource
    before = await db.scalar(select(func.count()).select_from(Resource))
    await db.commit()
    await dbm.init_db()
    await dbm.init_db()
    assert await db.scalar(select(func.count()).select_from(Resource)) == before
    assert await db.scalar(select(func.count()).select_from(Board).where(Board.key == "kw")) == 1


async def test_marking_notification_read_never_mutates_task(db, live_server):
    task = await new_task(db, assignee="owner")
    notification = await db.scalar(select(TaskNotification))
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as client:
        await client.post("/ui/login", data={"password": "adminpass123"})
        response = await client.post(f"/ui/work/notifications/{notification.id}/read")
        assert response.status_code == 303
    current = await tasks.get_task(db, task["id"])
    assert current["status"] == "backlog" and current["assignee"] == "owner" and current["version"] == 1


async def test_agent_assignment_requires_board_read_permission_and_owner_can_reassign(db, agent):
    agent_id = agent.id
    with pytest.raises(tasks.TaskError):
        await new_task(db, assignee="agent:" + agent_id)
    await db.rollback()
    await tasks.set_access(db, "brd_kw", agent_id, {"read": True})
    task = await new_task(db, assignee="agent:" + agent_id)
    assert task["assignee"] == "agent:" + agent_id
    await tasks.update_task(db, task["id"], tasks.TaskPatch(expected_version=1, assignee="owner"))
    assert await db.scalar(select(func.count()).select_from(TaskNotification)) == 1


async def test_disabled_agent_cannot_read_with_previously_loaded_identity(db, agent):
    await tasks.set_access(db, "brd_kw", agent.id, {"read": True})
    agent.disabled_at = now()
    await db.commit()
    with pytest.raises(tasks.TaskError) as exc:
        await tasks.list_tasks(db, tasks.TaskFilter(), agent)
    assert exc.value.code == "forbidden"


async def test_agent_deletion_preserves_assigned_tasks_and_disabling_does_not_block_owner_edits(db, agent, live_server):
    agent_id = agent.id
    await tasks.set_access(db, "brd_kw", agent_id, {"read": True})
    task = await new_task(db, assignee="agent:" + agent_id)
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as client:
        await client.post("/ui/login", data={"password": "adminpass123"})
        response = await client.post(f"/ui/agents/{agent_id}/delete")
        assert response.status_code == 303
        assert "Reassign" in response.cookies.get("kw_flash", "")
        await client.post(f"/ui/agents/{agent_id}/disable")
        response = await client.patch("/api/work/tasks/" + task["id"], json={
            "expected_version": 1, "assignee": "agent:" + agent_id, "notes": "Owner can still plan"})
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["assignee"] == "agent:" + agent_id
