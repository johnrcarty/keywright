"""Admin UI/API adapters for the shared work domain."""
from urllib.parse import urlencode
from uuid import uuid4

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import select, update

from .. import audit, settings_store, tasks
from ..db import session
from ..models import Agent, Board, BoardAgentAccess, Repository, TaskNotification, now
from . import auth
from .admin import redirect, render
from .security import require_same_origin

router = APIRouter(dependencies=[Depends(require_same_origin), Depends(auth.require_admin)])


def error(exc):
    if isinstance(exc, tasks.TaskError):
        status = {"not_found": 404, "forbidden": 403, "stale_version": 409, "conflict": 409}.get(exc.code, 422)
        return JSONResponse(exc.payload(), status_code=status)
    return JSONResponse({"error": "invalid_arguments", "message": "Check the supplied fields and try again."}, status_code=422)


def task_form(form, creating=False):
    fields = {key: str(form[key]) for key in ("title", "description", "notes", "acceptance", "status", "assignee")
              if key in form}
    for key in ("priority", "expected_version"):
        if key in form:
            fields[key] = int(str(form[key]))
    if "due_date" in form:
        fields["due_date"] = str(form["due_date"]) or None
    if "labels" in form:
        fields["labels"] = [s.strip() for s in str(form["labels"]).split(",") if s.strip()]
    if "archived" in form:
        fields["archived"] = str(form["archived"]) == "true"
    if "before_id" in form:
        fields["before_id"] = str(form["before_id"]) or None
    if creating:
        fields["board_id"] = str(form.get("board_id", "")) or None
        return tasks.TaskCreate(**fields)
    return tasks.TaskPatch(**fields)


@router.get("/ui/work")
async def home(request: Request):
    raw = dict(request.query_params)
    view = raw.pop("view", "all")
    mode = raw.pop("mode", "board")
    raw.pop("needs_you", None)
    board_offset = int(raw.pop("board_offset", "0")) if raw.get("board_offset", "0").isdigit() else 0
    try:
        filters = tasks.TaskFilter(**{k: v for k, v in raw.items() if v != ""}, needs_you=view == "needs_you")
        async with session() as db:
            result = await tasks.list_tasks(db, filters)
            boards = await tasks.list_boards(db, include_archived=filters.include_archived, offset=board_offset)
            selected = await db.get(Board, filters.board_id) if filters.board_id else None
            repositories = list(await db.scalars(select(Repository).order_by(Repository.name).limit(500)))
            agents = list(await db.scalars(select(Agent).order_by(Agent.name).limit(100)))
            grants = list(await db.scalars(select(BoardAgentAccess).where(BoardAgentAccess.board_id == selected.id))) if selected else []
            owner = (await settings_store.get(db, "work_owner", {})).get("name", "Me")
            unread = list(await db.scalars(select(TaskNotification).where(TaskNotification.read_at.is_(None))
                                          .order_by(TaskNotification.created_at.desc()).limit(20)))
    except (tasks.TaskError, ValidationError, ValueError) as exc:
        return error(exc)
    query = dict(request.query_params)
    def page_url(offset):
        return "/ui/work?" + urlencode({**query, "offset": offset})
    return render(request, "work.html", result=result, boards=boards, selected=selected, agents=agents,
                  grants={g.agent_id: g for g in grants}, repositories=repositories, owner=owner, unread=unread, filters=filters,
                  statuses=tasks.STATUSES, priorities=tasks.PRIORITIES, view=view,
                  mode="list" if mode == "list" else "board", page_url=page_url, board_offset=board_offset,
                  selected_project=next((b for b in boards["boards"] if selected and b["id"] == selected.id), None))


@router.get("/ui/work/tasks/{task_id}")
async def detail(request: Request, task_id: str, offset: int = 0):
    try:
        if not 0 <= offset <= 1000000:
            raise ValueError("Invalid offset")
        async with session() as db:
            task = await tasks.get_task(db, task_id, offset=offset)
            boards = await tasks.list_boards(db)
            agents = list(await db.scalars(select(Agent).order_by(Agent.name).limit(100)))
            owner = (await settings_store.get(db, "work_owner", {})).get("name", "Me")
            audiences = {}
            for board in boards["boards"]:
                audiences[board["id"]] = list(await db.scalars(select(Agent.name).join(
                    BoardAgentAccess, BoardAgentAccess.agent_id == Agent.id).where(
                    BoardAgentAccess.board_id == board["id"], BoardAgentAccess.read.is_(True),
                    Agent.disabled_at.is_(None)).order_by(Agent.name)))
    except (tasks.TaskError, ValueError) as exc:
        return error(exc)
    return render(request, "work_task.html", task=task, boards=boards["boards"], audiences=audiences,
                  agents=agents, owner=owner, statuses=tasks.STATUSES, priorities=tasks.PRIORITIES,
                  comment_key=str(uuid4()))


@router.post("/ui/work/projects")
async def create_project(request: Request):
    try:
        form = await request.form()
        async with session() as db:
            result = await tasks.create_project(db, tasks.ProjectCreate(**dict(form)))
        return redirect("/ui/work?board_id=" + result["board_id"])
    except (tasks.TaskError, ValidationError, ValueError) as exc:
        return error(exc)


@router.post("/ui/work/projects/{project_id}/archive")
async def archive_project(request: Request, project_id: str):
    try:
        form = await request.form()
        async with session() as db:
            await tasks.archive_project(db, project_id, int(str(form["expected_version"])), form.get("archived") == "true")
        return redirect("/ui/work?include_archived=true")
    except (tasks.TaskError, ValueError, KeyError) as exc:
        return error(exc)


@router.post("/ui/work/boards/{board_id}/access")
async def access(request: Request, board_id: str):
    try:
        form = await request.form()
        async with session() as db:
            await tasks.set_access(db, board_id, str(form["agent_id"]),
                                   {k: form.get(k) == "on" for k in ("read", "write")})
        return redirect("/ui/work?board_id=" + board_id, "Board access saved.")
    except (tasks.TaskError, KeyError) as exc:
        return error(exc)


@router.post("/ui/work/owner")
async def owner(request: Request):
    form = await request.form()
    name = str(form.get("name", "")).strip()
    if not name or len(name) > 120 or any(ord(c) < 32 for c in name):
        return error(ValueError())
    async with session() as db:
        await settings_store.put(db, "work_owner", {"name": name})
        await audit.record(db, tool="work.owner.configure", decision="saved")
    return redirect("/ui/work", "Owner display name saved.")


@router.post("/ui/work/tasks")
async def create_task(request: Request):
    try:
        data = task_form(await request.form(), creating=True)
        async with session() as db:
            result = await tasks.create_task(db, data)
        return redirect("/ui/work/tasks/" + result["id"])
    except (tasks.TaskError, ValidationError, ValueError) as exc:
        return error(exc)


@router.post("/ui/work/tasks/{task_id}")
async def update_task(request: Request, task_id: str):
    try:
        form = await request.form()
        data = task_form(form)
        async with session() as db:
            result = await tasks.update_task(db, task_id, data)
        if request.headers.get("accept") == "application/json":
            return JSONResponse(result)
        return redirect(str(form.get("return_to", "/ui/work/tasks/" + task_id)))
    except (tasks.TaskError, ValidationError, ValueError) as exc:
        return error(exc)


@router.post("/ui/work/tasks/{task_id}/move")
async def move_task(request: Request, task_id: str):
    try:
        form = await request.form()
        if form.get("confirm_audience") != "on":
            raise tasks.TaskError("invalid_arguments", "Confirm the destination audience before moving.")
        async with session() as db:
            await tasks.move_task(db, task_id, str(form["board_id"]), int(str(form["expected_version"])))
        return redirect("/ui/work/tasks/" + task_id)
    except (tasks.TaskError, ValueError, KeyError) as exc:
        return error(exc)


@router.post("/ui/work/tasks/{task_id}/comments")
async def comment(request: Request, task_id: str):
    try:
        form = await request.form()
        async with session() as db:
            await tasks.comment(db, task_id, str(form.get("body", "")), str(form.get("idempotency_key", "")))
        return redirect("/ui/work/tasks/" + task_id)
    except tasks.TaskError as exc:
        return error(exc)


@router.post("/ui/work/notifications/{event_id}/read")
async def read_notification(event_id: str):
    async with session() as db:
        await db.execute(update(TaskNotification).where(TaskNotification.id == event_id,
                         TaskNotification.recipient == "owner").values(read_at=now()))
        await db.commit()
    return redirect("/ui/work?view=needs_you")


@router.get("/api/work/tasks")
async def api_list(request: Request):
    try:
        filters = tasks.TaskFilter(**dict(request.query_params))
        async with session() as db:
            return await tasks.list_tasks(db, filters)
    except (tasks.TaskError, ValidationError) as exc:
        return error(exc)


@router.get("/api/work/tasks/{task_id}")
async def api_get(task_id: str):
    try:
        async with session() as db:
            return await tasks.get_task(db, task_id)
    except tasks.TaskError as exc:
        return error(exc)


@router.post("/api/work/tasks")
async def api_create(data: tasks.TaskCreate):
    try:
        async with session() as db:
            return await tasks.create_task(db, data)
    except tasks.TaskError as exc:
        return error(exc)


@router.patch("/api/work/tasks/{task_id}")
async def api_update(task_id: str, data: tasks.TaskPatch):
    try:
        async with session() as db:
            return await tasks.update_task(db, task_id, data)
    except tasks.TaskError as exc:
        return error(exc)
