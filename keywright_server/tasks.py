"""Shared work domain. Callers supply authenticated Agent or None for the local owner.

Mutations own their transaction. SQLite writes use the same BEGIN IMMEDIATE convention
as knowledge; versions still fence stale client edits. No operation executes remote work.
"""
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import case, func, or_, select, text, update

from . import audit, events
from .models import (
    Agent,
    Board,
    BoardAgentAccess,
    Project,
    Task,
    TaskActivity,
    TaskComment,
    TaskNotification,
    now,
)

STATUSES = {"backlog": "Backlog", "ready": "Ready", "in_progress": "In progress",
            "blocked": "Blocked", "review": "Review", "done": "Done"}
PRIORITIES = {0: "Urgent", 1: "High", 2: "Normal", 3: "Low"}
Status = Literal["backlog", "ready", "in_progress", "blocked", "review", "done"]


class TaskError(ValueError):
    def __init__(self, code, message, latest_version=None):
        super().__init__(message)
        self.code, self.latest_version = code, latest_version

    def payload(self):
        return {"error": self.code, "message": str(self), "latest_version": self.latest_version}


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProjectCreate(Input):
    key: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=4000)


class TaskFields(Input):
    title: str = Field(min_length=1, max_length=240)
    description: str = Field(default="", max_length=64000)
    notes: str = Field(default="", max_length=64000)
    acceptance: str = Field(default="", max_length=16000)
    status: Status = "backlog"
    priority: int = Field(default=2, ge=0, le=3)
    due_date: date | None = None
    labels: list[str] = Field(default_factory=list, max_length=20)
    assignee: str = Field(default="unassigned", max_length=100)


class TaskCreate(TaskFields):
    board_id: str | None = None
    project_id: str | None = None


class TaskPatch(Input):
    expected_version: int = Field(ge=1)
    title: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=64000)
    notes: str | None = Field(default=None, max_length=64000)
    acceptance: str | None = Field(default=None, max_length=16000)
    status: Status | None = None
    priority: int | None = Field(default=None, ge=0, le=3)
    due_date: date | None = None
    labels: list[str] | None = Field(default=None, max_length=20)
    assignee: str | None = Field(default=None, max_length=100)
    archived: bool | None = None
    before_id: str | None = None


class TaskFilter(Input):
    board_id: str | None = None
    project_id: str | None = None
    assignee: str | None = None
    status: Status | None = None
    priority: int | None = Field(default=None, ge=0, le=3)
    q: str = Field(default="", max_length=240)
    needs_you: bool = False
    include_done: bool = False
    include_archived: bool = False
    offset: int = Field(default=0, ge=0, le=1000000)
    limit: int = Field(default=60, ge=1, le=100)


def actor(agent):
    return "agent:" + agent.id if agent else "owner"


async def lock(db):
    if db.bind.dialect.name == "sqlite":
        await db.execute(text("BEGIN IMMEDIATE"))
    else:
        await db.execute(text("SELECT pg_advisory_xact_lock(74182020)"))


async def seed(conn):
    # Called once at startup before workers; the unique key also protects identity.
    if not await conn.scalar(select(Board.id).where(Board.key == "kw")):
        await conn.execute(Board.__table__.insert().values(id="brd_kw", key="kw", name="Keywright", kind="general"))


async def active_agent(db, agent):
    if agent is not None:
        current = await db.get(Agent, agent.id, populate_existing=True)
        if not current or current.disabled:
            raise TaskError("forbidden", "Agent is disabled or unavailable.")


async def board_access(db, board_id, agent, capability="read", writable=False):
    await active_agent(db, agent)
    board = await db.get(Board, board_id)
    if not board:
        raise TaskError("not_found", "Board not found.")
    if agent:
        access = await db.get(BoardAgentAccess, (board.id, agent.id), populate_existing=True)
        if not access or not access.read or not getattr(access, capability):
            raise TaskError("forbidden", "Board access is not granted.")
    project = await db.get(Project, board.project_id) if board.project_id else None
    if writable and project and project.archived:
        raise TaskError("invalid_transition", "Unarchive the project before changing its tasks.")
    return board


async def list_boards(db, agent=None, include_archived=False, offset=0, limit=100):
    await active_agent(db, agent)
    offset, limit = max(0, offset), min(100, max(1, limit))
    stmt = select(Board, Project).outerjoin(Project, Board.project_id == Project.id)
    if agent:
        stmt = stmt.join(BoardAgentAccess, BoardAgentAccess.board_id == Board.id).where(
            BoardAgentAccess.agent_id == agent.id, BoardAgentAccess.read.is_(True))
    if not include_archived:
        stmt = stmt.where(or_(Project.id.is_(None), Project.archived.is_(False)))
    rows = (await db.execute(stmt.order_by(Board.kind, Board.name, Board.id)
                            .offset(offset).limit(limit + 1))).all()
    return {"boards": [{"id": b.id, "key": b.key, "name": b.name, "kind": b.kind,
                        "project_id": b.project_id, "archived": bool(p and p.archived),
                        "project_version": p.version if p else None,
                        "description": p.description if p else "Tasks without a project"}
                       for b, p in rows[:limit]], "next_offset": offset + limit if len(rows) > limit else None}


async def commit(db, kind, **fields):
    await db.commit()
    events.publish("work.changed", kind=kind, **fields)


async def create_project(db, data: ProjectCreate):
    await lock(db)
    if not data.name.strip():
        raise TaskError("invalid_arguments", "Project name cannot be blank.")
    if await db.scalar(select(Project.id).where(Project.key == data.key)):
        raise TaskError("conflict", "Project key is already in use.")
    project = Project(**data.model_dump())
    db.add(project)
    await db.flush()
    board = Board(key="project_" + project.id, name=project.name, kind="project", project_id=project.id)
    db.add(board)
    await db.flush()
    await audit.record(db, tool="work.project.create", decision="saved", detail={"project_id": project.id}, commit=False)
    await commit(db, "project", board_id=board.id)
    return {"project_id": project.id, "board_id": board.id, "version": project.version}


async def archive_project(db, project_id, expected_version, archived):
    await lock(db)
    changed = await db.execute(update(Project).where(Project.id == project_id, Project.version == expected_version)
                              .values(archived=archived, version=Project.version + 1))
    if changed.rowcount != 1:
        raise TaskError("stale_version", "Project changed or is unavailable. Refresh and retry.")
    await audit.record(db, tool="work.project.archive", decision="saved",
                       detail={"project_id": project_id, "archived": archived}, commit=False)
    await commit(db, "project")


async def set_access(db, board_id, agent_id, permissions):
    await lock(db)
    await board_access(db, board_id, None)
    target = await db.get(Agent, agent_id)
    if not target:
        raise TaskError("invalid_assignee", "Unknown agent.")
    if any(k not in {"read", "write", "claim", "request_human_action"} for k in permissions):
        raise TaskError("invalid_arguments", "Unknown permission.")
    row = await db.get(BoardAgentAccess, (board_id, agent_id))
    if not row:
        row = BoardAgentAccess(board_id=board_id, agent_id=agent_id)
        db.add(row)
    for key in ("read", "write", "claim", "request_human_action"):
        setattr(row, key, bool(permissions.get(key, False)))
    if not row.read:
        row.write = row.claim = row.request_human_action = False
    await audit.record(db, tool="work.board.access", decision="saved",
                       detail={"board_id": board_id, "agent_id": agent_id, "permissions": permissions}, commit=False)
    await commit(db, "access", board_id=board_id)


async def resolve_board(db, board_id, project_id, agent):
    if project_id:
        destination = await db.scalar(select(Board).where(Board.project_id == project_id))
        if not destination:
            raise TaskError("not_found", "Project not found.")
        if board_id and board_id != destination.id:
            raise TaskError("invalid_arguments", "Project and board disagree.")
        board_id = destination.id
    if not board_id:
        board_id = await db.scalar(select(Board.id).where(Board.key == "kw"))
    return await board_access(db, board_id, agent, "write", writable=True)


async def assignment(db, value, board_id):
    if value in ("owner", "unassigned"):
        return {"assignee_kind": value, "assignee_agent_id": None}
    if value.startswith("agent:"):
        target = await db.get(Agent, value[6:])
        access = await db.get(BoardAgentAccess, (board_id, value[6:]))
        if target and not target.disabled and access and access.read:
            return {"assignee_kind": "agent", "assignee_agent_id": target.id}
    raise TaskError("invalid_assignee", "Choose the owner, unassigned, or an enabled agent with board access.")


def validate_fields(data):
    if "title" in data:
        data["title"] = data["title"].strip()
        if not data["title"] or any(ord(c) < 32 for c in data["title"]):
            raise TaskError("invalid_arguments", "Use a nonblank, single-line title.")
    if "labels" in data:
        if any(not v.strip() or len(v) > 60 or any(ord(c) < 32 for c in v) for v in data["labels"]):
            raise TaskError("invalid_arguments", "Labels must contain 1–60 printable characters.")
        data["labels"] = list(dict.fromkeys(v.strip() for v in data["labels"]))


async def activity(db, task, agent, kind, data=None, notify=False):
    entry = TaskActivity(task_id=task.id, actor=actor(agent), kind=kind, data=data or {})
    db.add(entry)
    await db.flush()
    if notify:
        db.add(TaskNotification(task_id=task.id, activity_id=entry.id))
    await audit.record(db, tool="work.task." + kind, decision="saved", agent=agent,
                       detail={"task_id": task.id, "board_id": task.board_id}, commit=False)


async def create_task(db, data: TaskCreate, agent=None):
    await lock(db)
    board = await resolve_board(db, data.board_id, data.project_id, agent)
    values = data.model_dump(exclude={"board_id", "project_id", "assignee"})
    validate_fields(values)
    if agent and data.status not in ("backlog", "ready"):
        raise TaskError("invalid_transition", "Agents create Backlog or Ready tasks; active work requires claiming.")
    values.update(await assignment(db, data.assignee, board.id))
    position = await db.scalar(select(func.max(Task.position)).where(Task.board_id == board.id, Task.status == data.status))
    task = Task(board_id=board.id, creator=actor(agent), position=(position or 0) + 1024, **values)
    db.add(task)
    await db.flush()
    await activity(db, task, agent, "created", notify=task.assignee_kind == "owner")
    await commit(db, "task", task_id=task.id)
    return serialize(task, board, details=True)


def serialize(task, board, details=False):
    result = {"id": task.id, "board_id": board.id, "board_name": board.name, "board_kind": board.kind,
              "project_id": board.project_id, "title": task.title, "status": task.status,
              "priority": task.priority, "due_date": task.due_date.isoformat() if task.due_date else None,
              "labels": task.labels, "assignee": "agent:" + task.assignee_agent_id
              if task.assignee_kind == "agent" else task.assignee_kind,
              "version": task.version, "position": task.position, "archived": task.archived,
              "created_at": task.created_at.isoformat(), "updated_at": task.updated_at.isoformat()}
    if details:
        result.update(description=task.description, notes=task.notes, acceptance=task.acceptance, creator=task.creator)
    return result


async def list_tasks(db, filters: TaskFilter, agent=None):
    await active_agent(db, agent)
    stmt = select(Task, Board).join(Board, Task.board_id == Board.id).outerjoin(Project, Board.project_id == Project.id)
    if agent:
        stmt = stmt.join(BoardAgentAccess, BoardAgentAccess.board_id == Board.id).where(
            BoardAgentAccess.agent_id == agent.id, BoardAgentAccess.read.is_(True))
    if filters.board_id:
        await board_access(db, filters.board_id, agent)
        stmt = stmt.where(Task.board_id == filters.board_id)
    if filters.project_id:
        stmt = stmt.where(Board.project_id == filters.project_id)
    if not filters.include_archived:
        stmt = stmt.where(Task.archived.is_(False), or_(Project.id.is_(None), Project.archived.is_(False)))
    if filters.needs_you:
        if agent:
            raise TaskError("forbidden", "Needs you is the local owner's queue.")
        stmt = stmt.where(Task.assignee_kind == "owner", Task.status != "done", Task.archived.is_(False))
    elif not filters.include_done and filters.status != "done":
        stmt = stmt.where(Task.status != "done")
    if filters.status:
        stmt = stmt.where(Task.status == filters.status)
    if filters.priority is not None:
        stmt = stmt.where(Task.priority == filters.priority)
    if filters.assignee:
        if filters.assignee.startswith("agent:"):
            stmt = stmt.where(Task.assignee_agent_id == filters.assignee[6:])
        else:
            stmt = stmt.where(Task.assignee_kind == filters.assignee)
    if filters.q:
        stmt = stmt.where(Task.title.contains(filters.q, autoescape=True))
    count = await db.scalar(select(func.count()).select_from(stmt.subquery()))
    ordering = [Task.priority, Task.due_date.is_(None), Task.due_date, Task.id]
    if filters.board_id:
        ordering = [Task.position, Task.id]
    if filters.needs_you:
        ordering.insert(0, case((Task.status == "review", 0), (Task.status == "blocked", 1), else_=2))
    rows = (await db.execute(stmt.order_by(*ordering).offset(filters.offset).limit(filters.limit))).all()
    return {"tasks": [serialize(t, b) for t, b in rows], "total": count,
            "next_offset": filters.offset + filters.limit if filters.offset + filters.limit < count else None}


async def get_task(db, task_id, agent=None, offset=0, limit=50):
    offset, limit = max(0, offset), min(100, max(1, limit))
    task = await db.get(Task, task_id, populate_existing=True)
    if not task:
        raise TaskError("not_found", "Task not found.")
    board = await board_access(db, task.board_id, agent)
    data = serialize(task, board, details=True)
    for model, key in ((TaskActivity, "activity"), (TaskComment, "comments")):
        rows = list(await db.scalars(select(model).where(model.task_id == task_id)
                                    .order_by(model.created_at.desc(), model.id).offset(offset).limit(limit + 1)))
        data[key] = [{"id": r.id, "actor": r.actor, "created_at": r.created_at.isoformat(),
                      **({"body": r.body} if key == "comments" else {"kind": r.kind, "data": r.data})}
                     for r in rows[:limit]]
        data[key + "_next_offset"] = offset + limit if len(rows) > limit else None
    return data


async def update_task(db, task_id, data: TaskPatch, agent=None):
    await lock(db)
    task = await db.get(Task, task_id, populate_existing=True)
    if not task:
        raise TaskError("not_found", "Task not found.")
    board = await board_access(db, task.board_id, agent, "write", writable=True)
    if task.version != data.expected_version:
        raise TaskError("stale_version", "Task changed. Refresh before saving.", task.version)
    values = data.model_dump(exclude_unset=True, exclude={"expected_version", "before_id"})
    if any(v is None for k, v in values.items() if k != "due_date"):
        raise TaskError("invalid_arguments", "Only due date may be cleared with null.")
    validate_fields(values)
    if agent:
        if task.assignee_kind == "agent" and task.assignee_agent_id != agent.id:
            raise TaskError("forbidden", "Task is assigned to another agent.")
        if task.status in ("in_progress", "review") or values.get("status", task.status) in ("in_progress", "review", "done"):
            raise TaskError("invalid_transition", "Agent execution is not enabled; only planning edits are available.")
        if "archived" in values or "assignee" in values:
            raise TaskError("forbidden", "Reassignment and archiving require the owner.")
    was_owner, old_status = task.assignee_kind == "owner", task.status
    previous_assignee = "agent:" + task.assignee_agent_id if task.assignee_kind == "agent" else task.assignee_kind
    if "assignee" in values:
        requested_assignee = values.pop("assignee")
        if requested_assignee != previous_assignee:
            values.update(await assignment(db, requested_assignee, board.id))
    if task.archived and values.get("archived") is not False:
        raise TaskError("invalid_transition", "Unarchive the task before editing it.")
    status = values.get("status", task.status)
    if status != task.status or "before_id" in data.model_fields_set:
        ids = list(await db.scalars(select(Task.id).where(Task.board_id == board.id, Task.status == status,
                         Task.id != task.id, Task.archived.is_(False)).order_by(Task.position, Task.id)))
        if data.before_id and data.before_id not in ids:
            raise TaskError("invalid_arguments", "Order target must be in the same board and status.")
        index = ids.index(data.before_id) if data.before_id else len(ids)
        ids.insert(index, task.id)
        for rank, tid in enumerate(ids, 1):
            if tid == task.id:
                values["position"] = rank * 1024
            else:
                await db.execute(update(Task).where(Task.id == tid, Task.position != rank * 1024)
                                 .values(position=rank * 1024, version=Task.version + 1))
    changed = await db.execute(update(Task).where(Task.id == task.id, Task.version == data.expected_version)
                              .values(**values, version=Task.version + 1, updated_at=now()))
    if changed.rowcount != 1:
        raise TaskError("stale_version", "Task changed. Refresh before saving.")
    await db.refresh(task)
    notify = task.assignee_kind == "owner" and (not was_owner or (status == "review" and old_status != status))
    changes = {"fields": sorted(values)}
    if status != old_status:
        changes["status"] = {"from": old_status, "to": status}
    current_assignee = "agent:" + task.assignee_agent_id if task.assignee_kind == "agent" else task.assignee_kind
    if current_assignee != previous_assignee:
        changes["assignee"] = {"from": previous_assignee, "to": current_assignee}
    await activity(db, task, agent, "updated", changes, notify=notify)
    await commit(db, "task", task_id=task.id)
    return serialize(task, board, details=True)


async def comment(db, task_id, body, idempotency_key, agent=None):
    if not isinstance(body, str) or not body.strip() or len(body) > 16000:
        raise TaskError("invalid_arguments", "Comment must contain 1–16,000 characters.")
    if not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 100:
        raise TaskError("invalid_arguments", "Supply an idempotency key of 1–100 characters.")
    await lock(db)
    task = await db.get(Task, task_id)
    if not task:
        raise TaskError("not_found", "Task not found.")
    await board_access(db, task.board_id, agent, "write", writable=True)
    existing = await db.scalar(select(TaskComment).where(TaskComment.task_id == task_id,
                              TaskComment.actor == actor(agent), TaskComment.idempotency_key == idempotency_key))
    if existing:
        if existing.body != body:
            raise TaskError("conflict", "Idempotency key was already used for another comment.")
        await db.commit()
        return {"id": existing.id}
    entry = TaskComment(task_id=task_id, actor=actor(agent), body=body, idempotency_key=idempotency_key)
    db.add(entry)
    await activity(db, task, agent, "commented")
    await commit(db, "comment", task_id=task.id)
    return {"id": entry.id}


async def move_task(db, task_id, board_id, expected_version):
    """Owner-only entry point. Moving transfers task visibility, never resource permissions."""
    await lock(db)
    task = await db.get(Task, task_id, populate_existing=True)
    if not task:
        raise TaskError("not_found", "Task not found.")
    await board_access(db, task.board_id, None, writable=True)
    destination = await board_access(db, board_id, None, writable=True)
    if task.version != expected_version:
        raise TaskError("stale_version", "Task changed. Refresh before moving it.", task.version)
    if task.assignee_kind == "agent":
        await assignment(db, "agent:" + task.assignee_agent_id, board_id)
    last = await db.scalar(select(func.max(Task.position)).where(Task.board_id == board_id, Task.status == task.status))
    old_board = task.board_id
    changed = await db.execute(update(Task).where(Task.id == task_id, Task.version == expected_version)
                              .values(board_id=board_id, position=(last or 0) + 1024,
                                      version=Task.version + 1, updated_at=now()))
    if changed.rowcount != 1:
        raise TaskError("stale_version", "Task changed. Refresh before moving it.")
    await db.refresh(task)
    await activity(db, task, None, "moved", {"from_board_id": old_board, "to_board_id": board_id})
    await commit(db, "task", task_id=task_id)
    return serialize(task, destination, details=True)
