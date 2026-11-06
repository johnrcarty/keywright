"""Native work tools: authenticated identity and board permissions are always server supplied."""
import mcp_types as types
from pydantic import Field, ValidationError

from . import tasks


class Boards(tasks.Input):
    include_archived: bool = False
    offset: int = Field(default=0, ge=0, le=1000000)
    limit: int = Field(default=100, ge=1, le=100)


class Get(tasks.Input):
    task_id: str
    offset: int = Field(default=0, ge=0, le=1000000)
    limit: int = Field(default=50, ge=1, le=100)


class Update(tasks.TaskPatch):
    task_id: str


class Comment(tasks.Input):
    task_id: str
    body: str = Field(min_length=1, max_length=16000)
    idempotency_key: str = Field(min_length=1, max_length=100)


OPERATIONS = {
    "work_list_boards": (Boards, "List authorized project boards and General; grants no host access."),
    "work_list_tasks": (tasks.TaskFilter, "List tasks across authorized boards, or filter to one project/board."),
    "work_get_task": (Get, "Read an authorized task with local comments and activity."),
    "work_create_task": (tasks.TaskCreate, "Create a local Backlog/Ready task. Defaults to General, requiring explicit access."),
    "work_update_task": (Update, "Edit local planning fields with expected_version. Agent execution requires claiming; not available yet."),
    "work_comment_task": (Comment, "Append a local comment, deduplicated by task, actor and idempotency key."),
}


def list_tools():
    return [types.Tool(name=name, description=description, input_schema=model.model_json_schema(),
                       annotations=types.ToolAnnotations(read_only_hint=name in {
                           "work_list_boards", "work_list_tasks", "work_get_task"}))
            for name, (model, description) in OPERATIONS.items()]


async def execute(db, agent, name, arguments):
    try:
        data = OPERATIONS[name][0].model_validate(arguments)
    except ValidationError:
        raise tasks.TaskError("invalid_arguments", "Invalid work arguments; consult the tool schema.") from None
    if name == "work_list_boards":
        return await tasks.list_boards(db, agent, **data.model_dump())
    if name == "work_list_tasks":
        return await tasks.list_tasks(db, data, agent)
    if name == "work_get_task":
        return await tasks.get_task(db, agent=agent, **data.model_dump())
    if name == "work_create_task":
        return await tasks.create_task(db, data, agent)
    if name == "work_update_task":
        return await tasks.update_task(db, data.task_id,
                                      tasks.TaskPatch(**data.model_dump(exclude={"task_id"}, exclude_unset=True)), agent)
    return await tasks.comment(db, agent=agent, **data.model_dump())
