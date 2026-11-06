"""Owner-driven CLI setup on an existing managed SSH host."""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.exc import IntegrityError

from .. import audit, cli_setup
from ..db import session
from ..models import Resource
from . import auth
from .admin import redirect, render
from .security import require_same_origin

router = APIRouter(dependencies=[Depends(require_same_origin), Depends(auth.require_admin)])


@router.post("/ui/cli-setup/doordash")
async def create(request: Request):
    form = await request.form()
    name = str(form.get("name", "DoorDash")).strip()
    if not name or len(name) > 64 or not all(c.isascii() and (c.isalnum() or c in "_.-") for c in name):
        return redirect("/ui/resources/new?integration=doordash", "Choose a name using letters, numbers, _ . - only.")
    async with session() as db:
        host = await db.get(Resource, str(form.get("host_id", "")))
        if not host or host.kind != "ssh" or not host.config.get("key_path") or not host.config.get("host"):
            return redirect("/ui/resources/new?integration=doordash", "Choose an enrolled SSH host.")
        config = {key: host.config[key] for key in cli_setup.CONNECTION_KEYS if key in host.config}
        config.update(user=config.get("user") or "root", port=config.get("port") or 22)
        config.update(integration="doordash", cli_setup={"status": "new", "source_id": host.id, "source_name": host.name})
        res = Resource(name=name, kind="ssh", default_mode="approval", config=config,
                       description="DoorDash CLI on " + host.name)
        db.add(res)
        try:
            await db.flush()
            await audit.record(db, tool="cli.setup.create", decision="saved", detail={"resource": name, "host": host.name})
        except IntegrityError:
            await db.rollback()
            return redirect("/ui/resources/new?integration=doordash", "That connection name already exists.")
        rid = res.id
    return redirect(f"/ui/cli-setup/{rid}")


@router.get("/ui/cli-setup/{rid}")
async def page(request: Request, rid: str):
    async with session() as db:
        res = await db.get(Resource, rid)
    if not res or res.kind != "ssh" or res.config.get("integration") != "doordash" or not res.config.get("cli_setup"):
        return redirect("/ui/resources", "No managed DoorDash setup found.")
    state = cli_setup.state(res.config)
    return render(request, "cli_setup.html", res=res, setup=state, actions=cli_setup.allowed_actions(state))


@router.post("/ui/cli-setup/{rid}/{action}")
async def step(request: Request, rid: str, action: str):
    form = await request.form()
    try:
        await cli_setup.start(rid, action, str(form.get("value", "")))
    except ValueError as exc:
        return redirect(f"/ui/cli-setup/{rid}", str(exc))
    return redirect(f"/ui/cli-setup/{rid}")
