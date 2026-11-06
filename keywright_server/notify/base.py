from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from .. import semantic
from ..audit import _scrub
from ..models import AccessRequest, Agent, Nudge


@dataclass
class Field:
    """One input on the driver's settings form. Rendered generically by the admin UI."""

    name: str
    label: str
    type: str = "text"  # text | password | url | textarea | select | multiselect | checkbox
    help: str = ""
    required: bool = False
    options: list[tuple[str, str]] = field(default_factory=list)  # (value, label) for selects
    options_from_probe: str = ""  # key in ProbeResult.choices to populate options dynamically


@dataclass
class ProbeResult:
    ok: bool
    message: str = ""
    info: dict[str, Any] = field(default_factory=dict)
    choices: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # field name -> options


DecisionCallback = Callable[[str], Awaitable[None]]  # receives a signed decision token


class Notifier(ABC):
    id: str = ""
    label: str = ""
    description: str = ""
    fields: ClassVar[list[Field]] = []
    supports_actions: bool = False  # can render decision buttons (vs. links only)
    max_actions: int = 3

    def __init__(self, config: dict[str, Any]):
        self.config = config

    @abstractmethod
    async def probe(self) -> ProbeResult:
        """Validate the config and discover selectable targets. Never raises."""

    @abstractmethod
    async def send(self, req: AccessRequest, agent: Agent, links: dict[str, str], buttons: list[str]) -> None:
        """Deliver the request. `links` maps scope -> signed decision URL (temporary approval scopes and deny).
        `buttons` is the ordered subset of scopes to render as actions when supported."""

    def capped(self, buttons: list[str]) -> list[str]:
        """At most `max_actions` buttons, deny last and never the one that is dropped."""
        allow = [b for b in buttons if b != "deny"]
        if "deny" in buttons:
            return [*allow[:self.max_actions - 1], "deny"]
        return allow[:self.max_actions]

    async def clear(self, req: AccessRequest) -> None:
        """Called after a decision; drivers may retract the notification."""

    async def send_nudge(self, nudge: Nudge, agent: Agent, url: str) -> None:
        """Deliver "the agent needs you in the conversation". No decision comes back: the human
        goes to the conversation. `url` opens the dashboard, where the nudge can also be cleared."""
        raise NotImplementedError

    async def clear_nudge(self, nudge: Nudge) -> None:
        """Called once the human has cleared it; drivers may retract the notification."""

    async def send_task(self, event_id: str, url: str) -> None:
        """Notify the owner without copying private task content or offering access decisions."""
        raise NotImplementedError

    async def start(self, on_decision: DecisionCallback) -> None:
        """Optional: start a background listener that feeds decisions back."""

    async def stop(self) -> None:
        """Optional: stop the background listener."""


registry: dict[str, type[Notifier]] = {}


def register(cls: type[Notifier]) -> type[Notifier]:
    registry[cls.id] = cls
    return cls


def request_summary(req: AccessRequest, agent: Agent) -> tuple[str, str]:
    from keywright.hazards import blocks, describe

    from ..access import binds_exactly, hazard_level, hazards_of, operations, path_scoped

    level = hazard_level(req.detail)
    title = f"Keywright DESTRUCTIVE ({level}): {agent.name}" if blocks(level) else f"Keywright: {agent.name}"
    groups = (req.detail or {}).get("bundles") or {}
    grouped = {p for ps in groups.values() for p in ps}
    lines = [f"bundle {name} ({len(ps)} patterns)" for name, ps in groups.items()]
    lines += [p for p in req.patterns if p not in grouped]
    pats = "\n".join(lines)
    body = f"{pats}\n{req.reason}".strip()
    if req.detail.get("shopping_session"):
        return f"Keywright shopping: {agent.name}", body + "\nAllow browsing and cart preparation for 20 minutes in this session. Purchases require a separate priced approval."
    if req.detail.get("checkout"):
        quote = req.detail["checkout"]
        lines = [f"{item['quantity']} × {item['item']['name']}" +
                 (f" — {item['special_instructions']}" if item.get("special_instructions") else "") for item in quote["items"]]
        body += f"\nTotal ${quote['total_cents'] / 100:.2f} {quote['currency']} including ${quote['tip_cents'] / 100:.2f} tip"
        body += "\n" + quote["payment"]["display_name"] + "\n" + "\n".join(lines)
        body += "\nReview destination, options and full price breakdown in the request. This priced order only, once."
        return f"Keywright checkout: {agent.name}", body
    if level:
        body = f"FLAGGED {level}: {describe(hazards_of(req.detail))}\n" + body
    jev = semantic.describe(getattr(req, "semantic", None))
    if jev:
        body += "\n" + jev
    ops = [op for _, op in operations(req.detail)]
    operation = "\n".join(operation_line(op) for op in ops)
    if operation:
        body += "\n" + operation[:300]
        if len(operation) > 300:
            body += "\n[Preview shortened. Open the request to review full details.]"
    users = {op.get("user") for op in ops if op.get("user")}
    if users:
        body += f"\nRemote user: {', '.join(sorted(users))}"
    if blocks(level):
        body += "\nScope: this exact operation, once. Timed and standing access are not offered."
    elif len(ops) > 1:
        body += f"\nScope: these {len(ops)} operations exactly, each for every duration."
    elif path_scoped(req.detail):
        body += ("\nScope: these exact contents for every duration; 'This path, 15 min' allows any contents at "
                 "this path for 15 minutes.")
    elif binds_exactly(req.detail):
        body += "\nScope: exact operation for every duration. Open the request to approve broader patterns."
    else:
        body += "\nScope: the listed permission patterns."
    return title, body


def nudge_summary(nudge: Nudge, agent: Agent) -> tuple[str, str]:
    """Title and body for a nudge, in the shape the phone shows it."""
    title = f"Keywright: {agent.name} needs you"
    lines = [nudge.message]
    where = " \u00b7 ".join(x for x in (nudge.context, nudge.session_id) if x)
    if where:
        lines.append(where)
    return title, "\n".join(lines)


def operation_line(op: dict) -> str:
    """One line per operation, as the phone shows it: a command line, a file write as path, size and
    digest (never the contents), a file read as its path, or a tool call's arguments."""
    if op.get("checkout"):
        quote = op["checkout"]
        return f"DoorDash order · ${quote['total_cents'] / 100:.2f} {quote['currency']} · {quote['payment']['display_name']}"
    if op.get("shopping_session"):
        return "Browse and prepare a DoorDash cart · 20 minutes · purchases approved separately"
    if op.get("command"):
        if op.get("to_path"):
            how = "append to" if op.get("append") else "write"
            return f"$ {op['command']}\n  output -> {how} {op.get('to_host')}:{op['to_path']} (not returned to the agent)"
        return f"$ {op['command']}"
    if "sha256" in op:
        return f"put {op.get('path')} ({op.get('bytes', '?')} bytes, sha256 {str(op['sha256'])[:12]})"
    if "path" in op:
        return f"get {op['path']}"
    if "arguments" in op:
        return json.dumps(_scrub(op["arguments"]), ensure_ascii=False)
    return ""
