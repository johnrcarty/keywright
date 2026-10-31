"""Owns the active notifier. Config lives in settings["notifications"] =
{"driver": "<id>", "config": {...}, "buttons": ["once", "session", "deny"]}."""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from .. import audit
from ..db import session
from ..models import AccessRequest, Agent, Nudge
from ..settings_store import get as get_setting
from . import registry
from .base import Notifier

log = logging.getLogger("keywright.notify")
DEFAULT_BUTTONS = ["once", "session", "deny"]


class NotifierManager:
    def __init__(self) -> None:
        self.active: Notifier | None = None
        self.driver_id: str = "log"
        self.buttons: list[str] = list(DEFAULT_BUTTONS)
        self.last_error: str = ""

    async def reload(self) -> None:
        async with session() as db:
            cfg = await get_setting(db, "notifications", {"driver": "log", "config": {}, "buttons": DEFAULT_BUTTONS})
        await self._apply(cfg)

    async def _apply(self, cfg: dict[str, Any]) -> None:
        from ..approvals import PHONE_SCOPES
        if self.active:
            await self.active.stop()
        self.driver_id = cfg.get("driver") or "log"
        cls = registry.get(self.driver_id) or registry["log"]
        self.active = cls(cfg.get("config") or {})
        self.buttons = [b for b in (cfg.get("buttons") or DEFAULT_BUTTONS) if b in PHONE_SCOPES]
        if "deny" not in self.buttons:
            self.buttons.append("deny")
        await self.active.start(self.on_decision_token)
        log.info("notifier: %s", self.driver_id)

    async def stop(self) -> None:
        if self.active:
            await self.active.stop()

    async def notify_request(self, req: AccessRequest, agent: Agent) -> None:
        if not self.active:
            return
        from ..approvals import decision_links, offered_scopes

        scopes = offered_scopes(req)
        links = decision_links(req.id, scopes)
        try:
            await self.active.send(req, agent, links, [b for b in self.buttons if b in scopes])
            self.last_error = ""
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            log.exception("notifier %s failed for %s", self.driver_id, req.id)
            async with session() as db:
                await audit.record(db, tool="notify", decision="error", agent=agent, patterns=list(req.patterns),
                                   detail={"request_id": req.id, "driver": self.driver_id, "error": self.last_error})

    async def request_decided(self, req: AccessRequest) -> None:
        if self.active:
            await self.active.clear(req)

    async def notify_nudge(self, nudge: Nudge, agent: Agent) -> None:
        """Push "the agent needs you". A driver that cannot carry one just logs it: the dashboard
        card is created either way, so the ask is never lost because a channel is misconfigured."""
        if not self.active:
            return
        from ..approvals import public_url

        try:
            await self.active.send_nudge(nudge, agent, f"{public_url()}/ui")
            self.last_error = ""
        except NotImplementedError:
            log.info("notifier %s cannot carry nudges; %s is on the dashboard only", self.driver_id, nudge.id)
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            log.exception("notifier %s failed for nudge %s", self.driver_id, nudge.id)
            async with session() as db:
                await audit.record(db, tool="notify", decision="error", agent=agent,
                                   detail={"nudge_id": nudge.id, "driver": self.driver_id, "error": self.last_error})

    async def nudge_cleared(self, nudge: Nudge) -> None:
        if self.active:
            with contextlib.suppress(Exception):
                await self.active.clear_nudge(nudge)

    async def on_decision_token(self, action: str) -> None:
        """Accept authenticated compact actions or legacy signed tokens, never bare request IDs."""
        from .. import nudges
        from ..approvals import decide, parse_decision_token, parse_notification_action

        if action.startswith(nudges.DISMISS):
            nudge_id = nudges.parse_dismiss_action(action)
            if not nudge_id:
                log.warning("ignored unrecognised dismiss action from %s", self.driver_id)
                return
            async with session() as db:
                await nudges.clear(db, nudge_id, via=self.driver_id)
            log.info("nudge %s dismissed via %s", nudge_id, self.driver_id)
            return
        parsed = None
        if action.startswith(("KW_", "GK_")):
            parsed = parse_notification_action(action)
        elif action.startswith("GK:"):
            parsed = parse_decision_token(action[3:])
        else:
            parsed = parse_decision_token(action)
        if not parsed:
            log.warning("ignored unrecognised decision action from %s", self.driver_id)
            return
        request_id, scope = parsed
        async with session() as db:
            try:
                req = await decide(db, request_id, scope, via=self.driver_id)
            except (LookupError, ValueError) as e:
                # A tap that could not be applied (unknown request, or a lease whose key the gateway
                # would not mint) leaves the request pending; the dashboard says why.
                log.warning("decision for request %s not applied: %s", request_id, e)
                return
        log.info("decision via %s: %s -> %s (%s)", self.driver_id, request_id, req.status, scope)


manager = NotifierManager()
