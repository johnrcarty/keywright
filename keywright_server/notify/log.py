"""Fallback driver: writes requests to the log. Decisions come from the admin UI."""

from __future__ import annotations

import logging
from typing import ClassVar

from ..models import AccessRequest, Agent, Nudge
from .base import Notifier, ProbeResult, nudge_summary, register, request_summary

log = logging.getLogger("keywright.notify")


@register
class LogNotifier(Notifier):
    id = "log"
    label = "Log only (decide in the admin UI)"
    description = "No push channel. Pending requests show on the dashboard."
    fields: ClassVar[list] = []

    async def probe(self) -> ProbeResult:
        return ProbeResult(ok=True, message="Nothing to configure.")

    async def send(self, req: AccessRequest, agent: Agent, links: dict[str, str], buttons: list[str]) -> None:
        title, body = request_summary(req, agent)
        log.warning("ACCESS REQUEST %s\n%s\n%s\ndecide: %s", req.id, title, body, links.get("once", "").rsplit("/", 1)[0])

    async def send_nudge(self, nudge: Nudge, agent: Agent, url: str) -> None:
        title, body = nudge_summary(nudge, agent)
        log.warning("NEEDS YOU %s\n%s\n%s\nclear: %s", nudge.id, title, body, url)
