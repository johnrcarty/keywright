"""Generic webhook driver: POSTs the request as JSON. Works with ntfy, Pushover relays, n8n,
Slack incoming webhooks via a small template, or anything that can render links."""

from __future__ import annotations

from typing import ClassVar

import httpx

from ..models import AccessRequest, Agent, Nudge
from .base import Field, Notifier, ProbeResult, nudge_summary, register, request_summary


@register
class WebhookNotifier(Notifier):
    id = "webhook"
    label = "Webhook (JSON POST)"
    description = "POST {title, body, request, links} to a URL. Humans decide via the signed links."
    fields: ClassVar[list[Field]] = [
        Field("url", "Webhook URL", "url", required=True),
        Field("auth_header", "Authorization header value", "password", help="Optional, sent as-is."),
        Field("format", "Payload format", "select", options=[("json", "Keywright JSON"), ("ntfy", "ntfy.sh")]),
    ]

    async def probe(self) -> ProbeResult:
        url = self.config.get("url", "")
        if not url.startswith(("http://", "https://")):
            return ProbeResult(ok=False, message="URL must start with http:// or https://")
        return ProbeResult(ok=True, message="Saved. A test POST is sent on the first request.")

    async def send(self, req: AccessRequest, agent: Agent, links: dict[str, str], buttons: list[str]) -> None:
        from ..approvals import SCOPE_LABELS

        title, body = request_summary(req, agent)
        headers = {}
        if self.config.get("auth_header"):
            headers["Authorization"] = self.config["auth_header"]
        if self.config.get("format") == "ntfy":
            # ntfy rejects the whole message with a 400 when it carries more than three actions.
            shown = self.capped([s for s in buttons if s in links])
            actions = ", ".join(f"view, {SCOPE_LABELS[s]}, {links[s]}" for s in shown)
            headers.update({"Title": title, "Actions": actions, "Tags": "lock"})
            payload = body.encode()
            async with httpx.AsyncClient(timeout=10) as c:
                (await c.post(self.config["url"], content=payload, headers=headers)).raise_for_status()
            return
        payload = {
            "title": title,
            "body": body,
            "request": {
                "id": req.id, "agent": agent.name, "patterns": req.patterns, "reason": req.reason,
                "detail": req.detail, "created_at": req.created_at.isoformat(),
            },
            "links": links,
        }
        async with httpx.AsyncClient(timeout=10) as c:
            (await c.post(self.config["url"], json=payload, headers=headers)).raise_for_status()

    async def send_nudge(self, nudge: Nudge, agent: Agent, url: str) -> None:
        title, body = nudge_summary(nudge, agent)
        headers = {}
        if self.config.get("auth_header"):
            headers["Authorization"] = self.config["auth_header"]
        if self.config.get("format") == "ntfy":
            headers.update({"Title": title, "Actions": f"view, Open dashboard, {url}", "Tags": "speech_balloon"})
            async with httpx.AsyncClient(timeout=10) as c:
                (await c.post(self.config["url"], content=body.encode(), headers=headers)).raise_for_status()
            return
        payload = {
            "title": title,
            "body": body,
            "nudge": {
                "id": nudge.id, "agent": agent.name, "message": nudge.message, "context": nudge.context,
                "session": nudge.session_id, "created_at": nudge.created_at.isoformat(),
            },
            "links": {"open": url},
        }
        async with httpx.AsyncClient(timeout=10) as c:
            (await c.post(self.config["url"], json=payload, headers=headers)).raise_for_status()
