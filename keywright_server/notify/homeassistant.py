"""Home Assistant driver.

Sends actionable notifications through any `notify.*` service HA exposes (the companion app's
`notify.mobile_app_*` services are the useful ones) and listens on HA's websocket for
`mobile_app_notification_action` events so a tap on the phone becomes a decision without any
HA automation. Everything is discovered from the HA instance with a long-lived access token.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import Any, ClassVar

import httpx
import websockets

from ..models import AccessRequest, Agent, Nudge
from .base import (
    DecisionCallback,
    Field,
    Notifier,
    ProbeResult,
    nudge_summary,
    register,
    request_summary,
)

log = logging.getLogger("keywright.notify.ha")
ACTION_PREFIX = "GK:"


@register
class HomeAssistantNotifier(Notifier):
    id = "homeassistant"
    label = "Home Assistant (companion app)"
    description = "Actionable push via notify.mobile_app_* services; taps come back over the HA websocket."
    supports_actions = True
    max_actions = 3  # Android caps at 3 buttons; iOS allows more but 3 keeps both consistent
    fields: ClassVar[list[Field]] = [
        Field("base_url", "Home Assistant URL", "url", required=True,
              help="e.g. http://homeassistant.local:8123 or your Nabu Casa URL"),
        Field("token", "Long-lived access token", "password", required=True,
              help="Profile -> Security -> Long-lived access tokens. Stored in the Keywright database."),
        Field("targets", "Notify services", "multiselect", options_from_probe="targets",
              help="Probe first, then pick the phones to notify."),
        Field("critical", "Mark as time-sensitive / high priority", "checkbox"),
    ]

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    # ---- helpers ----------------------------------------------------------------------------
    def _base(self) -> str:
        return self.config.get("base_url", "").rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.config.get('token', '')}", "Content-Type": "application/json"}

    def _ws_url(self) -> str:
        b = self._base()
        return b.replace("https://", "wss://", 1).replace("http://", "ws://", 1) + "/api/websocket"

    # ---- Notifier API -----------------------------------------------------------------------
    async def probe(self) -> ProbeResult:
        if not self._base() or not self.config.get("token"):
            return ProbeResult(ok=False, message="URL and token are required.")
        try:
            async with httpx.AsyncClient(timeout=10, headers=self._headers()) as c:
                cfg = await c.get(self._base() + "/api/config")
                if cfg.status_code == 401:
                    return ProbeResult(ok=False, message="HA rejected the token (401).")
                cfg.raise_for_status()
                svc = await c.get(self._base() + "/api/services")
                svc.raise_for_status()
        except httpx.HTTPError as e:
            return ProbeResult(ok=False, message=f"Could not reach Home Assistant: {e}")
        info = cfg.json()
        notify = next((d for d in svc.json() if d.get("domain") == "notify"), {})
        services = notify.get("services", {}) or {}
        targets: list[tuple[str, str]] = []
        for name, meta in sorted(services.items()):
            if name in ("send_message", "persistent_notification"):
                continue
            label = (meta or {}).get("name") or name
            if name.startswith("mobile_app_"):
                label = f"{label} (companion app)"
            targets.append((name, label))
        msg = f"Connected to {info.get('location_name', 'Home Assistant')} {info.get('version', '')}: " \
              f"{len(targets)} notify services."
        return ProbeResult(ok=True, message=msg, info={"location_name": info.get("location_name"),
                                                       "version": info.get("version")},
                           choices={"targets": targets})

    async def send(self, req: AccessRequest, agent: Agent, links: dict[str, str], buttons: list[str]) -> None:
        targets = self.config.get("targets") or []
        if not targets:
            raise RuntimeError("Home Assistant driver has no notify targets selected")
        title, body = request_summary(req, agent)
        from ..approvals import SCOPE_LABELS, notification_action

        # Compact action IDs are authenticated; knowledge of a request ID grants no authority.
        actions = [
            {"action": notification_action(req.id, s), "title": SCOPE_LABELS[s], "destructive": s == "deny"}
            for s in self.capped(buttons)
        ]
        open_url = links.get("once", "").rsplit("/d/", 1)[0] + f"/ui/requests/{req.id}"
        data: dict[str, Any] = {
            "tag": req.id,
            "group": "keywright",
            "actions": actions,
            "url": open_url,
            "clickAction": open_url,
            # Android: survive swipes and stay put until decided or expired (the server clears it).
            "persistent": True,
            "sticky": True,
            # iOS: show it even while the companion app is in the foreground.
            "presentation_options": ["alert", "sound", "badge"],
        }
        if self.config.get("critical"):
            data["push"] = {"interruption-level": "time-sensitive", "sound": "default"}
            data["ttl"] = 0
            data["priority"] = "high"
        payload = {"title": title, "message": body, "data": data}
        async with httpx.AsyncClient(timeout=15, headers=self._headers()) as c:
            for t in targets:
                r = await c.post(f"{self._base()}/api/services/notify/{t}", json=payload)
                if r.status_code >= 400:
                    log.error("HA notify.%s failed: %s %s", t, r.status_code, r.text[:200])

    async def send_nudge(self, nudge: Nudge, agent: Agent, url: str) -> None:
        targets = self.config.get("targets") or []
        if not targets:
            raise RuntimeError("Home Assistant driver has no notify targets selected")
        from ..nudges import dismiss_action

        title, body = nudge_summary(nudge, agent)
        # Nothing here is a decision, so the only button clears the card; tapping the body opens
        # the dashboard. Not marked critical even when approvals are: a question can wait for the
        # next time they look at their phone, a destructive command cannot.
        data: dict[str, Any] = {
            "tag": nudge.id,
            "group": "keywright-attention",
            "actions": [{"action": dismiss_action(nudge.id), "title": "Dismiss"}],
            "url": url,
            "clickAction": url,
            "persistent": True,
            "sticky": True,
            "presentation_options": ["alert", "sound", "badge"],
        }
        payload = {"title": title, "message": body, "data": data}
        async with httpx.AsyncClient(timeout=15, headers=self._headers()) as c:
            for t in targets:
                r = await c.post(f"{self._base()}/api/services/notify/{t}", json=payload)
                if r.status_code >= 400:
                    log.error("HA notify.%s failed: %s %s", t, r.status_code, r.text[:200])

    async def clear(self, req: AccessRequest) -> None:
        await self._clear_tag(req.id)

    async def clear_nudge(self, nudge: Nudge) -> None:
        await self._clear_tag(nudge.id)

    async def _clear_tag(self, tag: str) -> None:
        payload = {"message": "clear_notification", "data": {"tag": tag}}
        with contextlib.suppress(Exception):
            async with httpx.AsyncClient(timeout=10, headers=self._headers()) as c:
                for t in self.config.get("targets") or []:
                    await c.post(f"{self._base()}/api/services/notify/{t}", json=payload)

    async def start(self, on_decision: DecisionCallback) -> None:
        self._stop.clear()
        self._task = asyncio.create_task(self._listen(on_decision), name="ha-ws-listener")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None

    async def _listen(self, on_decision: DecisionCallback) -> None:
        backoff = 2
        while not self._stop.is_set():
            try:
                async with websockets.connect(self._ws_url(), max_size=2**20) as ws:
                    hello = json.loads(await ws.recv())
                    if hello.get("type") != "auth_required":
                        raise RuntimeError(f"unexpected hello {hello}")
                    await ws.send(json.dumps({"type": "auth", "access_token": self.config.get("token", "")}))
                    resp = json.loads(await ws.recv())
                    if resp.get("type") != "auth_ok":
                        log.error("HA websocket auth failed: %s", resp)
                        await asyncio.sleep(60)
                        continue
                    await ws.send(json.dumps({"id": 1, "type": "subscribe_events",
                                              "event_type": "mobile_app_notification_action"}))
                    log.info("HA websocket listener connected to %s", self._base())
                    backoff = 2
                    async for raw in ws:
                        msg = json.loads(raw)
                        if msg.get("type") != "event":
                            continue
                        action = ((msg.get("event") or {}).get("data") or {}).get("action") or ""
                        log.info("HA notification action received: %s", action[:24] + ("…" if len(action) > 24 else ""))
                        if action.startswith((ACTION_PREFIX, "KW_", "KWN_")):
                            try:
                                await on_decision(action)
                            except Exception:
                                log.exception("decision callback failed")
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                log.warning("HA websocket listener error: %s; retry in %ss", e, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)
