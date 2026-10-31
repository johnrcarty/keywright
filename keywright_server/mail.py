"""Inbox cache and owner-configured mail automations; mailbox calls retain broker policy checks.

The UI worker is opt-in and independent of the legacy YAML router. Disable overlapping
legacy rules before enabling it. A first sync only indexes mail; existing mail is processed
only by an explicit Run rules action. Delivery receipts survive retries and process restarts.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
from email.utils import parseaddr
from fnmatch import fnmatchcase
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select

from . import audit, settings_store
from .db import session
from .models import AccessRequest, Agent, MailMessage, MailRule, Resource, now

log = logging.getLogger(__name__)
MAX_PDF = 5 * 1024 * 1024  # upstream's 8 MiB serialized result must also fit base64
STATUS = {"unprocessed": "Unprocessed", "queued": "Queued", "running": "Processing",
          "pending": "Waiting for approval", "done": "Completed", "failed": "Failed"}
lock = asyncio.Lock()


class MailError(Exception):
    pass


class Pending(MailError):
    def __init__(self, request_id):
        self.request_id = request_id
        super().__init__("Waiting for Keywright approval")


def source(cfg):
    return hashlib.sha256(json.dumps([cfg.get(k) for k in ("resource", "account", "mailbox")]).encode()).hexdigest()


def budget_url(value):
    url = urlsplit(value.strip())
    if (url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path.rstrip('/') not in {'', '/api/integrations/documents'}):
        raise MailError("Enter the budget server URL, without credentials, a query, or an ingress path.")
    return f"{url.scheme}://{url.netloc}/api/integrations/documents"


async def config(db):
    cfg = await settings_store.get(db, "mail")
    return {"account": "agents", "mailbox": "INBOX", "enabled": False, **cfg}


def payload(result):
    data = getattr(result, "structured_content", None)
    if isinstance(data, dict):
        return data
    for block in result.content:
        if getattr(block, "type", None) == "text":
            try:
                data = json.loads(block.text)
                if isinstance(data, dict):
                    return data
            except (ValueError, TypeError):
                pass
    return {}


async def call(db, cfg, tool, args):
    from .mcp_server import _proxy_call
    agent = await db.get(Agent, cfg.get("agent")) if cfg.get("agent") else None
    resource = await db.get(Resource, cfg.get("resource")) if cfg.get("resource") else None
    if not agent or agent.disabled or not resource or resource.kind != "mcp":
        raise MailError("Choose an enabled agent and an email resource in Mail settings.")
    result = await _proxy_call(db, agent, "mail-inbox", resource.name, tool,
                               {**args, "_reason": "Mailbox UI and saved mail rules", "_wait_seconds": 0})
    if result.is_error:
        data = payload(result)
        if data.get("error") == "approval_required" and data.get("request_id"):
            raise Pending(data["request_id"])
        # Do not surface upstream errors that might contain credentials or message contents.
        raise MailError(f"Email operation {tool} failed. Check Keywright’s audit log and email service settings.")
    return result


def mail_args(cfg):
    return {"account_name": cfg["account"], "mailbox": cfg["mailbox"]}


def matches(rule, message):
    return ((not rule.sender or fnmatchcase(parseaddr(message.sender)[1].lower(), rule.sender.lower()))
            and (not rule.subject or rule.subject.lower() in message.subject.lower()))


def snapshot(rule, cfg):
    return {"rule_id": rule.id, "name": rule.name, "action": rule.action, "target": rule.target,
            "destination": cfg.get("budget_url", "") if rule.action == "pdf" else ""}


async def rules(db):
    return list((await db.scalars(select(MailRule).order_by(MailRule.position, MailRule.created_at))).all())


async def queue(db, cfg, message):
    if message.status in {"done", "running", "pending", "queued"}:
        return
    selected = next((r for r in await rules(db) if r.enabled and matches(r, message)), None)
    if not selected:
        message.note = "No enabled rule matched."
        await db.commit()
        return
    message.plan = snapshot(selected, cfg)
    message.status, message.note, message.request_id = "queued", "", None
    message.updated_at = now()
    await db.commit()


async def sync(db, cfg):
    if not cfg.get("resource"):
        raise MailError("Connect the mailbox in Mail settings first.")
    identity = source(cfg)
    initial = cfg.get("indexed_source") != identity
    existing = {m.id: m for m in (await db.scalars(select(MailMessage).where(MailMessage.source == identity))).all()}
    seen = set()
    active_rules = [r for r in await rules(db) if r.enabled]
    for page in range(1, 101):  # upstream caps metadata candidates at 10,000
        data = payload(await call(db, cfg, "list_emails_metadata", {
            **mail_args(cfg), "page": page, "page_size": 100, "order": "desc"}))
        if not isinstance(data.get("emails"), list):
            raise MailError("Email service returned an invalid message list.")
        for meta in data["emails"]:
            uid = str(meta["email_id"])
            # Include immutable headers as well as Message-ID: some senders omit/reuse that header.
            fingerprint = [identity, uid, *(str(meta.get(k) or '') for k in ('message_id', 'sender', 'subject', 'date'))]
            key = hashlib.sha256(json.dumps(fingerprint).encode()).hexdigest()
            seen.add(key)
            message = existing.get(key)
            if not message:
                message = MailMessage(id=key, source=identity, uid=uid)
                db.add(message)
                existing[key] = message
            message.message_id = str(meta.get("message_id") or "")
            for field in ("sender", "subject", "date"):
                setattr(message, field, str(meta.get(field) or "")[:4000])
            message.recipients = list(meta.get("recipients") or [])[:100]
            message.attachments = list(meta.get("attachments") or [])[:20]
            message.present = True
            if message in db.new and not initial and cfg.get("enabled"):
                rule = next((r for r in active_rules if matches(r, message)), None)
                if rule:
                    message.status, message.plan = "queued", snapshot(rule, cfg)
        await db.commit()  # message discovery and its initial job are durable together
        if len(data["emails"]) < 100 or page * 100 >= int(data.get("total") or 0):
            break
    else:
        raise MailError("Mailbox exceeds the 10,000-message sync limit; move older mail to another folder.")
    for key, message in existing.items():
        if key not in seen:
            message.present = False
    await db.commit()
    # Re-read configuration so a concurrent settings save cannot be overwritten.
    latest = await config(db)
    if source(latest) == identity:
        await settings_store.put(db, "mail", {**latest, "indexed_source": identity,
                                              "last_sync": now().isoformat(), "sync_error": ""})


async def body(db, cfg, message):
    if message.body is not None:
        return
    data = payload(await call(db, cfg, "get_emails_content", {
        **mail_args(cfg), "email_ids": [message.uid], "mark_as_read": False, "max_body_length": 50000}))
    entries = data.get("emails") or []
    if not entries or (str(entries[0].get("message_id") or "") != message.message_id):
        raise MailError("Message is no longer available at this mailbox location. Refresh the inbox.")
    message.body = str(entries[0].get("body") or "")
    await db.commit()


async def attachment(db, cfg, message, name):
    if name not in message.attachments or not name.lower().endswith('.pdf'):
        raise MailError("Choose a PDF attachment from this message.")
    result = await call(db, cfg, "get_attachment_content", {
        **mail_args(cfg), "email_id": message.uid, "attachment_name": name})
    blobs = [b.resource.blob for b in result.content
             if getattr(b, "type", None) == "resource" and hasattr(b.resource, "blob")]
    if len(blobs) != 1 or len(blobs[0]) > (MAX_PDF + 2) // 3 * 4:
        raise MailError("The email service did not return a PDF within the 5 MiB transfer limit.")
    try:
        data = base64.b64decode(blobs[0], validate=True)
    except (ValueError, TypeError) as exc:
        raise MailError("The email service returned invalid attachment data.") from exc
    if len(data) > MAX_PDF or not data.startswith(b'%PDF-'):
        raise MailError("Attachment is not a PDF or exceeds the 5 MiB transfer limit.")
    return data


async def verify_message(db, cfg, message):
    data = payload(await call(db, cfg, "get_emails_content", {
        **mail_args(cfg), "email_ids": [message.uid], "mark_as_read": False, "max_body_length": 1}))
    entries = data.get("emails") or []
    if (not entries or str(entries[0].get("message_id") or "") != message.message_id
            or str(entries[0].get("sender") or "")[:4000] != message.sender
            or str(entries[0].get("subject") or "")[:4000] != message.subject):
        raise MailError("Message identity changed or the message moved. Refresh the inbox before processing.")


async def upload(cfg, message, name, content):
    endpoint = message.plan.get("destination")
    if not endpoint or endpoint != cfg.get("budget_url") or not cfg.get("budget_token"):
        raise MailError("The budget destination is missing or has changed. Restore it before retrying this delivery.")
    # URL is fixed by the owner, never taken from the email. Never follow a redirect with the token.
    async with httpx.AsyncClient(timeout=60, follow_redirects=False) as http:
        response = await http.post(endpoint, content=content,
            headers={"Authorization": "Bearer " + cfg["budget_token"], "Content-Type": "application/pdf"},
            params={"filename": name, "source_id": message.id, "sender": message.sender[:320],
                    "subject": message.subject[:500]})
    if response.status_code not in (200, 201):
        raise MailError(f"Budget delivery returned HTTP {response.status_code}. Check the connection and retry.")
    try:
        receipt = response.json()
        if receipt["sha256"] != hashlib.sha256(content).hexdigest() or not isinstance(receipt["id"], int):
            raise ValueError()
    except (ValueError, KeyError, TypeError) as exc:
        raise MailError("Budget did not confirm the PDF checksum. Retry to verify delivery.") from exc
    return {"id": receipt["id"], "sha256": receipt["sha256"]}


async def advance(db, cfg, message):
    if message.status == "pending" and message.request_id:
        request = await db.get(AccessRequest, message.request_id)
        if request and request.status == "pending":
            return
        if not request or request.status != "approved":
            message.status, message.note = "failed", "Access approval was denied or expired."
            await db.commit()
            return
    message.status, message.request_id = "running", None
    await db.commit()
    try:
        if source(cfg) != message.source:
            raise MailError("The mailbox connection changed. Restore it before retrying this job.")
        await verify_message(db, cfg, message)
        action = message.plan.get("action")
        if action == "pdf":
            names = [a for a in message.attachments if isinstance(a, str) and a.lower().endswith('.pdf')]
            if not names:
                raise MailError("This message has no PDF attachment.")
            if len(set(names)) != len(names):
                raise MailError("Attachments have duplicate filenames; delivery needs manual review.")
            for name in names:
                if name in message.receipts:
                    continue
                if len(name) > 200 or any(c in name for c in '/\\') or any(ord(c) < 32 for c in name):
                    raise MailError("The PDF filename cannot be delivered safely; download it for manual review.")
                content = await attachment(db, cfg, message, name)
                receipt = await upload(cfg, message, name, content)
                message.receipts = {**message.receipts, name: receipt}
                await audit.record(db, tool="mail_pdf_delivery", decision="allow", detail={
                    "message": message.id, "rule": message.plan.get("name"), "receipt": receipt})
        elif action == "move" and not message.receipts.get("moved"):
            await call(db, cfg, "move_emails", {"account_name": cfg["account"], "email_ids": [message.uid],
                "source_mailbox": cfg["mailbox"], "destination_mailbox": message.plan["target"]})
            message.receipts = {"moved": True}
            message.present = False
        elif action != "mark_read" and action != "move":
            raise MailError("Unknown mail action.")
        if action != "move" and not message.receipts.get("marked_read"):
            await call(db, cfg, "mark_emails_as_read", {**mail_args(cfg), "email_ids": [message.uid]})
            message.receipts = {**message.receipts, "marked_read": True}
        message.status, message.note = "done", "PDFs delivered to Budget." if action == "pdf" else "Rule completed."
    except Pending as exc:
        message.status, message.note, message.request_id = "pending", str(exc), exc.request_id
    except MailError as exc:
        message.status, message.note = "failed", str(exc)
    except Exception:  # noqa: BLE001 - persist a safe, retryable failure without upstream secrets
        message.status, message.note = "failed", "The service could not finish this job. Retry when the connection is available."
        log.warning("Mail job %s failed", message.id)  # no upstream secrets or email content
    message.updated_at = now()
    await db.commit()


async def tick():
    async with lock, session() as db:
        cfg = await config(db)
        if not cfg.get("enabled"):
            return
        try:
            await sync(db, cfg)
        except Exception as exc:  # noqa: BLE001 - keep jobs moving when mailbox sync is unavailable
            latest = await config(db)
            await settings_store.put(db, "mail", {**latest, "sync_error": str(exc) if isinstance(exc, MailError)
                                                  else "Mailbox sync failed. Check the connection and access permissions."})
        jobs = (await db.scalars(select(MailMessage).where(
            MailMessage.source == source(cfg), MailMessage.status.in_(["queued", "running", "pending"])
        ).order_by(MailMessage.created_at).limit(50))).all()
        for message in jobs:
            await advance(db, cfg, message)


async def worker():
    while True:
        try:
            await tick()
        except Exception:  # noqa: BLE001 - one cycle must not stop the worker
            log.warning("Mail worker could not complete a cycle")
        await asyncio.sleep(60)
