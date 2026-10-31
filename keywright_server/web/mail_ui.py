"""Owner-authenticated inbox, rule editor, and delivery history."""
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import func, or_, select

from .. import audit, mail, settings_store
from ..db import session
from ..models import Agent, MailMessage, MailRule, Resource
from . import auth
from .admin import redirect, render
from .security import require_same_origin

router = APIRouter(dependencies=[Depends(require_same_origin), Depends(auth.require_admin)])


async def get_message(db, cfg, identifier):
    message = await db.get(MailMessage, identifier)
    if not message or message.source != mail.source(cfg):
        raise HTTPException(404, "Message not found")
    return message


@router.get('/ui/mail')
async def inbox(request: Request, selected: str = '', status: str = '', q: str = '', page: int = 1,
                view: str = 'inbox'):
    async with session() as db:
        cfg = await mail.config(db)
        conditions = [MailMessage.source == mail.source(cfg)]
        if view != 'history':
            conditions.append(MailMessage.present.is_(True))
        if status in mail.STATUS:
            conditions.append(MailMessage.status == status)
        if q:
            conditions.append(or_(MailMessage.subject.contains(q[:200], autoescape=True),
                                  MailMessage.sender.contains(q[:200], autoescape=True)))
        total = await db.scalar(select(func.count()).select_from(MailMessage).where(*conditions))
        pages = max(1, (total + 49) // 50)
        page = max(1, min(page, pages))
        messages = (await db.scalars(select(MailMessage).where(*conditions)
                    .order_by(MailMessage.date.desc(), MailMessage.created_at.desc())
                    .offset((page - 1) * 50).limit(50))).all()
        message, error = None, ''
        if selected:
            message = await get_message(db, cfg, selected)
            try:
                await mail.body(db, cfg, message)
            except mail.MailError as exc:
                error = str(exc)
        counts = dict((await db.execute(select(MailMessage.status, func.count()).where(
            MailMessage.source == mail.source(cfg), MailMessage.present.is_(True)
        ).group_by(MailMessage.status))).all())
        return render(request, 'mail.html', cfg=cfg, messages=messages, message=message, counts=counts,
                      statuses=mail.STATUS, selected=selected, status=status, q=q, page=page, pages=pages,
                      total=total, view=view, error=error)


@router.post('/ui/mail/sync')
async def sync_mail():
    async with mail.lock, session() as db:
        try:
            await mail.sync(db, await mail.config(db))
        except mail.MailError as exc:
            return redirect('/ui/mail', str(exc))
        except Exception:  # noqa: BLE001 - upstream connection failures must not expose credentials
            return redirect('/ui/mail', 'Mailbox sync failed. Check the email connection and audit log.')
    return redirect('/ui/mail', 'Inbox refreshed.')


@router.post('/ui/mail/{identifier}/run')
async def run_message(identifier: str):
    async with mail.lock, session() as db:
        cfg = await mail.config(db)
        message = await get_message(db, cfg, identifier)
        if message.status == 'failed' and message.plan:
            # Keep the original plan and receipts: a retry never silently changes destinations.
            message.status, message.request_id = 'queued', None
            await db.commit()
        else:
            await mail.queue(db, cfg, message)
        if message.status in {'queued', 'running', 'pending'}:
            await mail.advance(db, cfg, message)
        await audit.record(db, tool='mail_run', decision='allow', detail={'message': identifier})
    return redirect('/ui/mail?selected=' + identifier)


@router.get('/ui/mail/{identifier}/attachment')
async def download(identifier: str, name: str):
    async with session() as db:
        cfg = await mail.config(db)
        message = await get_message(db, cfg, identifier)
        try:
            await mail.verify_message(db, cfg, message)
            content = await mail.attachment(db, cfg, message, name)
        except mail.MailError as exc:
            return redirect('/ui/mail?selected=' + identifier, str(exc))
    return Response(content, media_type='application/pdf', headers={
        'Content-Disposition': "attachment; filename*=UTF-8''" + quote(name, safe=''),
        'Cache-Control': 'no-store',
    })


@router.get('/ui/mail/rules')
async def rule_page(request: Request, edit: str = ''):
    async with session() as db:
        entries = await mail.rules(db)
        rule = await db.get(MailRule, edit) if edit else None
        return render(request, 'mail_rules.html', rules=entries, rule=rule)


@router.post('/ui/mail/rules/save')
async def save_rule(request: Request):
    form = await request.form()
    async with mail.lock, session() as db:
        identifier = str(form.get('id') or '')
        rule = await db.get(MailRule, identifier) if identifier else MailRule()
        if rule is None:
            raise HTTPException(404, 'Rule not found')
        name, sender, subject = (str(form.get(k) or '').strip() for k in ('name', 'sender', 'subject'))
        action, target = str(form.get('action') or ''), str(form.get('target') or '').strip()
        if not name or len(name) > 120 or not (sender or subject) or len(sender) > 320 or len(subject) > 200:
            return redirect('/ui/mail/rules', 'Give the rule a name and a sender or subject filter.')
        if action not in {'pdf', 'mark_read', 'move'} or (action == 'move' and not target):
            return redirect('/ui/mail/rules', 'Choose an action and a destination folder when moving mail.')
        if len(target) > 200 or any(ord(c) < 32 for c in target):
            return redirect('/ui/mail/rules', 'Use a valid destination folder name.')
        try:
            position = int(str(form.get('position') or '100'))
            if not 0 <= position <= 9999:
                raise ValueError()
        except ValueError:
            return redirect('/ui/mail/rules', 'Priority must be between 0 and 9999.')
        rule.name, rule.sender, rule.subject = name, sender, subject
        rule.action, rule.target, rule.position = action, target, position
        rule.enabled = form.get('enabled') == 'on'
        db.add(rule)
        await db.flush()
        await audit.record(db, tool='mail_rule_save', decision='allow', detail={'rule': rule.id, 'action': action})
    return redirect('/ui/mail/rules', 'Rule saved. It applies to new mail; use Run rules for existing messages.')


@router.post('/ui/mail/rules/{identifier}/toggle')
async def toggle_rule(identifier: str):
    async with mail.lock, session() as db:
        rule = await db.get(MailRule, identifier)
        if not rule:
            raise HTTPException(404, 'Rule not found')
        rule.enabled = not rule.enabled
        await audit.record(db, tool='mail_rule_toggle', decision='allow', detail={'rule': identifier, 'enabled': rule.enabled})
    return redirect('/ui/mail/rules')


@router.get('/ui/mail/settings')
async def settings_page(request: Request):
    async with session() as db:
        cfg = await mail.config(db)
        resources = (await db.scalars(select(Resource).where(Resource.kind == 'mcp').order_by(Resource.name))).all()
        agents = (await db.scalars(select(Agent).where(Agent.disabled_at.is_(None)).order_by(Agent.name))).all()
        return render(request, 'mail_settings.html', cfg=cfg, resources=resources, agents=agents)


@router.post('/ui/mail/settings')
async def save_settings(request: Request):
    form = await request.form()
    async with mail.lock, session() as db:
        cfg = await mail.config(db)
        resource = await db.get(Resource, str(form.get('resource') or ''))
        agent = await db.get(Agent, str(form.get('agent') or ''))
        if not resource or resource.kind != 'mcp' or not agent or agent.disabled:
            return redirect('/ui/mail/settings', 'Choose an email resource and an enabled agent.')
        try:
            endpoint = mail.budget_url(str(form.get('budget_url'))) if form.get('budget_url') else ''
            account, mailbox = (str(form.get(k) or '').strip() for k in ('account', 'mailbox'))
            if not account or not mailbox or max(len(account), len(mailbox)) > 200:
                raise mail.MailError('Account and mailbox are required (up to 200 characters).')
            token = str(form.get('budget_token') or '').strip()
            if token and (not token.startswith('ba_docs_') or len(token) > 200):
                raise mail.MailError('Use a document delivery token from Budget settings.')
            if endpoint != cfg.get('budget_url', '') and endpoint and not token:
                raise mail.MailError('Enter a delivery token when changing the budget server.')
        except mail.MailError as exc:
            return redirect('/ui/mail/settings', str(exc))
        updated = {**cfg, 'resource': resource.id, 'agent': agent.id, 'account': account, 'mailbox': mailbox,
                   'budget_url': endpoint, 'budget_token': token or cfg.get('budget_token', ''),
                   'enabled': form.get('enabled') == 'on'}
        await settings_store.put(db, 'mail', updated)
        await audit.record(db, tool='mail_settings_save', decision='allow', detail={
            'resource': resource.id, 'agent': agent.id, 'enabled': updated['enabled']})
    return redirect('/ui/mail/settings', 'Connection saved. Refresh the inbox to check access.')
