import base64
import hashlib
import json

import httpx
import mcp_types as types
import pytest
import respx
from sqlalchemy import select

from keywright_server import mail, mcp_proxy, settings_store
from keywright_server.models import MailMessage, MailRule, Policy, Resource

PDF = b'%PDF-1.4\nsynthetic electric bill\n%%EOF'
META = {'email_id': '41', 'message_id': '<bill-41@example.test>', 'sender': 'Utility <billing@power.test>',
        'recipients': ['agents@example.test'], 'subject': 'Your electric bill',
        'date': '2026-10-17T12:00:00+00:00', 'attachments': ['electric.pdf']}


def result(data):
    return types.CallToolResult(content=[types.TextContent(type='text', text=json.dumps(data))])


@pytest.fixture
async def mailbox(db, agent, monkeypatch):
    resource = Resource(name='email', kind='mcp', default_mode='open', config={'url': 'http://email.test/mcp'})
    db.add(resource)
    await db.commit()
    cfg = {'resource': resource.id, 'agent': agent.id, 'account': 'agents', 'mailbox': 'INBOX',
           'enabled': True, 'budget_url': 'http://budget.test/api/integrations/documents', 'budget_token': 'ba_docs_test'}
    await settings_store.put(db, 'mail', cfg)
    messages, calls = [dict(META)], []

    async def upstream(config, tool, arguments):
        calls.append((tool, arguments))
        if tool == 'list_emails_metadata':
            return result({'emails': messages, 'total': len(messages)})
        if tool == 'get_emails_content':
            return result({'emails': [{**m, 'body': 'Amount due in the attached statement.'}
                                     for m in messages if m['email_id'] in arguments['email_ids']]})
        if tool == 'get_attachment_content':
            return types.CallToolResult(content=[types.EmbeddedResource(type='resource', resource=types.BlobResourceContents(
                uri='email-attachment://content/test', mime_type='application/pdf', blob=base64.b64encode(PDF).decode()))])
        return result({'success': True})

    monkeypatch.setattr(mcp_proxy, 'call_tool', upstream)
    return cfg, resource, messages, calls


async def index(db, mailbox):
    await mail.sync(db, mailbox[0])
    return await db.scalar(select(MailMessage))


async def add_rule(db, **changes):
    row = MailRule(name='Electric bill', sender='billing@power.test', subject='electric', action='pdf', **changes)
    db.add(row)
    await db.commit()
    return row


async def test_first_sync_indexes_read_and_unread_without_processing(db, mailbox):
    await add_rule(db)
    message = await index(db, mailbox)
    assert message.status == 'unprocessed'
    assert 'seen' not in mailbox[3][0][1]
    cfg = await mail.config(db)
    mailbox[2].append({**META, 'email_id': '42', 'message_id': '<bill-42@example.test>'})
    await mail.sync(db, cfg)
    new = await db.scalar(select(MailMessage).where(MailMessage.uid == '42'))
    assert new.status == 'queued' and new.plan['name'] == 'Electric bill'
    assert message.status == 'unprocessed'


async def test_pdf_delivered_then_marked_read_and_retry_does_not_upload_twice(db, mailbox, monkeypatch):
    await add_rule(db)
    message = await index(db, mailbox)
    await mail.queue(db, mailbox[0], message)
    uploads = []

    async def upload(cfg, message, name, content):
        assert content == PDF
        assert not any(t == 'mark_emails_as_read' for t, _ in mailbox[3])
        uploads.append(name)
        return {'id': 1, 'sha256': hashlib.sha256(content).hexdigest()}

    monkeypatch.setattr(mail, 'upload', upload)
    original = mcp_proxy.call_tool
    attempts = 0

    async def upstream(config, tool, arguments):
        nonlocal attempts
        if tool == 'mark_emails_as_read':
            attempts += 1
            if attempts == 1:
                raise ConnectionError('synthetic timeout')
        return await original(config, tool, arguments)

    monkeypatch.setattr(mcp_proxy, 'call_tool', upstream)
    await mail.advance(db, mailbox[0], message)
    assert message.status == 'failed' and 'electric.pdf' in message.receipts
    # Simulate reopening the database session after a process restart.
    from keywright_server.db import session
    async with session() as reopened:
        persisted = await reopened.get(MailMessage, message.id)
        await mail.advance(reopened, mailbox[0], persisted)
        assert persisted.status == 'done' and persisted.receipts['marked_read']
    assert uploads == ['electric.pdf']


async def test_failed_delivery_never_marks_read(db, mailbox, monkeypatch):
    await add_rule(db)
    message = await index(db, mailbox)
    await mail.queue(db, mailbox[0], message)

    async def fail(*args):
        raise mail.MailError('Budget delivery returned HTTP 503.')

    monkeypatch.setattr(mail, 'upload', fail)
    await mail.advance(db, mailbox[0], message)
    assert message.status == 'failed' and '503' in message.note
    assert not any(t == 'mark_emails_as_read' for t, _ in mailbox[3])


async def test_attachment_policy_is_enforced(db, mailbox, agent):
    await add_rule(db)
    message = await index(db, mailbox)
    db.add(Policy(agent_id=agent.id, pattern='mcp/email/tools/get_attachment_content', effect='deny'))
    await db.commit()
    await mail.queue(db, mailbox[0], message)
    await mail.advance(db, mailbox[0], message)
    assert message.status == 'failed'
    assert not any(t == 'get_attachment_content' for t, _ in mailbox[3])


async def test_pending_approval_parks_job_without_repeated_calls(db, mailbox, agent, log_notifier):
    await add_rule(db)
    message = await index(db, mailbox)
    mailbox[1].default_mode = 'approval'
    await db.commit()
    await mail.queue(db, mailbox[0], message)
    await mail.advance(db, mailbox[0], message)
    assert message.status == 'pending' and message.request_id
    before = len(mailbox[3])
    await mail.advance(db, mailbox[0], message)
    assert len(mailbox[3]) == before


async def test_first_match_and_rule_edit_do_not_change_queued_destination(db, mailbox):
    first = await add_rule(db, position=10)
    await add_rule(db, position=20)
    message = await index(db, mailbox)
    await mail.queue(db, mailbox[0], message)
    assert message.plan['rule_id'] == first.id
    first.action = 'move'
    await db.commit()
    await mail.queue(db, mailbox[0], message)
    assert message.plan['action'] == 'pdf'
    with pytest.raises(mail.MailError, match='changed'):
        await mail.upload({**mailbox[0], 'budget_url': 'http://other.test'}, message, 'electric.pdf', PDF)


async def test_missing_or_changed_message_cannot_send_attachment(db, mailbox):
    await add_rule(db)
    message = await index(db, mailbox)
    await mail.queue(db, mailbox[0], message)
    mailbox[2][0]['message_id'] = '<different-message@example.test>'
    await mail.advance(db, mailbox[0], message)
    assert message.status == 'failed' and 'identity' in message.note
    assert not any(t == 'get_attachment_content' for t, _ in mailbox[3])


async def test_missing_pdf_fails_and_disappeared_mail_stays_in_history(db, mailbox):
    mailbox[2][0]['attachments'] = []
    await add_rule(db)
    message = await index(db, mailbox)
    await mail.queue(db, mailbox[0], message)
    await mail.advance(db, mailbox[0], message)
    assert message.status == 'failed' and 'no PDF' in message.note
    mailbox[2].clear()
    await mail.sync(db, await mail.config(db))
    assert not message.present and message.status == 'failed'


@respx.mock
async def test_upload_verifies_receipt_and_never_follows_redirects(db, mailbox):
    message = await index(db, mailbox)
    message.plan = {'destination': mailbox[0]['budget_url']}
    route = respx.post(mailbox[0]['budget_url']).mock(return_value=httpx.Response(201, json={
        'id': 5, 'sha256': hashlib.sha256(PDF).hexdigest()}))
    assert (await mail.upload(mailbox[0], message, 'electric.pdf', PDF))['id'] == 5
    assert route.calls[0].request.content == PDF
    route.mock(return_value=httpx.Response(302, headers={'Location': 'http://other.test'}))
    with pytest.raises(mail.MailError, match='302'):
        await mail.upload(mailbox[0], message, 'electric.pdf', PDF)
    route.mock(return_value=httpx.Response(201, json={'id': 5, 'sha256': 'wrong'}))
    with pytest.raises(mail.MailError, match='checksum'):
        await mail.upload(mailbox[0], message, 'electric.pdf', PDF)


@pytest.mark.parametrize('url', ['file:///etc/passwd', 'https://user:password@budget.test',
                                  'http://budget.test?token=x', 'http://budget.test/other'])
def test_budget_url_requires_explicit_fixed_intake(url):
    with pytest.raises(mail.MailError):
        mail.budget_url(url)


async def test_inbox_ui_auth_escape_and_csrf(db, mailbox):
    from keywright_server.web import auth
    from keywright_server.web.app import create_app
    mailbox[2][0]['subject'] = '<script>alert("unsafe")</script>'
    message = await index(db, mailbox)
    await auth.set_password(db, 'mail-test-password')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url='http://test',
                                 headers={'Origin': 'http://test'}) as client:
        assert (await client.get('/ui/mail')).status_code == 303
        await client.post('/ui/login', data={'password': 'mail-test-password'})
        response = await client.get('/ui/mail', params={'selected': message.id})
        assert response.status_code == 200
        assert '&lt;script&gt;' in response.text and '<script>alert' not in response.text
        assert 'mark_emails_as_read' not in [t for t, _ in mailbox[3]]
        assert next(a for t, a in mailbox[3] if t == 'get_emails_content')['mark_as_read'] is False
        for path in ('rules', 'settings'):
            response = await client.get('/ui/mail/' + path)
            assert response.status_code == 200
            assert 'ba_docs_test' not in response.text
        assert (await client.post('/ui/mail/sync', headers={'Origin': 'http://evil.test'})).status_code == 403
        assert (await client.post('/ui/mail/rules/save', data={'name': 'invalid', 'action': 'pdf'})).status_code == 303
        assert await db.scalar(select(MailRule)) is None
