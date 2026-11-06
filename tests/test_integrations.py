import re
from html import unescape
from urllib.parse import urlsplit

import httpx
import pytest

from keywright_server import homelab, integrations, mcp_oauth
from keywright_server.config import settings
from keywright_server.models import Resource
from keywright_server.web import auth
from keywright_server.web.app import create_app


@pytest.fixture
async def browser(db, monkeypatch):
    monkeypatch.setattr(settings, "public_url", "https://kw.test")
    monkeypatch.setattr(settings, "auth_mode", "password")
    await auth.set_password(db, "fixture-password")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="https://kw.test",
                                headers={"Origin": "https://kw.test"}) as client:
        await client.post("/ui/login", data={"password": "fixture-password"})
        yield client


async def test_picker_search_and_legacy_links(browser):
    picker = await browser.get("/ui/resources/new")
    assert picker.status_code == 200
    assert picker.text.index("integration=notion") < picker.text.index("kind=ssh")
    assert "integration=omada" in picker.text and "integration=keywright" in picker.text
    assert 'name="url"' not in picker.text
    search = await browser.get("/ui/resources/new", params={"q": "WiFi"})
    assert "1 connection available" in search.text
    empty = await browser.get("/ui/resources/new", params={"q": "unavailable vendor"})
    assert "0 connections available" in empty.text
    for query in ("kind=ssh", "kind=mcp", "kind=llm", "kind=mcp&adapter=omada", "kind=mcp&adapter=keywright"):
        assert (await browser.get("/ui/resources/new?" + query)).status_code == 200
    assert (await browser.get("/ui/resources/new?integration=missing")).status_code == 303
    assert (await browser.get("/ui/resources/new?kind=missing")).status_code == 303


@pytest.mark.parametrize("integration,title,endpoint,consent", [
    ("notion", "Notion", "https://mcp.notion.com/mcp", "https://mcp.notion.com/authorize"),
    ("coinstats", "CoinStats", "https://mcp.coinstats.app/mcp", "https://coinstats.app/openapi/consent"),
    ("robinhood", "Robinhood", "https://agent.robinhood.com/mcp/trading", "https://robinhood.com/oauth"),
])
async def test_oauth_preset_enforces_defaults_and_continues_to_sign_in(
    browser, db, monkeypatch, integration, title, endpoint, consent,
):
    form = await browser.get("/ui/resources/new?integration=" + integration)
    assert f'value="{title}"' in form.text and f"Continue to {title}" in form.text
    assert '<select name="auth_type">' not in form.text
    for origin in integrations.PRESET_BY_ID[integration].oauth_origins:
        assert origin in form.text
    seen = []

    async def begin(config, browser_cookie, admin_cookie):
        assert browser_cookie and admin_cookie
        seen.append(config)
        assert await mcp_oauth.status(config) == "disconnected"
        return consent + "?state=fixture"

    monkeypatch.setattr(mcp_oauth, "begin", begin)
    saved = await browser.post("/ui/resources", data={
        "kind": "mcp", "name": title, "integration": integration, "setup_action": "connect",
        "url": "https://wrong.test/mcp", "auth_type": "headers",
    })
    assert saved.status_code == 200
    link = re.search(r'id="oauth-continue"[^>]*href="([^"]+)"', saved.text)
    assert link and urlsplit(unescape(link[1])).hostname == urlsplit(consent).hostname
    assert "form-action 'self'" in saved.headers["content-security-policy"]
    assert len(seen) == 1 and seen[0]["url"] == endpoint
    assert seen[0]["auth_type"] == "oauth" and seen[0]["integration"] == integration
    assert seen[0]["oauth"]["origins"] == list(integrations.PRESET_BY_ID[integration].oauth_origins)
    from sqlalchemy import select
    res = (await db.execute(select(Resource))).scalar_one()
    assert res.default_mode == "approval"
    edit = await browser.get("/ui/resources/" + res.id)
    assert title in edit.text and f'value="{integration}"' in edit.text
    oauth_id = res.config["oauth_id"]
    saved = await browser.post("/ui/resources", data={
        "rid": res.id, "kind": "mcp", "name": title, "integration": integration,
    })
    assert saved.status_code == 303
    await db.refresh(res)
    assert res.config["oauth_id"] == oauth_id
    changed = await browser.post("/ui/resources", data={
        "rid": res.id, "kind": "mcp", "name": title, "integration": "omada",
    })
    assert changed.status_code == 303
    await db.refresh(res)
    assert res.config["integration"] == integration


@pytest.mark.parametrize("integration,query", [("coinstats", "coinstats portfolio"), ("robinhood", "equities options")])
async def test_finance_preset_search(browser, integration, query):
    page = await browser.get("/ui/resources/new", params={"q": query})
    assert "1 connection available" in page.text
    assert re.search(rf'href="/ui/resources/new\?integration={integration}"\s*>', page.text)


@pytest.mark.parametrize("integration,title", [("coinbase", "Coinbase"), ("doordash", "DoorDash")])
async def test_cli_ssh_setup_and_edit(browser, db, integration, title):
    picker = await browser.get("/ui/resources/new", params={"q": integration + " cli"})
    assert "1 connection available" in picker.text
    assert re.search(rf'href="/ui/resources/new\?integration={integration}"\s*>', picker.text)
    form = await browser.get("/ui/resources/new?integration=" + integration)
    assert form.status_code == 200 and f'value="{title}"' in form.text
    assert f'name="user" value="{integration}"' in form.text
    assert 'name="api_secret"' not in form.text and 'name="oauth_client_id"' not in form.text
    assert "Test connection checks SSH connectivity only" in form.text
    assert integrations.PRESET_BY_ID[integration].cli_verify_command in unescape(form.text)
    if integration == "doordash":
        assert "DD_CLI_ACCESS_TOKEN" in form.text
    fields = {"kind": "mcp", "name": title, "integration": integration,
              "host": integration + ".example.test", "user": integration, "port": "2222"}
    saved = await browser.post("/ui/resources", data=fields)
    assert saved.status_code == 303
    rid = saved.headers["location"].rsplit("/", 1)[-1]
    resource = await db.get(Resource, rid)
    assert resource.kind == "ssh" and resource.default_mode == "approval"
    assert resource.config["integration"] == integration and "oauth_id" not in resource.config
    assert resource.config["host"] == fields["host"] and resource.config["port"] == 2222
    edit = await browser.get("/ui/resources/" + rid)
    assert f'name="integration" value="{integration}"' in edit.text and f"{title} setup guide" in edit.text
    saved = await browser.post("/ui/resources", data={**fields, "rid": rid, "port": "22"})
    assert saved.status_code == 303
    await db.refresh(resource)
    assert resource.config["port"] == 22 and integrations.for_resource(resource).id == integration
    resource.kind = "mcp"
    assert integrations.for_resource(resource) is None


@pytest.mark.parametrize("integration,title,command", [
    ("coinbase", "Coinbase", "coinbase balance"),
    ("doordash", "DoorDash", 'dd-cli order history --intent "Check past orders"'),
    ("doordash", "DoorDash", 'dd-cli order submit --cart-uuid fixture-cart --tip-cents 300 --yes --intent "Submit confirmed cart"'),
])
async def test_cli_commands_require_approval(browser, db, agent, fake_ssh, log_notifier, integration, title, command):
    from keywright_server import approvals, mcp_server

    await browser.post("/ui/resources", data={
        "kind": "ssh", "name": title, "integration": integration,
        "host": integration + ".example.test", "user": integration,
    })
    args = {"host": title, "command": command, "reason": "Verify CLI approval", "wait_seconds": 0}
    denied = await mcp_server._ssh_run(db, agent, None, args)
    if integration == "doordash" and "order submit" in command:
        assert denied.structured_content["error"] == "invalid_arguments"
        assert "kw shop" in denied.structured_content["hint"]
        assert fake_ssh == []
        return
    assert denied.structured_content["error"] == "approval_required"
    assert fake_ssh == []
    await approvals.decide(db, denied.structured_content["request_id"], "once", via="ui")
    result = await mcp_server._ssh_run(db, agent, None, args)
    assert result.structured_content["exit_code"] == 0
    if integration == "doordash":
        import shlex

        assert fake_ssh[0][0] == integration + ".example.test"
        assert shlex.split(shlex.split(fake_ssh[0][1])[-1]) == shlex.split(command)
        assert fake_ssh[0][2] == integration
    else:
        assert fake_ssh == [(integration + ".example.test", command, integration)]
    again = await mcp_server._ssh_run(db, agent, None, args)
    assert again.structured_content["error"] == "approval_required"
    assert len(fake_ssh) == 1


async def test_builtin_preset_needs_no_endpoint_or_credentials(browser, db):
    saved = await browser.post("/ui/resources", data={
        "kind": "mcp", "name": "Keywright", "integration": "keywright",
    })
    assert saved.status_code == 303
    rid = saved.headers["location"].rsplit("/", 1)[-1]
    resource = await db.get(Resource, rid)
    assert resource.config["adapter"] == "keywright" and "url" not in resource.config
    assert resource.config["integration"] == "keywright"


async def test_invalid_preset_does_not_create_resource(browser, db):
    from sqlalchemy import func, select
    result = await browser.post("/ui/resources", data={"kind": "mcp", "name": "Bad", "integration": "missing"})
    assert result.status_code == 303
    assert await db.scalar(select(func.count()).select_from(Resource)) == 0


def test_legacy_notion_recognition_requires_matching_endpoint_and_oauth():
    resource = Resource(kind="mcp", name="Existing", config={"url": "https://mcp.notion.com/mcp", "auth_type": "oauth"})
    assert integrations.for_resource(resource).id == "notion"
    resource.config = {**resource.config, "url": "https://other.test/mcp"}
    assert integrations.for_resource(resource) is None


@pytest.mark.parametrize("adapter", homelab.CONNECTORS)
async def test_homelab_setup_edit_preserves_secrets(browser, db, adapter):
    form = await browser.get("/ui/resources/new", params={"integration": adapter})
    assert form.status_code == 200 and 'name="api_secret"' in form.text
    assert "Read-only" in (await browser.get("/ui/resources/new")).text
    fields = {"kind": "mcp", "name": "TestService", "integration": adapter,
              "url": "https://service.test", "api_secret": "fixture-connector-private",
              "token_id": "reader@pve!inventory", "verify_tls": "1"}
    saved = await browser.post("/ui/resources", data=fields)
    assert saved.status_code == 303
    rid = saved.headers["location"].rsplit("/", 1)[-1]
    resource = await db.get(Resource, rid)
    assert resource and resource.config["adapter"] == adapter
    assert resource.default_mode == "approval" and resource.config["verify_tls"] is True
    edit = await browser.get("/ui/resources/" + rid)
    assert fields["api_secret"] not in edit.text and 'name="api_secret"' in edit.text
    assert 'name="headers"' not in edit.text and 'name="oauth_client_id"' not in edit.text
    saved = await browser.post("/ui/resources", data={**fields, "rid": rid, "api_secret": "", "verify_tls": "0"})
    assert saved.status_code == 303
    await db.refresh(resource)
    assert resource.config["api_secret"] == fields["api_secret"] and resource.config["verify_tls"] is False
    assert integrations.for_resource(resource).id == adapter
    await browser.post("/ui/resources", data={**fields, "rid": rid, "api_secret": "replacement-private"})
    await db.refresh(resource)
    assert resource.config["api_secret"] == "replacement-private"


@pytest.mark.parametrize("field,value", [("url", "https://user:pw@service.test"), ("api_secret", ""),
                                         ("token_id", "missing-realm"), ("verify_tls", "maybe")])
async def test_invalid_connector_form_does_not_save(browser, db, field, value):
    from sqlalchemy import func, select

    fields = {"kind": "mcp", "name": "Invalid", "integration": "proxmox", "url": "https://service.test",
              "api_secret": "fixture-private", "token_id": "reader@pve!inventory"}
    result = await browser.post("/ui/resources", data={**fields, field: value})
    assert result.status_code == 303
    assert await db.scalar(select(func.count()).select_from(Resource)) == 0
