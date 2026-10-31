import re
from html import unescape
from urllib.parse import urlsplit

import httpx
import pytest

from keywright_server import integrations, mcp_oauth
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


async def test_notion_preset_enforces_defaults_and_continues_to_sign_in(browser, db, monkeypatch):
    form = await browser.get("/ui/resources/new?integration=notion")
    assert 'value="Notion"' in form.text and "Continue to Notion" in form.text
    assert '<select name="auth_type">' not in form.text
    seen = []

    async def begin(config, browser_cookie, admin_cookie):
        assert browser_cookie and admin_cookie
        seen.append(config)
        assert await mcp_oauth.status(config) == "disconnected"
        return "https://mcp.notion.com/authorize?state=fixture"

    monkeypatch.setattr(mcp_oauth, "begin", begin)
    saved = await browser.post("/ui/resources", data={
        "kind": "mcp", "name": "Notion", "integration": "notion", "setup_action": "connect",
        "url": "https://wrong.test/mcp", "auth_type": "headers",
    })
    assert saved.status_code == 200
    link = re.search(r'id="oauth-continue"[^>]*href="([^"]+)"', saved.text)
    assert link and urlsplit(unescape(link[1])).hostname == "mcp.notion.com"
    assert "form-action 'self'" in saved.headers["content-security-policy"]
    assert len(seen) == 1 and seen[0]["url"] == "https://mcp.notion.com/mcp"
    assert seen[0]["auth_type"] == "oauth" and seen[0]["integration"] == "notion"
    from sqlalchemy import select
    res = (await db.execute(select(Resource))).scalar_one()
    assert res.default_mode == "approval"
    edit = await browser.get("/ui/resources/" + res.id)
    assert "Notion" in edit.text and 'value="notion"' in edit.text
    changed = await browser.post("/ui/resources", data={
        "rid": res.id, "kind": "mcp", "name": "Notion", "integration": "omada",
    })
    assert changed.status_code == 303
    await db.refresh(res)
    assert res.config["integration"] == "notion"


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
