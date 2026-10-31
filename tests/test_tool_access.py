"""The Access page (tools x one agent -> standing rules) and the hourly tool watch."""

from __future__ import annotations

import httpx
from mcp import types
from sqlalchemy import select

from keywright_server import tool_access
from keywright_server.models import AuditEvent, Policy, Resource


def tool(name, props=(), read_only=None, destructive=None, description=""):
    ann = None if read_only is None and destructive is None else types.ToolAnnotations(
        read_only_hint=read_only, destructive_hint=destructive)
    return types.Tool(name=name, description=description, annotations=ann,
                      input_schema={"type": "object", "properties": {p: {"type": "string"} for p in props}})


EMAIL = [
    tool("list_emails_metadata", ["account_name", "mailbox"], read_only=True, description="List emails.\nMore."),
    tool("send_email", ["account_name", "recipients", "body"], read_only=False, destructive=False),
    tool("delete_emails", ["account_name", "email_ids"], read_only=False, destructive=True),
    tool("list_available_accounts"),                       # no annotations: the verb decides
    tool("purge_cache"),
]


def test_groups_prefer_annotations_then_verbs():
    groups = {t.name: tool_access.group_of(t) for t in EMAIL}
    assert groups == {"list_emails_metadata": "read-only", "send_email": "write", "delete_emails": "destructive",
                      "list_available_accounts": "read-only", "purge_cache": "destructive"}


def test_diff_and_record():
    config, d = tool_access.record({"url": "x"}, EMAIL)
    assert d is None and set(config["tools_seen"]) == {t.name for t in EMAIL} and config["tools_drift"] is None
    later = [t for t in EMAIL if t.name != "purge_cache"] + [tool("archive_emails", ["account_name"])]
    later[1] = tool("send_email", ["account_name", "recipients", "body", "bcc"], read_only=False, destructive=False)
    config2, d = tool_access.record(config, later)
    assert d.added == ["archive_emails"] and d.removed == ["purge_cache"]
    assert d.changed == [{"tool": "send_email", "new_args": ["bcc"], "dropped_args": []}]
    assert config2["tools_seen"] == config["tools_seen"]  # the baseline moves only when the owner accepts
    assert config2["tools_drift"]["added"] == ["archive_emails"]
    assert tool_access.record(config2, EMAIL)[0]["tools_drift"] is None  # back to baseline: drift clears


class P:  # a policy row, enough for the pure functions
    def __init__(self, pattern, effect="allow", agent_id="a1", constraints=None):
        self.pattern, self.effect, self.agent_id, self.constraints = pattern, effect, agent_id, constraints


def test_rows_scope_state_and_plan():
    res = Resource(kind="mcp", name="email", config={"arg_keys": ["account_name", "recipients"]})
    pols = [P("mcp/email/tools/list_emails_metadata/account_name=agents"),
            P("mcp/email/tools/send_email/recipients=me@x.org"),            # another shape: shown, not edited
            P("mcp/email/tools/delete_emails", "deny", None),                # every agent
            P("mcp/email/tools/old_tool/account_name=agents")]               # tool no longer offered
    rows = {r.name: r for r in tool_access.mcp_rows(res, EMAIL, pols, "a1", ("account_name", "agents"))}
    assert rows["list_emails_metadata"].state == "allow"
    assert rows["list_available_accounts"].pattern == "mcp/email/tools/list_available_accounts"  # takes no account
    assert rows["send_email"].state == "ask" and rows["send_email"].other_rules == 1
    assert rows["delete_emails"].everyone == "ask"  # no every-agent rule on the scoped path itself...
    assert rows["delete_emails"].covered_by == ["deny mcp/email/tools/delete_emails (every agent)"]  # ...but this

    assert rows["old_tool/account_name=agents"].group == "gone"

    change = tool_access.plan(list(rows.values()), {"list_emails_metadata": "ask", "send_email": "allow",
                                                    "old_tool/account_name=agents": "ask",
                                                    "delete_emails": "deny"}, pols, "a1")
    assert [p.pattern for p in change.delete] == ["mcp/email/tools/list_emails_metadata/account_name=agents",
                                                  "mcp/email/tools/old_tool/account_name=agents"]
    assert set(change.add) == {("mcp/email/tools/send_email/account_name=agents", "allow"),
                               ("mcp/email/tools/delete_emails/account_name=agents", "deny")}


def test_scope_must_be_an_argument_key():
    assert tool_access.parse_scope("account_name=agents", ["account_name"]) == ("account_name", "agents")
    for bad in ("account_name", "mailbox=INBOX", "account_name=*"):
        try:
            tool_access.parse_scope(bad, ["account_name"])
        except ValueError:
            continue
        raise AssertionError(bad)


async def test_access_page_end_to_end(live_server, db, agent, monkeypatch):
    from keywright_server import mcp_proxy

    res = Resource(kind="mcp", name="email", default_mode="approval",
                   config={"url": "http://email.test/mcp", "arg_keys": ["account_name", "recipients"]})
    db.add(res)
    db.add(Policy(pattern="mcp/email/**", effect="allow", agent_id=None, note="broad"))
    await db.commit()
    await db.refresh(res)
    await db.refresh(agent)
    rid, aid = res.id, agent.id
    offered = list(EMAIL)

    async def list_tools(name, config, *, force=False):
        return offered

    monkeypatch.setattr(mcp_proxy, "list_tools", list_tools)
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as http:
        await http.post("/ui/login", data={"password": "adminpass123"}, follow_redirects=False)
        page = (await http.get(f"/ui/access?resource={rid}&agent={aid}&scope=account_name%3Dagents")).text
        assert "list_emails_metadata" in page and "Also decided by" in page and "mcp/email/**" in page

        r = await http.post("/ui/access", data={
            "resource": rid, "agent": aid, "scope": "account_name=agents",
            "s:list_emails_metadata": "allow", "s:send_email": "ask", "s:delete_emails": "deny"},
            follow_redirects=False)
        assert r.status_code == 303
        db.expire_all()
        mine = {(p.pattern, p.effect) for p in (await db.execute(
            select(Policy).where(Policy.agent_id == aid))).scalars().all()}
        assert mine == {("mcp/email/tools/list_emails_metadata/account_name=agents", "allow"),
                        ("mcp/email/tools/delete_emails/account_name=agents", "deny")}

        # the scope is remembered, and saving the same states again changes nothing
        page = (await http.get(f"/ui/access?resource={rid}&agent={aid}")).text
        assert 'value="account_name=agents"' in page
        r = await http.post("/ui/access", data={"resource": rid, "agent": aid, "scope": "account_name=agents",
                                                "s:list_emails_metadata": "allow"}, follow_redirects=False)
        db.expire_all()
        assert len((await db.execute(select(Policy).where(Policy.agent_id == aid))).scalars().all()) == 2

        # the watch: baseline first, then a new argument on a tool is drift, shown until accepted
        await tool_access.watch_once(db)
        offered[1] = tool("send_email", ["account_name", "recipients", "body", "bcc"], read_only=False,
                          destructive=False)
        fresh = await tool_access.watch_once(db)
        assert [(n, d.changed) for n, d in fresh] == [
            ("email", [{"tool": "send_email", "new_args": ["bcc"], "dropped_args": []}])]
        assert await tool_access.watch_once(db) == []  # same drift again: not news
        assert (await db.execute(select(AuditEvent).where(AuditEvent.tool == "tools.drift"))).scalars().all()
        assert "Tools changed on email" in (await http.get("/ui")).text
        page = (await http.get(f"/ui/access?resource={rid}&agent={aid}")).text
        assert "New arguments: bcc" in page

        await http.post(f"/ui/resources/{rid}/tools/accept", data={"agent": aid}, follow_redirects=False)
        db.expire_all()
        fresh_res = await db.get(Resource, rid)
        assert fresh_res.config["tools_drift"] is None and "bcc" in fresh_res.config["tools_seen"]["send_email"]["args"]


def test_grants_grouped_by_agent_then_host_newest_first():
    from datetime import timedelta

    from keywright_server.access_view import grant_groups
    from keywright_server.models import AccessRequest, Agent, Grant, now

    t = now()
    agents = {"a1": Agent(id="a1", name="mail-router"), "a2": Agent(id="a2", name="claude")}
    reqs = {"r1": AccessRequest(id="r1", agent_id="a1", patterns=[], reason="router access", decision_scope="ttl",
                                decision_options={"ttl_s": 3600}),
            "r2": AccessRequest(id="r2", agent_id="a2", patterns=[], reason="deploy", decision_scope="once")}

    def g(i, agent, pattern, req=None, minutes_ago=0, expires=60, revoked=False, scope="ttl"):
        return Grant(id=f"g{i}", agent_id=agent, pattern=pattern, scope=scope, request_id=req,
                     created_at=t - timedelta(minutes=minutes_ago),
                     expires_at=t + timedelta(minutes=expires) if expires is not None else None,
                     revoked_at=t if revoked else None)

    grants = [
        g(1, "a1", "mcp/email/tools/list_emails_metadata/account_name=agents", "r1", minutes_ago=5),
        g(2, "a1", "mcp/email/tools/get_emails_content/account_name=agents", "r1", minutes_ago=5),
        g(3, "a1", "mcp/ha-mcp/tools/ha_call_service/domain=mqtt", "r1", minutes_ago=5),
        g(4, "a2", "ssh/nvr/exec/docker/ps", "r2", minutes_ago=1, expires=None, scope="once"),
        g(5, "a2", "ssh/pve/exec/qm", None, minutes_ago=30, expires=-5),   # expired
        g(6, "a2", "ssh/pve/exec/ls", None, minutes_ago=20, revoked=True),
    ]
    out = grant_groups(grants, agents, reqs, t)
    assert [a["name"] for a in out] == ["claude", "mail-router"]           # most recent approval first
    assert [h["resource"] for h in out[0]["hosts"]] == ["ssh/nvr"]         # inactive hidden by default
    mail = out[1]
    assert [h["resource"] for h in mail["hosts"]] == ["mcp/email", "mcp/ha-mcp"]
    email = mail["hosts"][0]["approvals"][0]
    assert len(email["grants"]) == 2 and email["label"] == "1 hour" and email["elsewhere"] == 1
    assert email["revoke"] == "/ui/requests/r1/revoke"

    history = grant_groups(grants, agents, reqs, t, include_inactive=True)
    pve = [h for h in history[0]["hosts"] if h["resource"] == "ssh/pve"][0]
    assert [a["state"] for a in pve["approvals"]] == ["revoked", "ended"] and pve["active"] == 0
    assert all(a["revoke"] is None for a in pve["approvals"])
