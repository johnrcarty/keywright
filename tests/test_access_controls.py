from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from keywright_server import access_view, approvals, policy
from keywright_server.db import _upgrade_access_columns
from keywright_server.models import AccessRequest, AuditEvent, Grant, Policy, Resource, now


@pytest.fixture
async def target(db):
    res = Resource(kind="ssh", name="prod", default_mode="approval",
                   config={"host": "prod.internal", "user": "deploy"})
    db.add(res)
    await db.commit()
    return res


def operation(target, command="docker logs api", user="deploy"):
    return {"host": target.name, "resource_id": target.id, "command": command, "user": user}


@pytest.mark.parametrize("scope", ["once", "ttl15", "ttl30", "ttl", "session", "always"])
async def test_exact_operation_is_independent_of_duration(db, agent, target, scope):
    detail = operation(target)
    req = await approvals.create(db, agent, "run-1", ["ssh/prod/exec/docker/logs"], "debug", detail)
    await approvals.decide(db, req.id, scope, via="ui")
    for changed in (operation(target, "docker logs database"), operation(target, user="root")):
        assert not (await policy.evaluate(db, agent, "run-1", req.patterns, operation=changed)).allowed
    # Discovery sees that this tool can be used; preapproval cannot mistake an exact grant for a broad one.
    assert not (await policy.evaluate(db, agent, "run-1", req.patterns, consume=False)).allowed
    assert (await policy.evaluate(db, agent, "run-1", req.patterns, consume=False, discovery=True)).allowed
    assert (await policy.evaluate(db, agent, "run-1", req.patterns, operation=detail)).allowed
    assert req.decision_options["extent"] == "exact"
    if scope in approvals.TTL_PRESETS:
        grant = (await db.execute(select(Grant).where(Grant.request_id == req.id))).scalar_one()
        assert (grant.expires_at - req.decided_at).total_seconds() == approvals.TTL_PRESETS[scope]


@pytest.mark.parametrize("scope", ["ttl30", "session", "always"])
async def test_pattern_choice_still_binds_remote_account_and_target(db, agent, target, scope):
    req = await approvals.create(db, agent, "run-1", ["ssh/prod/exec/docker/logs"], "debug", operation(target))
    await approvals.decide(db, req.id, scope, via="ui", extent="patterns")
    assert (await policy.evaluate(db, agent, "run-1", req.patterns,
                                  operation=operation(target, "docker logs database"))).allowed
    assert not (await policy.evaluate(db, agent, "run-1", req.patterns,
                                      operation=operation(target, user="root"))).allowed
    replacement = {**operation(target), "resource_id": "replacement"}
    assert not (await policy.evaluate(db, agent, "run-1", req.patterns, operation=replacement)).allowed


async def test_exact_mcp_arguments_preserve_json_types_and_all_arguments(db, agent):
    db.add(Resource(kind="mcp", name="ha", config={}, default_mode="approval"))
    await db.commit()
    detail = {"server": "ha", "tool": "set", "arguments": {"enabled": True, "entity": "light.a"}}
    req = await approvals.create(db, agent, None, ["mcp/ha/tools/set"], "lamp", detail)
    await approvals.decide(db, req.id, "ttl30", via="ui")
    for args in ({"enabled": 1, "entity": "light.a"}, {"enabled": True, "entity": "light.b"},
                 {"enabled": True, "entity": "light.a", "force": True}):
        assert not (await policy.evaluate(db, agent, None, req.patterns,
                                          operation={**detail, "arguments": args})).allowed
    assert (await policy.evaluate(db, agent, None, req.patterns, operation=detail)).allowed


async def test_exact_permanent_deny_and_temporary_denial(db, agent, target):
    target.default_mode = "open"
    await db.commit()
    detail = operation(target)
    req = await approvals.create(db, agent, None, ["ssh/prod/exec/docker/logs"], "debug", detail)
    await approvals.decide(db, req.id, "deny_always", via="ui")
    assert (await policy.evaluate(db, agent, None, req.patterns, operation=detail)).status == "deny"
    changed = operation(target, "docker logs other")
    assert (await policy.evaluate(db, agent, None, req.patterns, operation=changed)).allowed
    # The cooldown is per pattern: a reworded command does not re-prompt the human.
    assert await approvals.recently_denied(db, agent, req.patterns)
    listing = (await policy.effective_access(db, agent, None))[0]
    assert listing["deny_rules"] == []
    assert listing["constrained_rules"][0]["effect"] == "deny"


@pytest.mark.parametrize("ttl_s", [0, -60, 59, 3601, 86400, True])
async def test_duration_validation_leaves_request_pending(db, agent, target, ttl_s):
    req = await approvals.create(db, agent, None, ["ssh/prod/exec/ls"], "debug")
    with pytest.raises(ValueError, match="between 1 minute and 1 hour"):
        await approvals.decide(db, req.id, "ttl", via="ui", ttl_s=ttl_s)
    await db.refresh(req)
    assert req.status == "pending"


async def test_phone_durations_are_signed_and_cannot_broaden(db, agent, target, log_notifier):
    req = await approvals.create(db, agent, None, ["ssh/prod/exec/docker/logs"], "debug", operation(target))
    action = approvals.notification_action(req.id, "ttl15")
    assert approvals.parse_notification_action(action.replace("TTL15", "TTL30")) is None
    with pytest.raises(ValueError):
        approvals.decision_token(req.id, "deny_always")
    with pytest.raises(ValueError):
        await approvals.decide(db, req.id, "ttl15", via="link", extent="patterns")
    await log_notifier.on_decision_token(action)
    await db.refresh(req)
    assert req.decision_options == {"extent": "exact", "ttl_s": 900}
    changed = operation(target, "docker logs database")
    assert not (await policy.evaluate(db, agent, None, req.patterns, operation=changed)).allowed


async def test_phone_hour_on_an_unparseable_command_is_not_a_host_wide_grant(db, agent, target, log_notifier):
    # 2026-09-17 stress test: a ping `for` loop classified as `**`; "1 hour" on the phone must mean that loop.
    loop = operation(target, "for i in 1 2 3; do ping -c1 10.0.0.$i; done")
    req = await approvals.create(db, agent, None, ["ssh/prod/exec/**"], "sweep", loop)
    await log_notifier.on_decision_token(approvals.notification_action(req.id, "ttl"))
    assert (await policy.evaluate(db, agent, None, req.patterns, operation=loop)).allowed
    for path, command in (("ssh/prod/exec/ssh", "ssh root@10.0.0.2 id"), ("ssh/prod/exec/qm/destroy", "qm destroy 100")):
        assert not (await policy.evaluate(db, agent, None, [path], operation=operation(target, command))).allowed
        # A later access_request must reach the human rather than come back "already allowed".
        assert (await policy.evaluate(db, agent, None, [path], consume=False)).missing == [path]


async def test_revoke_group_does_not_claim_to_remove_permanent_access(db, agent, target):
    req = await approvals.create(db, agent, None, ["ssh/prod/exec/ls", "ssh/prod/exec/df"], "inspect")
    await approvals.decide(db, req.id, "ttl30", via="ui")
    db.add(Policy(agent_id=agent.id, pattern="ssh/prod/exec/ls", effect="allow"))
    await db.commit()
    view = await access_view.overview(db)
    assert view["lease_count"] == 1
    assert len(view["access_agents"][0]["leases"][0]["grants"]) == 2
    assert await approvals.revoke_request_grants(db, req.id) == 2
    assert await approvals.revoke_request_grants(db, req.id) == 0
    assert (await policy.evaluate(db, agent, None, ["ssh/prod/exec/ls"])).allowed
    assert not (await policy.evaluate(db, agent, None, ["ssh/prod/exec/df"])).allowed
    view = await access_view.overview(db)
    assert view["lease_count"] == 0
    assert view["access_agents"][0]["targets"][0]["state"] == "Scoped access"


async def test_overview_includes_old_active_grants_defaults_denies_and_suspension(db, agent, target):
    active = Grant(agent_id=agent.id, pattern="ssh/prod/exec/ls", scope="ttl",
                   created_at=now() - timedelta(hours=2), expires_at=now() + timedelta(minutes=30))
    db.add(active)
    for _ in range(25):
        db.add(Grant(agent_id=agent.id, pattern="ssh/prod/exec/df", scope="ttl",
                     expires_at=now() - timedelta(minutes=1)))
    db.add(Resource(kind="ssh", name="dev", default_mode="open", config={}))
    db.add(Policy(pattern="ssh/prod/**", effect="deny"))
    await db.commit()
    view = await access_view.overview(db)
    assert view["lease_count"] == 1
    targets = {t["resource"].name: t for t in view["access_agents"][0]["targets"]}
    assert targets["prod"]["state"] == "Denied for this target"
    assert targets["dev"]["state"] == "Allowed by default"
    agent.disabled_at = now()
    await db.commit()
    assert not (await policy.evaluate(db, agent, None, ["ssh/dev/exec/ls"])).allowed
    view = await access_view.overview(db)
    assert all(t["state"].startswith("Suspended") for t in view["access_agents"][0]["targets"])


async def test_upgrade_preserves_existing_rows_and_is_idempotent(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'legacy.db'}")
    async with engine.begin() as conn:
        for table in ("grants", "policies", "requests"):
            await conn.execute(text(f'CREATE TABLE "{table}" (id TEXT PRIMARY KEY, pattern TEXT)'))
            await conn.execute(text(f'INSERT INTO "{table}" VALUES (\'legacy\', \'ssh/prod/**\')'))
        await conn.run_sync(_upgrade_access_columns)
        await conn.run_sync(_upgrade_access_columns)
        for table, column in (("grants", "constraints"), ("policies", "constraints"),
                              ("requests", "decision_options"), ("policies", "request_id")):
            row = (await conn.execute(text(f'SELECT pattern, "{column}" FROM "{table}"'))).one()
            assert row == ("ssh/prod/**", None)
    await engine.dispose()


async def test_ui_scope_duration_revoke_and_suspend(live_server, db, agent, target):
    req = await approvals.create(db, agent, "run-1", ["ssh/prod/exec/docker/logs"], "inspect", operation(target))
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server},
                                 follow_redirects=True) as http:
        await http.post("/ui/login", data={"password": "adminpass123"})
        page = await http.get(f"/ui/requests/{req.id}")
        assert 'value="exact"' in page.text and "30 minutes" in page.text
        await http.post(f"/ui/requests/{req.id}/decide", data={"scope": "ttl30", "extent": "exact"})
        await db.refresh(req)
        assert req.decision_options == {"extent": "exact", "ttl_s": 1800}
        page = await http.get("/ui")
        assert "Exact command" in page.text and "30m remaining" in page.text
        assert "Permission patterns · any matching arguments" not in page.text
        await http.post(f"/ui/requests/{req.id}/revoke")
        assert not (await policy.evaluate(db, agent, "run-1", req.patterns, operation=operation(target))).allowed
        target.default_mode = "open"
        await db.commit()
        page = await http.post(f"/ui/agents/{agent.id}/disable", data={"next": "/ui"})
        assert "No active approvals." in page.text
        assert f'aria-label="Access for {agent.name}"' not in page.text
        assert "Running operations are not stopped" in page.text
        assert not (await policy.evaluate(db, agent, "run-1", req.patterns, operation=operation(target))).allowed
        events = (await db.execute(select(AuditEvent).where(AuditEvent.tool == "agent.disable"))).scalars().all()
        assert len(events) == 1


async def test_ssh_execution_uses_approved_account_if_default_changes(db, agent, target, monkeypatch):
    from keywright_server import mcp_server, ssh
    from keywright_server.db import session

    calls = []

    async def wait_and_change(request_id, timeout):
        async with session() as other:
            await approvals.decide(other, request_id, "ttl30", via="ui")
            resource = await other.get(Resource, target.id)
            resource.config = {**resource.config, "user": "root"}
            await other.commit()

    async def run(config, command, **kwargs):
        calls.append(kwargs["user"])
        return ssh.RunResult(0, "ok", "", False, 1)

    monkeypatch.setattr(approvals, "wait", wait_and_change)
    monkeypatch.setattr(ssh, "run", run)
    result = await mcp_server._ssh_run(db, agent, None, {"host": "prod", "command": "docker logs api"})
    assert not result.is_error and calls == ["deploy"]


async def test_legacy_once_scope_is_described_without_broadening(db, agent, target):
    req = AccessRequest(agent_id=agent.id, patterns=["ssh/prod/exec/docker/logs"],
                        detail=operation(target), status="approved", decision_scope="once")
    db.add(req)
    await db.flush()
    db.add(Grant(agent_id=agent.id, request_id=req.id, pattern=req.patterns[0], scope="once", uses_remaining=1))
    await db.commit()
    view = await access_view.overview(db)
    assert view["access_agents"][0]["leases"][0]["label"] == "Exact command"
    effective = await policy.effective_access(db, agent, None)
    assert effective[0]["grants"][0]["constraints"]["command"] == "docker logs api"
    assert not (await policy.evaluate(db, agent, None, req.patterns,
                                      operation=operation(target, "docker logs database"))).allowed
    assert (await policy.evaluate(db, agent, None, req.patterns, operation=operation(target))).allowed


@pytest.mark.parametrize("audit_handle", [True, False])
async def test_permanent_approval_provenance_survives_rule_deletion(
    live_server, db, agent, monkeypatch, audit_handle,
):
    import mcp_types as types

    from keywright_server import mcp_proxy, mcp_server
    db.add(Resource(kind="mcp", name="ha", default_mode="approval", config={"audit_handle": audit_handle}))
    await db.commit()
    detail = {"server": "ha", "tool": "set", "arguments": {"entity": "light.a"}}
    req = await approvals.create(db, agent, None, ["mcp/ha/tools/set"], "lamp", detail)
    await approvals.decide(db, req.id, "always", via="ui")
    rule = (await db.execute(select(Policy).where(Policy.request_id == req.id))).scalar_one()

    async def call(*args):
        # Authorization was decided already; deleting the source must not erase its audit provenance.
        await db.delete(rule)
        await db.commit()
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])

    monkeypatch.setattr(mcp_proxy, "call_tool", call)
    result = await mcp_server._proxy_call(db, agent, None, "ha", "set", detail["arguments"])
    if audit_handle:
        assert result.meta["keywright"]["request_ids"] == [req.id]
    event = (await db.execute(select(AuditEvent).where(AuditEvent.tool == "mcp_call"))).scalar_one()
    assert event.detail["request_ids"] == [req.id]
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as http:
        await http.post("/ui/login", data={"password": "adminpass123"})
        page = await http.get(f"/ui/requests/{req.id}")
        assert page.status_code == 200
        assert f"audit #{event.id}" in page.text and "mcp_call" in page.text


@pytest.mark.parametrize("scope", ["ttl30", "always"])
async def test_access_request_precheck_sees_target_bound_access(db, agent, target, scope):
    req = await approvals.create(db, agent, None, ["ssh/prod/exec/docker/logs"], "debug", operation(target))
    await approvals.decide(db, req.id, scope, via="ui", extent="patterns")
    assert (await policy.evaluate(db, agent, None, req.patterns, consume=False)).allowed
    target.config = {**target.config, "user": "root"}
    await db.commit()
    assert not (await policy.evaluate(db, agent, None, req.patterns, consume=False)).allowed


async def test_target_bound_deny_applies_without_an_operation(db, agent, target):
    req = await approvals.create(db, agent, None, ["ssh/prod/exec/docker/logs"], "debug", operation(target))
    await approvals.decide(db, req.id, "deny_always", via="ui", extent="patterns")
    for discovery in (False, True):
        v = await policy.evaluate(db, agent, None, req.patterns, consume=False, discovery=discovery)
        assert v.status == "deny"
    explicit = await approvals.create(db, agent, None, req.patterns, "again")
    with pytest.raises(ValueError, match="standing deny"):
        await approvals.decide(db, explicit.id, "once", via="ui")


async def test_exact_deny_does_not_block_pattern_requests(db, agent, target):
    req = await approvals.create(db, agent, None, ["ssh/prod/exec/docker/logs"], "debug", operation(target))
    await approvals.decide(db, req.id, "deny_always", via="ui")
    assert (await policy.evaluate(db, agent, None, req.patterns, consume=False)).status == "pending"


async def test_requests_from_before_the_upgrade_still_match(db, agent, target):
    legacy = {"host": "prod", "command": "docker logs api", "user": None}
    req = await approvals.create(db, agent, None, ["ssh/prod/exec/docker/logs"], "debug", legacy)
    await approvals.decide(db, req.id, "ttl30", via="ui")
    assert (await policy.evaluate(db, agent, None, req.patterns, operation=operation(target))).allowed
    assert not (await policy.evaluate(db, agent, None, req.patterns,
                                      operation=operation(target, "docker logs database"))).allowed
    # A once-grant decided before the upgrade has no decision_options and binds through its request.
    old = await approvals.create(db, agent, None, ["ssh/prod/exec/df"], "disk", {**legacy, "command": "df -h"})
    await approvals.decide(db, old.id, "once", via="ui")
    old.decision_options = None
    grant = (await db.execute(select(Grant).where(Grant.request_id == old.id))).scalar_one()
    grant.constraints = None
    await db.commit()
    assert (await policy.evaluate(db, agent, None, old.patterns, operation=operation(target, "df -h"))).allowed


async def test_non_json_numbers_match_nothing_instead_of_raising(db, agent):
    db.add(Resource(kind="mcp", name="ha", config={}, default_mode="approval"))
    await db.commit()
    detail = {"server": "ha", "tool": "set", "arguments": {"level": 1}}
    req = await approvals.create(db, agent, None, ["mcp/ha/tools/set"], "lamp", detail)
    await approvals.decide(db, req.id, "ttl30", via="ui")
    for level in (float("nan"), float("inf")):
        v = await policy.evaluate(db, agent, None, req.patterns, operation={**detail, "arguments": {"level": level}})
        assert v.status == "pending"


async def test_ui_says_when_a_choice_was_not_applied_and_resolves_old_audit_links(live_server, db, agent, target):
    decided = await approvals.create(db, agent, None, ["ssh/prod/exec/ls"], "inspect")
    await approvals.decide(db, decided.id, "deny", via="homeassistant")
    hour = await approvals.create(db, agent, None, ["ssh/prod/exec/df"], "inspect")
    stale = await approvals.create(db, agent, None, ["ssh/prod/exec/du"], "inspect")
    stale.expires_at = now() - timedelta(seconds=1)
    await db.commit()
    first = (await db.execute(select(AuditEvent).order_by(AuditEvent.id))).scalars().first()
    for _ in range(205):
        db.add(AuditEvent(tool="filler", decision="allow"))
    await db.commit()
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server},
                                 follow_redirects=True) as http:
        await http.post("/ui/login", data={"password": "adminpass123"})
        page = await http.post(f"/ui/requests/{decided.id}/decide", data={"scope": "once"})
        assert "was already denied (Deny) via homeassistant; this choice was not applied" in page.text
        page = await http.post(f"/ui/requests/{hour.id}/decide", data={"scope": "ttl"})
        assert "approved (1 hour)" in page.text
        page = await http.post(f"/ui/requests/{stale.id}/decide", data={"scope": "once"})
        assert "expired before it was decided" in page.text
        page = await http.get(f"/ui/audit?q=%23{first.id}")
        assert first.tool in page.text and "filler" not in page.text


async def test_batched_operations_bind_each_exactly(db, agent, target, log_notifier):
    """access_request(operations=[...]): one prompt, one exact grant per operation, and a `**` from a loop
    in the batch still covers only that loop."""
    from keywright_server.notify.base import request_summary

    logs = operation(target, "docker logs api")
    loop = operation(target, "for c in api db; do docker restart $c; done")
    put = {"host": target.name, "resource_id": target.id, "user": "deploy", "path": "/etc/app/app.env",
           "sha256": "ab" * 32, "bytes": 42}
    detail = {"operations": [{"patterns": ["ssh/prod/exec/docker/logs"], "operation": logs},
                             {"patterns": ["ssh/prod/exec/**"], "operation": loop},
                             {"patterns": ["ssh/prod/put/etc/app/app.env"], "operation": put}]}
    req = await approvals.create(db, agent, None, ["ssh/prod/exec/docker/logs", "ssh/prod/exec/**",
                                                   "ssh/prod/put/etc/app/app.env"], "release", detail)
    _, body = request_summary(req, agent)
    assert "$ docker logs api" in body and "$ for c in" in body and "put /etc/app/app.env (42 bytes, sha256 abababababab" in body
    assert "these 3 operations exactly" in body
    await log_notifier.on_decision_token(approvals.notification_action(req.id, "ttl"))
    await db.refresh(req)
    assert req.decision_options["extent"] == "exact"
    grants = (await db.execute(select(Grant).where(Grant.request_id == req.id))).scalars().all()
    assert {g.pattern: g.constraints for g in grants} == {
        "ssh/prod/exec/docker/logs": logs, "ssh/prod/exec/**": loop, "ssh/prod/put/etc/app/app.env": put}
    for pats, op in ((["ssh/prod/exec/docker/logs"], logs), (["ssh/prod/exec/**"], loop),
                     (["ssh/prod/put/etc/app/app.env"], put)):
        assert (await policy.evaluate(db, agent, None, pats, operation=op)).allowed
    assert not (await policy.evaluate(db, agent, None, ["ssh/prod/exec/**"], operation=operation(target, "rm -rf /"))).allowed
    assert not (await policy.evaluate(db, agent, None, ["ssh/prod/exec/docker/logs"],
                                      operation=operation(target, "docker logs db"))).allowed
    assert not (await policy.evaluate(db, agent, None, ["ssh/prod/put/etc/app/app.env"],
                                      operation={**put, "sha256": "cd" * 32})).allowed
    # the admin can still widen a batch to patterns; every pattern stays bound to the account and target
    again = await approvals.create(db, agent, None, req.patterns, "release", detail)
    await approvals.decide(db, again.id, "ttl30", via="ui", extent="patterns")
    assert (await policy.evaluate(db, agent, None, ["ssh/prod/put/etc/app/app.env"],
                                  operation={**put, "sha256": "cd" * 32})).allowed
    assert not (await policy.evaluate(db, agent, None, ["ssh/prod/put/etc/app/app.env"],
                                      operation={**put, "sha256": "cd" * 32, "user": "root"})).allowed


async def test_file_rules_cover_directories(db, agent, target):
    db.add(Policy(agent_id=None, pattern="ssh/prod/put/etc/komodo/stacks/**", effect="allow", constraints=None))
    db.add(Policy(agent_id=None, pattern="ssh/prod/get/etc/shadow", effect="deny", constraints=None))
    await db.commit()
    op = {"host": "prod", "resource_id": target.id, "user": "deploy", "path": "/etc/komodo/stacks/x/compose.yaml",
          "sha256": "00" * 32, "bytes": 1}
    v = await policy.evaluate(db, agent, None, ["ssh/prod/put/etc/komodo/stacks/x/compose.yaml"], operation=op)
    assert v.allowed and v.bound == {"ssh/prod/put/etc/komodo/stacks/x/compose.yaml": "Permission patterns · any matching arguments"}
    assert (await policy.evaluate(db, agent, None, ["ssh/prod/put/etc/ssh/sshd_config"], operation=op)).status == "pending"
    assert (await policy.evaluate(db, agent, None, ["ssh/prod/get/etc/shadow"])).status == "deny"


# ---- "This path, 15 min": a file write approved for its path, not its hash ----------------------
def put_operation(res, path="/tmp/probe.sh", content="echo v1"):
    from keywright_server import mcp_server

    return mcp_server._put_operation(res, path, content, "root")


async def test_path_grant_is_offered_only_for_a_single_file_write(db, agent, target):
    required, detail, _ = put_operation(target)
    put_req = await approvals.create(db, agent, None, required, "probe", detail)
    assert "path15" in approvals.offered_scopes(put_req)
    run_req = await approvals.create(db, agent, None, ["ssh/prod/exec/ls"], "look", operation(target, "ls"))
    assert "path15" not in approvals.offered_scopes(run_req)
    with pytest.raises(ValueError, match="single file write"):
        await approvals.decide(db, run_req.id, "path15", via="link")
    await db.refresh(run_req)
    assert run_req.status == "pending"


async def test_path_grant_from_the_phone_covers_new_contents_at_that_path_for_15_minutes(
        db, agent, target, log_notifier):
    required, detail, _ = put_operation(target, content="echo v1")
    req = await approvals.create(db, agent, None, required, "iterating on a probe", detail)
    await log_notifier.on_decision_token(approvals.notification_action(req.id, "path15"))
    await db.refresh(req)
    assert req.status == "approved" and req.decision_scope == "ttl"
    assert req.decision_options == {"extent": "patterns", "ttl_s": 900}
    grants = (await db.execute(select(Grant).where(Grant.request_id == req.id))).scalars().all()
    assert sorted(g.pattern for g in grants) == sorted(required)
    assert all("sha256" not in (g.constraints or {}) for g in grants)
    # a revised script at the same path passes; the same contents elsewhere do not
    _, revised, _ = put_operation(target, content="echo v2")
    assert (await policy.evaluate(db, agent, None, required, operation=revised)).allowed
    other_required, other, _ = put_operation(target, path="/tmp/other.sh", content="echo v1")
    assert not (await policy.evaluate(db, agent, None, other_required, operation=other)).allowed
