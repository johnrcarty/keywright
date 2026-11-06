"""Shopping grants never buy; priced approvals survive neither changed quotes nor replay."""
import copy
import json
import shlex
from datetime import timedelta

import pytest
from sqlalchemy import select

from keywright_server import approvals, policy, shopping, shopping_mcp, ssh
from keywright_server import mcp_server as m
from keywright_server.models import AccessRequest, Grant, Policy, Resource, ShoppingCart, now


@pytest.fixture
async def target(db):
    res = Resource(kind="ssh", name="Food", default_mode="approval",
                   config={"integration": "doordash", "host": "fixture.test", "user": "runner"})
    db.add(res)
    await db.commit()
    return res


@pytest.fixture
def quote():
    return {"success": True, "cart_uuid": "fixture-cart", "items": [],
            "payment_method": {"card_id": "fixture-card", "display_name": "Test card ending 1234"},
            "quote": {"total_before_tip": {"unit_amount": 2500, "currency": "USD"},
                      "delivery_address": {"printable_address": "123 Example Lane"},
                      "line_items": [{"label": "Total", "final_money": {"unit_amount": 2500}}],
                      "store_order_cart": {"store": {"id": "fixture-store", "name": "Fixture Cafe"},
                           "orders": [{"order_items": [{"id": "line-1", "item": {"name": "Lunch", "id": "item-1"},
                              "quantity": 1, "special_instructions": "No onions or sour cream"}]}]}}}


@pytest.fixture
def remote(monkeypatch, quote):
    calls = []

    async def run(config, command, **kwargs):
        # Production quotes the approved argv as the last argument to a version-check wrapper.
        argv = shlex.split(shlex.split(command)[-1])
        calls.append(argv)
        if "submit" in argv:
            return ssh.RunResult(0, '{"success":true,"status":"processing"}', "", False, 20)
        return ssh.RunResult(0, json.dumps(quote), "", False, 10)

    monkeypatch.setattr(ssh, "run", run)
    return calls


async def start(db, agent, target):
    result = await shopping_mcp.handle(db, agent, "session-a", {"host": target.name, "action": "start"})
    req = await db.get(AccessRequest, result.structured_content["request_id"])
    assert approvals.offered_scopes(req) == ("shopping20", "deny")
    await approvals.decide(db, req.id, "shopping20", via="ui")
    return req


def checkout_args(target):
    return {"host": target.name, "action": "checkout", "cart_uuid": "fixture-cart", "card_id": "fixture-card",
            "tip_cents": 500, "wait_seconds": 0}


async def approve_checkout(db, agent, target):
    result = await shopping_mcp.handle(db, agent, "session-a", checkout_args(target))
    assert result.structured_content["error"] == "approval_required", result
    req = await db.get(AccessRequest, result.structured_content["request_id"])
    assert req.detail["checkout"]["total_cents"] == 3000
    assert req.detail["checkout"]["items"][0]["special_instructions"] == "No onions or sour cream"
    await approvals.decide(db, req.id, "once", via="ui")
    return req


@pytest.mark.parametrize("command", ["sh -c 'dd-cli order submit'", "env X=1 dd-cli search", "dd-cli order submit --yes",
    "dd-cli search --query hi; echo bad", "dd-cli search --query hi | cat", "dd-cli payment-method set-default --card-id x",
    "dd-cli courier submit", "dd-cli search --unknown x", "dd-cli --json-output order submit", "dd-cli search --query a --query b"])
def test_commands_outside_contract_fail_closed(command):
    with pytest.raises(ValueError):
        shopping.parse(command)


def test_argument_quoting_and_preview_side_effects():
    command = 'dd-cli search --query "$(touch /tmp/not-run); tacos"'
    detail = shopping.parse(command)
    assert shlex.split(detail["command"])[-1] == "$(touch /tmp/not-run); tacos"
    assert "'$(touch /tmp/not-run); tacos'" in detail["command"]
    assert shopping.parse("dd-cli order preview --cart-uuid x")["cli_category"] == "read"
    assert shopping.parse("dd-cli order preview --cart-uuid x --fulfillment pickup")["cli_category"] == "cart"
    assert shopping.parse("dd-cli order preview --cart-uuid x --selected-budget-id b")["cli_category"] == "cart"


async def test_session_scope_identity_expiry_and_deny(db, agent, target, log_notifier):
    req = await start(db, agent, target)
    grant = (await db.scalars(select(Grant).where(Grant.request_id == req.id))).one()
    assert 1190 < (grant.expires_at - now()).total_seconds() <= 1200
    for cmd in ("dd-cli cart list", "dd-cli cart add-items --store-id s --items-json '[]'"):
        required, detail = m._run_operation(target, cmd, "runner")
        assert (await policy.evaluate(db, agent, "session-a", required, operation=detail)).allowed
        assert not (await policy.evaluate(db, agent, "session-b", required, operation=detail)).allowed
        assert not (await policy.evaluate(db, agent, "session-a", required, operation={**detail, "user": "root"})).allowed
    db.add(Policy(agent_id=None, pattern=required[0], effect="deny"))
    await db.commit()
    assert (await policy.evaluate(db, agent, "session-a", required, operation=detail)).status == "deny"


async def test_only_shopping_decision_can_create_session(db, agent, target, log_notifier):
    result = await shopping_mcp.handle(db, agent, "session-a", {"host": target.name, "action": "start"})
    rid = result.structured_content["request_id"]
    for scope in ("once", "ttl", "always", "session"):
        with pytest.raises(ValueError, match="Shopping"):
            await approvals.decide(db, rid, scope, via="ui")
    with pytest.raises(ValueError, match="human"):
        await approvals.decide(db, rid, "shopping20", via="jev")


async def test_checkout_once_then_replay_blocked(db, agent, target, log_notifier, remote):
    await start(db, agent, target)
    req = await approve_checkout(db, agent, target)
    result = await shopping_mcp.handle(db, agent, "session-a", checkout_args(target))
    assert result.structured_content["stage"] == "submitted_check_status", result
    assert sum("submit" in c for c in remote) == 1
    assert all("fixture-card" in c for c in remote)
    result = await shopping_mcp.handle(db, agent, "session-a", checkout_args(target))
    assert result.structured_content["error"] == "checkout_attempted"
    assert sum("submit" in c for c in remote) == 1
    grant = (await db.scalars(select(Grant).where(Grant.request_id == req.id))).one()
    assert grant.uses_remaining == 0


async def test_standing_open_and_wildcard_allow_cannot_purchase(db, agent, target, log_notifier, remote):
    await start(db, agent, target)
    target.default_mode = "open"
    db.add(Policy(agent_id=None, pattern="ssh/Food/**", effect="allow"))
    await db.commit()
    result = await shopping_mcp.handle(db, agent, "session-a", checkout_args(target))
    req = await db.get(AccessRequest, result.structured_content["request_id"])
    assert approvals.offered_scopes(req) == ("once", "deny")
    for scope, extent in (("ttl", None), ("always", None), ("once", "patterns")):
        with pytest.raises(ValueError):
            await approvals.decide(db, req.id, scope, via="ui", extent=extent)
    assert not any("submit" in c for c in remote)


async def test_quote_changed_before_retry_requires_new_approval(db, agent, target, log_notifier, remote, quote):
    await start(db, agent, target)
    old = await approve_checkout(db, agent, target)
    quote["quote"]["total_before_tip"]["unit_amount"] += 1
    result = await shopping_mcp.handle(db, agent, "session-a", checkout_args(target))
    assert result.structured_content["error"] == "approval_required"
    assert result.structured_content["request_id"] != old.id
    assert not any("submit" in c for c in remote)


async def test_change_during_final_recheck_never_submits(db, agent, target, log_notifier, remote, quote, monkeypatch):
    await start(db, agent, target)
    await approve_checkout(db, agent, target)
    original = ssh.run
    count = 0

    async def changed(*args, **kwargs):
        nonlocal count
        count += 1
        if count == 2:
            quote["quote"]["store_order_cart"]["orders"][0]["order_items"][0]["special_instructions"] = "Changed"
        return await original(*args, **kwargs)

    monkeypatch.setattr(ssh, "run", changed)
    result = await shopping_mcp.handle(db, agent, "session-a", checkout_args(target))
    assert result.structured_content["error"] == "quote_changed"
    assert not any("submit" in c for c in remote)


async def test_unknown_submit_stays_reserved(db, agent, target, log_notifier, remote, monkeypatch):
    await start(db, agent, target)
    await approve_checkout(db, agent, target)
    original = ssh.run

    async def timeout(config, command, **kwargs):
        if "submit" in shlex.split(shlex.split(command)[-1]):
            raise TimeoutError("lost after send")
        return await original(config, command, **kwargs)

    monkeypatch.setattr(ssh, "run", timeout)
    result = await shopping_mcp.handle(db, agent, "session-a", checkout_args(target))
    assert result.structured_content["error"] == "ssh_failed"
    row = await db.get(ShoppingCart, (target.id, "fixture-cart"))
    assert row.submit_state == "outcome_unknown"
    result = await shopping_mcp.handle(db, agent, "session-a", checkout_args(target))
    assert result.structured_content["error"] == "checkout_attempted"


@pytest.mark.parametrize("change", ["card", "empty", "partial", "currency"])
def test_bad_quote_refused(quote, change):
    q = copy.deepcopy(quote)
    if change == "card":
        q["payment_method"]["card_id"] = "other"
    elif change == "empty":
        q["quote"]["store_order_cart"]["orders"] = []
    elif change == "partial":
        q["partial_response"] = True
    else:
        q["quote"]["total_before_tip"]["currency"] = "EUR"
    with pytest.raises(ValueError):
        shopping.quote_snapshot(q, cart="fixture-cart", card="fixture-card", tip=500, options={})


async def test_doubledash_requires_observed_unexpired_link(db, agent, target, log_notifier, remote):
    await start(db, agent, target)
    row = ShoppingCart(resource_id=target.id, cart_id="fixture-cart",
                       link={"confirmed": False, "order_uuid": "parent", "expires_at": (now() + timedelta(minutes=5)).isoformat()})
    db.add(row)
    await db.commit()
    result = await shopping_mcp.handle(db, agent, "session-a", checkout_args(target))
    assert result.structured_content["error"] == "invalid_arguments"
    row.link = {**row.link, "confirmed": True, "expires_at": (now() - timedelta(seconds=1)).isoformat()}
    await db.commit()
    result = await shopping_mcp.handle(db, agent, "session-a", checkout_args(target))
    assert result.structured_content["error"] == "invalid_arguments"
    assert remote == []


async def test_checkout_ui_shows_notes_price_card_destination_and_single_approval(db, agent, target, log_notifier, remote):
    from starlette.requests import Request

    from keywright_server.web.admin import request_detail, templates

    await start(db, agent, target)
    result = await shopping_mcp.handle(db, agent, "session-a", checkout_args(target))
    rid = result.structured_content["request_id"]
    request = Request({"type": "http", "method": "GET", "path": "/ui/requests/" + rid,
                       "headers": [], "scheme": "http", "server": ("fixture", 80)})
    response = await request_detail(request, rid)
    html = response.body.decode()
    for expected in ("No onions or sour cream", "$30.00", "$5.00", "Test card ending 1234", "123 Example Lane",
                     "Place this order once", "data-until="):
        assert expected in html
    assert 'value="always"' not in html and 'value="ttl"' not in html
    req = await db.get(AccessRequest, rid)
    tile = templates.get_template("_request_card.html").render(req=req)
    assert "Review priced order" in tile
    assert 'value="ttl"' not in tile


async def test_observed_link_deadline_and_json_enforced(db, target):
    deadline = (now() + timedelta(minutes=10)).isoformat()
    detail = shopping.parse("dd-cli doubledash options --order-uuid parent")
    assert "--json-output" in detail["command"]
    result = ssh.RunResult(0, json.dumps({"expires_at": deadline, "stores": []}), "", False, 1)
    out = await shopping_mcp.observe(db, target, detail, result)
    assert 590 < out["seconds_remaining"] <= 600
    detail = shopping.parse("dd-cli doubledash add --order-uuid parent --store-id s --item-id i")
    result = ssh.RunResult(0, '{"cart_id":"child","link_confirmed":false}', "", False, 1)
    await shopping_mcp.observe(db, target, detail, result)
    row = await db.get(ShoppingCart, (target.id, "child"))
    assert row.link == {"order_uuid": "parent", "parent_cart": None, "confirmed": False,
                        "expires_at": deadline, "bundle_cart_id": None}


async def test_expired_revoked_session_and_purchase_grants(db, agent, target, log_notifier, remote):
    req = await start(db, agent, target)
    checkout = await approve_checkout(db, agent, target)
    purchase = (await db.scalars(select(Grant).where(Grant.request_id == checkout.id))).one()
    purchase.expires_at = now() - timedelta(seconds=1)
    await db.commit()
    result = await shopping_mcp.handle(db, agent, "session-a", checkout_args(target))
    assert result.structured_content["error"] == "approval_required"
    grant = (await db.scalars(select(Grant).where(Grant.request_id == req.id))).one()
    grant.revoked_at = now()
    await db.commit()
    assert await shopping_mcp.session_grant(db, agent, "session-a", target) is None
    assert not any("submit" in c for c in remote)


def test_version_wrapper_rejects_new_binary_before_command(tmp_path):
    import os
    import subprocess

    cli = tmp_path / "dd-cli"
    cli.write_text('#!/bin/sh\necho "dd-cli, version 0.2.7"\n')
    cli.chmod(0o755)
    sentinel = tmp_path / "executed"
    result = subprocess.run(["sh", "-c", shopping.versioned_command(shlex.join(["touch", str(sentinel)]))],
                            env={**os.environ, "PATH": str(tmp_path) + ":" + os.environ["PATH"]}, capture_output=True, check=False)
    assert result.returncode == 2 and not sentinel.exists()


async def test_competing_checkout_calls_submit_at_most_once(db, agent, target, log_notifier, remote):
    import asyncio

    from keywright_server.db import session
    from keywright_server.models import Agent

    await start(db, agent, target)
    await approve_checkout(db, agent, target)
    aid, arguments = agent.id, checkout_args(target)

    async def call():
        async with session() as worker:
            identity = await worker.get(Agent, aid)
            return await shopping_mcp.handle(worker, identity, "session-a", arguments)

    results = await asyncio.gather(call(), call())
    assert sum("submit" in c for c in remote) == 1
    assert sum(r.structured_content.get("stage") == "submitted_check_status" for r in results) == 1
