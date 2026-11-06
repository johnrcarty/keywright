"""Shopping sessions and a human checkout gate built on existing policy and audit primitives."""
from __future__ import annotations

import json
import shlex
import time
from datetime import datetime

import mcp_types as types
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from . import approvals, audit, policy, shopping
from .access import operation_matches, target_of
from .models import Grant, ShoppingCart, now

TOOL = types.Tool(
    name="doordash_shop",
    description="DoorDash shopping: cached v0.2.6 guide, 20-minute preparation session, session status, or "
                "checkout with a live quote and one exact human approval. Checkout rechecks the quote and "
                "never retries a submitted cart. Use ssh_run for supported dd-cli browsing/cart commands.",
    input_schema={"type": "object", "properties": {
        "host": {"type": "string"}, "action": {"enum": ["guide", "start", "status", "checkout"]},
        "cart_uuid": {"type": "string"}, "card_id": {"type": "string"}, "tip_cents": {"type": "integer", "minimum": 0},
        "scheduled_time": {"type": "string"}, "priority": {"type": "boolean"},
        "no_apply_credits": {"type": "boolean"}, "reason": {"type": "string"},
        "intent": {"type": "string"}, "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 600}},
        "required": ["host", "action"]})


async def session_grant(db, agent, sid, res):
    if not sid:
        return None
    for grant in (await db.scalars(select(Grant).where(Grant.agent_id == agent.id,
                                 Grant.scope == "session", Grant.session_id == sid))).all():
        if (grant.pattern == f"ssh/{res.name}/exec/dd-cli" and grant.is_active(now(), sid)
                and grant.constraints and grant.constraints.get("shopping") is True
                and operation_matches(grant.constraints, {**target_of(res), "shopping": True})):
            return grant
    return None


def remaining(deadline):
    try:
        return max(0, int((datetime.fromisoformat(deadline) - now()).total_seconds()))
    except (ValueError, TypeError, AttributeError):
        return None


async def observe(db, res, detail, result):
    """Record only provider-observed linkage/deadlines. Never turn agent assertions into evidence."""
    if result.exit_code != 0 or result.truncated:
        return {}
    try:
        data = json.loads(result.stdout)
        body = data.get("result") or data
        if not isinstance(body, dict):
            return {}
    except (ValueError, AttributeError):
        return {}
    flags = detail.get("cli_flags", {})
    offer = body.get("doubledash") or body
    deadline = offer.get("expires_at") if isinstance(offer, dict) else None
    parent = flags.get("--order-uuid")
    if parent and deadline and remaining(deadline) is not None:
        key = (res.id, "offer:" + parent)
        row = await db.get(ShoppingCart, key)
        if row is None:
            row = ShoppingCart(resource_id=res.id, cart_id=key[1])
            db.add(row)
        row.link = {"order_uuid": parent, "expires_at": deadline}
        await db.commit()
    if detail.get("cli_command") == "doubledash add":
        cart = body.get("cart_id") or body.get("cart_uuid")
        if cart:
            row = await db.get(ShoppingCart, (res.id, str(cart)))
            if row is None:
                row = ShoppingCart(resource_id=res.id, cart_id=str(cart))
                db.add(row)
            offer_row = await db.get(ShoppingCart, (res.id, "offer:" + parent)) if parent else None
            row.link = {"order_uuid": parent, "parent_cart": flags.get("--cart-uuid"),
                        "confirmed": body.get("link_confirmed") is True,
                        "expires_at": (offer_row.link or {}).get("expires_at") if offer_row else None,
                        "bundle_cart_id": body.get("bundle_cart_id")}
            await db.commit()
    return {"doubledash_expires_at": deadline, "seconds_remaining": remaining(deadline)} if deadline else {}


async def handle(db, agent, sid, args):
    from . import mcp_server as m

    action = args.get("action")
    res, user = await m._ssh_target(db, args.get("host", ""), None)
    if not res or not shopping.enabled(res):
        return m._error("unknown_resource", hint="Choose an enrolled DoorDash resource")
    if action == "guide":
        return m._result(shopping.guide())
    if action not in {"start", "status", "checkout"}:
        return m._error("invalid_arguments", hint="action must be guide, start, status or checkout")
    grant = await session_grant(db, agent, sid, res)
    status = {"stage": "shopping" if grant else "session_required", "resource": res.name,
              "expires_at": grant.expires_at.isoformat() if grant and grant.expires_at else None,
              "seconds_remaining": remaining(grant.expires_at.isoformat()) if grant and grant.expires_at else 0}
    if action == "status":
        return m._result(status)
    if not sid:
        return m._error("invalid_arguments", hint="Shopping needs a client session ID; use kw or X-Keywright-Session")
    wait_s = min(max(int(args.get("wait_seconds") or 0), 0), m.MAX_WAIT)
    required = [f"ssh/{res.name}/exec/dd-cli"]
    detail = {**target_of(res), "shopping": True, "shopping_session": True}
    verdict = await policy.evaluate(db, agent, sid, required, consume=False, operation=detail)
    if verdict.status in {"deny", "locked"}:
        return m._error(verdict.status, hint="The DoorDash resource's access rules prevent this session")
    if not grant:
        req, _ = await m._request_or_reuse(db, agent, sid, required, args.get("reason") or "Prepare a DoorDash order", detail)
        if req is None:
            return m._error("denied", hint="Shopping access was recently denied")
        if wait_s:
            await approvals.wait(req.id, wait_s)
        grant = await session_grant(db, agent, sid, res)
        if not grant:
            await db.refresh(req)
            return m._error("approval_required" if req.status == "pending" else req.status, request_id=req.id,
                            stage="awaiting_shopping_approval", notified=await m._notified(db, req.id))
    if action == "start":
        return m._result({"stage": "shopping", "resource": res.name, "expires_at": grant.expires_at.isoformat(),
                          "seconds_remaining": remaining(grant.expires_at.isoformat()),
                          "guide": shopping.guide()})
    return await checkout(db, agent, sid, res, user, args, wait_s)


async def checkout(db, agent, sid, res, user, args, wait_s):
    from . import mcp_server as m

    started = time.monotonic()
    cart, card, tip = args.get("cart_uuid"), args.get("card_id"), args.get("tip_cents")
    if (not isinstance(cart, str) or not cart or len(cart) > 200 or cart.startswith("offer:")
            or not isinstance(card, str) or not card or len(card) > 300 or type(tip) is not int or not 0 <= tip <= 100000):
        return m._error("invalid_arguments", hint="Checkout needs cart_uuid, card_id and explicit tip_cents (0–100000)")
    row = await db.get(ShoppingCart, (res.id, cart), populate_existing=True)
    if row and row.submit_state:
        return m._error("checkout_attempted", stage=row.submit_state,
                        hint="This cart already had a submit attempt. Check order status; do not submit it again.")
    link = row.link if row else None
    if link and (not link.get("confirmed") or not link.get("order_uuid") or not link.get("expires_at")
                 or not remaining(link["expires_at"])):
        return m._error("invalid_arguments", hint="DoubleDash needs confirmed linkage to a placed order and an unexpired offer")
    intent = args.get("intent") or "Summary: Help the user complete their food order\nuser prompt/purpose: Place the reviewed order"
    if not isinstance(intent, str) or len(intent) > 2000:
        return m._error("invalid_arguments", hint="intent must be text under 2000 characters")
    options = {}
    for key in ("priority", "no_apply_credits"):
        if key in args and type(args[key]) is not bool:
            return m._error("invalid_arguments", hint=f"{key} must be a boolean")
        if args.get(key):
            options[key] = True
    if args.get("scheduled_time"):
        if not isinstance(args["scheduled_time"], str) or len(args["scheduled_time"]) > 80:
            return m._error("invalid_arguments", hint="scheduled_time must be an ISO timestamp")
        options["scheduled_time"] = args["scheduled_time"]
    common = ["--cart-uuid", cart, "--card-id", card, "--intent", intent]
    for key, value in options.items():
        common.append("--" + key.replace("_", "-"))
        if isinstance(value, str):
            common.append(value)
    preview_command = shlex.join(["dd-cli", "--json-output", "order", "preview", *common])
    preview_required, preview_detail = m._run_operation(res, preview_command, user)

    async def preview():
        v = await policy.evaluate(db, agent, sid, preview_required, operation=preview_detail)
        if not v.allowed:
            return None, m._error(v.status, hint="Shopping access expired or changed; restart the session")
        r, out = await m._ssh_execute(db, agent, sid, "doordash.preview", res, preview_required,
                                    preview_detail, v, preview_command, user, timeout=45)
        if r is None:
            return None, out
        try:
            if r.exit_code != 0 or r.truncated:
                raise ValueError("DoorDash preview failed or was truncated; inspect the cart before checkout")
            return shopping.quote_snapshot(json.loads(r.stdout), cart=cart, card=card, tip=tip, options=options, link=link), None
        except (ValueError, TypeError, KeyError, AttributeError) as e:
            return None, m._error("quote_unavailable", hint=str(e))

    snapshot, error = await preview()
    if error:
        return error
    command = shlex.join(["dd-cli", "--json-output", "order", "submit", *common, "--tip-cents", str(tip), "--yes"])
    required = [f"ssh/{res.name}/exec/dd-cli"]
    connection = shopping.fingerprint({key: res.config.get(key) for key in
                                      ("host", "port", "user", "key_path", "cli_runtime")})
    detail = {**target_of(res), "command": command, "cli_category": "purchase", "checkout": snapshot,
              "connection_sha256": connection,
              "quote_sha256": shopping.fingerprint(snapshot)}
    gate_started = time.monotonic()
    verdict, error = await m._gate(db, agent, sid, required, args.get("reason") or "Place this DoorDash order",
                                   detail, wait_s, "doordash.checkout")
    gate_ms = int((time.monotonic() - gate_started) * 1000)
    if error:
        if error.structured_content.get("error") == "approval_required":
            error.structured_content.update(stage="awaiting_checkout_approval", checkout=snapshot,
                                            hint="Review the priced order in Keywright. Approval expires within five minutes.")
            error.content = [types.TextContent(type="text", text=json.dumps(error.structured_content))]
        return error
    current, error = await preview()
    if error:
        return error
    await db.refresh(res)
    current_connection = shopping.fingerprint({key: res.config.get(key) for key in
                                              ("host", "port", "user", "key_path", "cli_runtime")})
    if current != snapshot or current_connection != connection or (link and not remaining(link["expires_at"])):
        return m._error("quote_changed", stage="needs_new_checkout_approval",
                        hint="The order or price changed after approval. Nothing was submitted; review a fresh quote.")
    # One durable reservation per resource/cart, across agents, workers and restarts.
    if row is None:
        try:
            async with db.begin_nested():
                db.add(ShoppingCart(resource_id=res.id, cart_id=cart))
                await db.flush()
        except IntegrityError:
            pass  # Another worker created the row; only one can reserve it below.
    reserved = await db.execute(update(ShoppingCart).where(ShoppingCart.resource_id == res.id,
        ShoppingCart.cart_id == cart, ShoppingCart.submit_state.is_(None)).values(
            submit_state="outcome_unknown", submitted_at=now(), request_ids=verdict.request_ids))
    await db.commit()
    if reserved.rowcount != 1:
        return m._error("checkout_attempted", hint="Another call already attempted this cart; check order status")
    r, out = await m._ssh_execute(db, agent, sid, "doordash.checkout", res, required, detail, verdict, command, user, timeout=60)
    state = "submitted_check_status" if r and r.exit_code == 0 else "outcome_unknown"
    await db.execute(update(ShoppingCart).where(ShoppingCart.resource_id == res.id, ShoppingCart.cart_id == cart)
                     .values(submit_state=state))
    await db.commit()
    if r is None:
        return out
    await audit.record(db, tool="doordash.checkout.timing", decision=state, agent=agent, session_id=sid,
                       detail={"resource": res.name, "gate_ms": gate_ms, "remote_ms": r.duration_ms},
                       duration_ms=int((time.monotonic() - started) * 1000))
    return m._result({"stage": state, "exit_code": r.exit_code, "stdout": r.stdout, "stderr": r.stderr,
                      "truncated": r.truncated, "keywright": out,
                      "timing": {"gate_ms": gate_ms, "remote_ms": r.duration_ms, **r.timing,
                                 "broker_total_ms": int((time.monotonic() - started) * 1000)},
                      "hint": "Check order status to confirm acceptance/payment. Do not replay this cart."})
