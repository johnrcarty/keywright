"""Reviewed DoorDash v0.2.6 command contract. No account data or credentials in this cache."""
from __future__ import annotations

import hashlib
import json
import shlex

VERSION = "0.2.6"
SESSION_SECONDS = 1200

# Only these commands can use a shopping grant. New provider commands fail closed.
READ = {
    "search", "menu", "store-details", "restaurant-item-details", "item-details",
    "find-items", "find-nearby-stores", "find-item-across-retailers",
    "cart list", "cart show", "order history", "order status", "order preview",
    "address list", "payment-method list", "promo list", "auth status",
    "doubledash options", "doubledash search",
}
PREPARE = {"cart add-items", "cart remove-item", "cart delete", "promo apply", "promo remove",
           "order reorder", "doubledash add"}
# Flags are deliberately allowlisted, including the preview flags which change cart state.
COMMON = {"--intent"}
FLAGS = {
    "search": "query lat lng address-id limit price-tier distance-preference max-eta-minutes",
    "menu": "store-id category-id menu-id",
    "store-details": "store-id",
    "restaurant-item-details": "store-id menu-id item-id",
    "item-details": "store-id item-id menu-id",
    "find-items": "store-id query limit",
    "find-nearby-stores": "lat lng query limit",
    "find-item-across-retailers": "query lat lng limit",
    "cart list": "", "cart show": "cart-uuid",
    "cart add-items": "store-id menu-id items-json cart-uuid fulfillment",
    "cart remove-item": "cart-uuid cart-item-id",
    "cart delete": "cart-uuid",
    "order history": "limit offset", "order status": "order-uuid cart-uuid",
    "order preview": "cart-uuid scheduled-time fulfillment selected-budget-id card-id",
    "order reorder": "order-uuid",
    "address list": "", "payment-method list": "", "auth status": "",
    "promo list": "store-id cart-uuid", "promo apply": "cart-uuid promo-code", "promo remove": "cart-uuid",
    "doubledash options": "order-uuid",
    "doubledash search": "order-uuid query max-stores lat lng",
    "doubledash add": "order-uuid cart-uuid store-id item-id menu-id quantity nested-options query lat lng",
}
BOOL_FLAGS = {"search": {"--dashpass-only"},
              "order preview": {"--priority", "--include-work-benefits", "--no-apply-credits", "--beautify"}}


def enabled(resource):
    return resource.kind == "ssh" and resource.config.get("integration") == "doordash"


def versioned_command(command: str) -> str:
    # Same SSH connection, no cached credential output. A changed binary invalidates the contract.
    script = ('v=$(dd-cli --version) || exit; case "$v" in '
              '*", version 0.2.6") exec sh -c "$1";; '
              '*) echo "Keywright: unsupported dd-cli version; reviewed version is 0.2.6" >&2; exit 2;; esac')
    return shlex.join(["sh", "-c", script, "kw-doordash", command])


def parse(command: str) -> dict:
    """Parse argv, then execute ONLY the quoted reconstruction, never the input shell program."""
    args = shlex.split(command)
    if not args or args.pop(0) != "dd-cli":
        raise ValueError("DoorDash connections accept dd-cli commands only; use the underlying host for maintenance.")
    original = list(args)
    if args and args[0] == "--json-output":
        args.pop(0)
    if args in (["--help"], ["-h"], ["--version"]):
        return {"command": shlex.join(["dd-cli", *original]), "cli_category": "read", "shopping": True,
                "cli_command": "help", "cli_flags": {}}
    if not args:
        raise ValueError("Specify a DoorDash command or --help")
    name = args.pop(0)
    if name in {"cart", "order", "address", "payment-method", "promo", "auth", "doubledash"}:
        name += " " + (args.pop(0) if args else "")
    if name == "order submit":
        raise ValueError("Use kw shop HOST checkout with --cart-uuid, --card-id and --tip-cents for a priced approval.")
    if name not in READ | PREPARE:
        raise ValueError("This command is outside the reviewed DoorDash shopping contract; use kw shop HOST guide.")
    values = COMMON | {"--" + f for f in FLAGS[name].split()}
    flags = {}
    while args:
        flag = args.pop(0)
        if flag in flags:
            raise ValueError(f"Repeated flag: {flag}")
        if flag in {"--help", "-h"} | BOOL_FLAGS.get(name, set()):
            flags[flag] = True
        elif flag in values and args and not args[0].startswith("--"):
            flags[flag] = args.pop(0)
        else:
            raise ValueError(f"Unreviewed or incomplete DoorDash option: {flag}")
    category = "cart" if name in PREPARE or (name == "order preview" and
                  {"--fulfillment", "--selected-budget-id"} & flags.keys()) else "read"
    if "--help" in flags or "-h" in flags:
        category = "read"
    elif name in {"doubledash add", "doubledash options", "doubledash search", "order status"} and original[0] != "--json-output":
        original.insert(0, "--json-output")  # Link/deadline evidence must be machine readable.
    return {"command": shlex.join(["dd-cli", *original]), "cli_category": category, "shopping": True,
            "cli_command": name, "cli_flags": flags}


def guide() -> dict:
    return {"version": VERSION, "source": "Reviewed contract for the checksum-pinned dd-cli v0.2.6 release",
            "commands": {name: {"values": sorted(COMMON | {"--" + f for f in FLAGS[name].split()}),
                                "switches": sorted(BOOL_FLAGS.get(name, set()))} for name in sorted(FLAGS)},
            "workflow": [
                "Start a 20-minute shopping session; browsing and cart preparation share one approval.",
                ("Read existing carts before adding. Preview items live under quote.store_order_cart.orders[].order_items; "
                "cart list can omit special instructions. Preserve each person's preferences separately."),
                "Fetch restaurant-item-details with store-id, menu-id AND item-id before selecting required modifiers.",
                ("Checkout requires explicit card-id and tip-cents. Keywright previews with that card, presents one "
                "priced approval, then rechecks it. Use kw shop HOST checkout, not raw order submit."),
                ("After submit, check order status: acceptance and payment may still be processing. Never replay an "
                "uncertain submit. Keywright records attempted carts durably and blocks repeat submissions."),
                ("DoubleDash is discoverable from order status even when absent from root help. Check expires_at, "
                "then options/search, add and checkout. Pass the same query from search to add. Do not invent or "
                "strip ID prefixes. Never checkout after link_confirmed=false; do not repeat add blindly."),
                ("Preview flags fulfillment and selected-budget-id can mutate cart state. Account default changes, "
                "courier and business administration are outside shopping access."),
                ("Exit 3: renew sign-in in Keywright. Exit 4: account/feature gated. Exit 5: timed-out writes may "
                "have happened; inspect state. Exit 7: action rejected; inspect item-level errors before retrying."),
                "Record sanitized CLI/KW observations as private beta-feedback talking points; never send them externally.",
            ]}


def quote_snapshot(data: dict, *, cart: str, card: str, tip: int, options: dict, link: dict | None = None) -> dict:
    """Fail closed on incomplete quotes; omit volatile delivery scheduling/UI data from the binding."""
    if not isinstance(data, dict) or data.get("success") is not True or data.get("partial_response") or data.get("error_message"):
        raise ValueError("DoorDash did not return a complete successful quote")
    quote = data.get("quote") or {}
    store_cart = quote.get("store_order_cart") or {}
    orders = store_cart.get("orders") or []
    items = [item for order in orders for item in order.get("order_items", [])]
    money = quote.get("net_total_before_tip") or quote.get("total_before_tip") or {}
    payment = data.get("payment_method") or {}
    if (data.get("cart_uuid") != cart or not items or payment.get("card_id") != card or payment.get("is_expired")
            or type(money.get("unit_amount")) is not int or money["unit_amount"] < 0 or money.get("currency") != "USD"):
        raise ValueError("Quote lacks matching cart, items, selected card or USD total; review in DoorDash")
    if not payment.get("display_name") or not quote.get("delivery_address") and not store_cart.get("is_consumer_pickup"):
        raise ValueError("Quote lacks a readable payment method or delivery destination")
    if any(not isinstance(i, dict) or not i.get("item", {}).get("name") or type(i.get("quantity")) is not int
           or i["quantity"] < 1 for i in items):
        raise ValueError("Quote contains incomplete items")
    return {"cart_uuid": cart, "store": store_cart.get("store"), "items": items,
            "destination": quote.get("delivery_address"), "pickup": bool(store_cart.get("is_consumer_pickup")),
            "charges": quote.get("line_items"), "before_tip_cents": money["unit_amount"],
            "tip_cents": tip, "total_cents": money["unit_amount"] + tip, "currency": "USD",
            "payment": {"card_id": card, "display_name": payment["display_name"]},
            "dropoff": quote.get("dropoff_options"), "warning": data.get("warning"),
            "options": options, "link": link}


def fingerprint(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
