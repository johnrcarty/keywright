"""Usage totals from local proxy audit events, with independent provider identities."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select

from .models import AuditEvent, LlmKey, Resource


def count(value):
    return value if type(value) is int and 0 <= value else None


def token_counts(usage):
    usage = usage if isinstance(usage, dict) else {}
    incoming = count(usage.get("prompt", usage.get("input")))
    outgoing = count(usage.get("completion", usage.get("output")))
    # Anthropic cache counts are additional input; OpenAI cached tokens are a subset.
    if incoming is not None and "prompt" not in usage:
        incoming += (count(usage.get("cache_creation_input")) or 0)
        incoming += (count(usage.get("cache_read_input")) or 0)
    total = count(usage.get("total"))
    if total is None and (incoming is not None or outgoing is not None):
        total = (incoming or 0) + (outgoing or 0)
    return incoming, outgoing, total


@dataclass
class Totals:
    requests: int = 0
    errors: int = 0
    reported: int = 0
    unreported: int = 0
    partial: int = 0
    input: int = 0
    output: int = 0
    total: int = 0

    def add(self, event):
        incoming, outgoing, total = token_counts(event.detail.get("usage"))
        self.requests += 1
        self.errors += event.decision == "error"
        self.reported += total is not None
        self.unreported += total is None
        self.partial += total is not None and (
            incoming is None or outgoing is None or event.detail.get("response_complete") is False)
        self.input += incoming or 0
        self.output += outgoing or 0
        self.total += total or 0


async def report(db, start: datetime, end: datetime, *, provider="", model="", agent="", key=""):
    # Only select safe identity fields, never load upstream secrets into the report.
    resources = (await db.execute(select(Resource.id, Resource.name).where(Resource.kind == "llm"))).all()
    resource_names = dict(resources)
    resource_ids = {name: rid for rid, name in resources}
    aliases = {}
    for kid, rid, aid, alias in (await db.execute(select(
            LlmKey.id, LlmKey.resource_id, LlmKey.agent_id, LlmKey.key_alias))).all():
        identity = (rid, aid, alias)
        # Ambiguous historical aliases must stay separate from known key IDs.
        aliases[identity] = kid if identity not in aliases else None

    options = {name: {} for name in ("provider", "model", "agent", "key")}
    providers, models, keys, days = {}, {}, {}, {}
    summary = Totals()
    recent = []
    stmt = select(AuditEvent).where(
        AuditEvent.tool == "llm.call", AuditEvent.ts >= start, AuditEvent.ts < end,
        AuditEvent.decision.in_(["allow", "error"])
    ).order_by(AuditEvent.ts.desc(), AuditEvent.id.desc()).execution_options(yield_per=500)
    async for event in (await db.stream_scalars(stmt)):
        detail = event.detail
        # Exclude discovery, blocked calls, and key-mint failures before an upstream attempt.
        if not detail.get("model") or not (detail.get("gateway_key_id") or detail.get("key_alias")):
            continue
        gateway = detail.get("gateway") or "Unknown provider"
        pid = detail.get("resource_id") or resource_ids.get(gateway) or "legacy:" + gateway
        provider_name = resource_names.get(pid, gateway)
        model_name = detail["model"]
        aid = event.agent_id or "legacy:" + event.agent_name
        agent_name = event.agent_name or "Unknown agent"
        alias = detail.get("key_alias") or "Unidentified key"
        kid = (detail.get("gateway_key_id") or aliases.get((pid, event.agent_id, alias))
               or "legacy:" + alias)
        # A key selector includes its provider and agent, including for legacy aliases.
        key_identity = json.dumps([pid, aid, kid], separators=(",", ":"))
        labels = {"provider": (pid, provider_name), "model": (model_name, model_name),
                  "agent": (aid, agent_name),
                  "key": (key_identity, f"{alias} · {provider_name} · {agent_name} · {kid}")}
        for dimension, (value, label) in labels.items():
            options[dimension][value] = label
        if any(selected and labels[dimension][0] != selected for dimension, selected in (
                ("provider", provider), ("model", model), ("agent", agent), ("key", key))):
            continue
        summary.add(event)
        p = providers.setdefault(pid, {"id": pid, "name": provider_name, "totals": Totals(), "models": {}})
        p["totals"].add(event)
        m = p["models"].setdefault(model_name, {"name": model_name, "totals": Totals()})
        m["totals"].add(event)
        models.setdefault(model_name, Totals()).add(event)
        k = keys.setdefault(key_identity, {"id": key_identity, "alias": alias, "key_id": kid,
                                          "provider": provider_name, "agent": agent_name,
                                          "totals": Totals(), "models": set()})
        k["totals"].add(event)
        k["models"].add(model_name)
        day = event.ts.date().isoformat()
        days.setdefault(day, Totals()).add(event)
        if len(recent) < 50:
            recent.append({"id": event.id, "ts": event.ts, "provider": provider_name, "model": model_name,
                           "agent": agent_name, "alias": alias, "decision": event.decision,
                           "total": token_counts(detail.get("usage"))[2]})
    ranked = lambda row: (-row["totals"].total, -row["totals"].requests)
    return {"totals": summary, "providers": sorted(providers.values(), key=ranked),
            "models": sorted(models.items(), key=lambda row: (-row[1].total, -row[1].requests)),
            "keys": sorted(keys.values(), key=ranked), "days": sorted(days.items()), "recent": recent,
            "options": {name: sorted(values.items(), key=lambda pair: pair[1].lower())
                        for name, values in options.items()}}
