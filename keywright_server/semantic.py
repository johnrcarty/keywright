"""Jev (TypeSafe) as a second opinion on operations that are about to prompt the human.

Runs on exactly one branch of the gate: the operation is not covered by standing access, not
denied, not a critical-hazard refusal, and a request is about to be created for it. Allowed
operations and denials never reach it, so it can only ever shrink the set of prompts, never
widen access.

`shadow` mode records Jev's verdict on the request and shows it wherever the human decides;
nothing is decided by it. `trust` mode approves an operation once, exactly, in Jev's name when
every deterministic guard passes and Jev's answers clear the safety and truthfulness thresholds;
anything else falls through to the human unchanged. A timeout, a provider error, a malformed
answer or a sanitiser refusal is "no verdict", which is never an approval.

What leaves the host: the command line, path or tool arguments, the agent's stated reason, and
an MCP tool's description and schema. Resource names are replaced with placeholders and values
that look like credentials abort the call. Nothing about the decision, the grant or the result
is sent.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import re
import time
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from . import audit, settings_store
from .config import settings
from .jev import (  # noqa: F401
    ENDPOINT,
    MAX_RESPONSE_BYTES,
    MODEL,
    QUESTION_PATH,
    canonical,
    questions_spec,
    strict_json,
    validate_response,
)

log = logging.getLogger("keywright.semantic")

MAX_STATE_BYTES = 8192
MAX_DESCRIPTOR_BYTES = 2048
SCHEMA_VERSION = "keywright.semantic.v1"

MODES = ("off", "shadow", "trust")
# The trust radio in the UI stays disabled until shadow data has earned it. Flipping this is a
# deliberate code change, not a setting.
TRUST_SELECTABLE = False
DEFAULT_TIMEOUT_S = 5.0
DEFAULT_DAILY_CAP = 2000

EFFECTS = ("modifies_state", "persistent_change", "deletes_data", "accesses_credentials",
           "affects_security_boundary", "affects_physical_world", "interrupts_service")
EFFECT_WORDS = {"modifies_state": "modifies state", "persistent_change": "persistent change",
                "deletes_data": "deletes data", "accesses_credentials": "reads credentials",
                "affects_security_boundary": "changes a security boundary",
                "affects_physical_world": "physical effect", "interrupts_service": "interrupts a service"}

# "Safe" is deliberately narrow: a read, with every effect near zero, whose stated reason fits.
SAFE_EFFECT_MAX = 0.15
SAFE_CATEGORY_CONFIDENCE = 0.8
TASK_FIT_MIN = 0.85
# "Unsafe" is anything Jev is at least as sure is harmful as not. Modifying state is what every
# write does and is not harm by itself: a write that is not otherwise unsafe is "write".
HARMFUL = ("deletes_data", "accesses_credentials", "affects_security_boundary", "affects_physical_world",
           "interrupts_service")
UNSAFE_EFFECT_MIN = 0.5
TASK_FIT_UNTRUE = 0.5
VERDICTS = ("safe", "write", "unsafe", "unclear", "no_verdict")

SECRET_KEY = re.compile(r"token|secret|password|authorization|api.?key|private.?key|credential|headers|environment",
                        re.IGNORECASE)
SECRET_TEXT = re.compile(
    r"-----BEGIN .*PRIVATE KEY|\bBearer\s+\S+|\b(?:password|passwd|token|api[_-]?key|secret)\s*[=:]\s*\S+"
    r"|https?://[^\s/]+:[^\s/]+@|\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]+|kw_[A-Za-z0-9_-]{16,}"
    r"|gk_[A-Za-z0-9_-]{16,})", re.IGNORECASE,
)
BLOCKED_KEYS = {"content", "body", "stdout", "stderr", "output", "env", "environment", "config",
                "script", "code", "payload", "examples", "default"}


# ---- configuration -------------------------------------------------------------------------------

def configured() -> bool:
    return bool((settings.typesafe_api_key or "").strip())


def defaults() -> dict[str, Any]:
    return {"mode": "shadow" if configured() else "off", "timeout_s": DEFAULT_TIMEOUT_S,
            "daily_cap": DEFAULT_DAILY_CAP}


async def config(db: AsyncSession) -> dict[str, Any]:
    cfg = {**defaults(), **(await settings_store.get(db, "semantic", defaults()))}
    if not configured() or cfg.get("mode") not in MODES:
        cfg["mode"] = "off"
    if cfg["mode"] == "trust" and not TRUST_SELECTABLE:
        cfg["mode"] = "shadow"
    return cfg


def validate_config(form: dict[str, Any]) -> dict[str, Any]:
    """The settings form, checked. Trust cannot be chosen while the radio is disabled, whatever
    the browser posts."""
    mode = str(form.get("mode") or "off")
    if mode not in MODES:
        raise ValueError("Unknown mode")
    if mode == "trust" and not TRUST_SELECTABLE:
        raise ValueError("Trust Jev is not available yet: it stays disabled until shadow data has earned it")
    try:
        timeout_s = float(form.get("timeout_s") or DEFAULT_TIMEOUT_S)
        daily_cap = int(form.get("daily_cap") or DEFAULT_DAILY_CAP)
    except (TypeError, ValueError):
        raise ValueError("Timeout and daily cap must be numbers") from None
    if not (1 <= timeout_s <= 30) or not (0 <= daily_cap <= 100_000):
        raise ValueError("Timeout must be 1 to 30 seconds and the daily cap 0 to 100000 calls")
    return {"mode": mode, "timeout_s": timeout_s, "daily_cap": daily_cap}


# ---- questions -----------------------------------------------------------------------------------

def questions_for(state: dict) -> dict:
    spec = questions_spec()
    chosen = dict(spec["core"])
    if "declared_task" in state:
        chosen["relevant_to_declared_task"] = spec["contextual"]["relevant_to_declared_task"]
    return {key: {**q, "instructions": spec["preamble"] + " " + q["instructions"]} for key, q in chosen.items()}


# ---- state: what a request looks like to Jev ------------------------------------------------------

def _clean(value, omissions: list[str], depth: int = 0):
    if depth > 12:
        raise ValueError("depth")
    if isinstance(value, dict):
        out = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError("key")
            if SECRET_KEY.search(key) or key.lower() in BLOCKED_KEYS:
                omissions.append("sensitive_or_payload_field")
                continue
            if SECRET_TEXT.search(key):
                raise ValueError("secret")
            out[key] = _clean(child, omissions, depth + 1)
        return out
    if isinstance(value, list):
        return [_clean(v, omissions, depth + 1) for v in value]
    if isinstance(value, str) and SECRET_TEXT.search(value):
        raise ValueError("secret")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("nan")
    return value


def build_state(detail: dict, reason: str, *, resource_kind: str | None = None,
                descriptor: dict | None = None) -> tuple[dict | None, str | None]:
    """(state, None) for a single operation, or (None, why) when there is nothing to ask about or
    the operation cannot be sent. Never raises on caller data."""
    if not detail or "operations" in detail or "bundles" in detail:
        return None, "not_a_single_operation"
    omissions: list[str] = []
    try:
        if detail.get("command") is not None:
            action: dict[str, Any] = {"protocol": "ssh", "operation": "exec", "command": detail["command"]}
            if detail.get("to_path"):
                action["operation"] = "capture"
                action["destination"] = {
                    "resource_ref": "resource-a" if detail.get("to_host") == detail.get("host") else "resource-b",
                    "path": detail["to_path"], "append": bool(detail.get("append"))}
        elif "sha256" in detail:
            action = {"protocol": "ssh", "operation": "put", "path": detail.get("path"),
                      "bytes": detail.get("bytes")}
            omissions.append("file_contents")
        elif detail.get("path") is not None:
            action = {"protocol": "ssh", "operation": "get", "path": detail["path"]}
        elif detail.get("tool") is not None:
            action = {"protocol": "mcp", "operation": "tool_call", "tool": detail["tool"],
                      "arguments": detail.get("arguments") if isinstance(detail.get("arguments"), dict) else {}}
            if descriptor:
                d = {k: v for k, v in descriptor.items() if k in ("description", "input_schema")}
                if len(canonical(d).encode()) <= MAX_DESCRIPTOR_BYTES:
                    action["tool_descriptor"] = d
                else:
                    omissions.append("tool_descriptor_too_large")
        else:
            return None, "unsupported_operation"
        action = _clean(action, omissions)
        action["resource_ref"] = "resource-a"
        if action["protocol"] == "ssh" and detail.get("user"):
            action["remote_account_class"] = "service_account"
        state: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "action": action,
            "trusted_context": {"resource_kind": resource_kind or action["protocol"]},
            "untrusted_context": _clean({"agent_reason": reason or None}, omissions),
            "evidence": {"context_source": "broker", "omitted_fields": sorted(set(omissions)),
                         "action_complete": not omissions},
        }
        if reason:
            state["declared_task"] = {"text": reason, "source": "untrusted_assertion"}
    except (ValueError, TypeError, RecursionError):
        return None, "unsafe_or_unrepresentable"
    if len(canonical(state).encode()) > MAX_STATE_BYTES:
        return None, "state_too_large"
    return state, None


# ---- the call ------------------------------------------------------------------------------------

class _Day:
    """In-process daily call counter; a cap on spend, not an audit."""

    def __init__(self):
        self.date = None
        self.calls = 0

    def take(self, cap: int) -> bool:
        today = datetime.now(UTC).date()
        if today != self.date:
            self.date, self.calls = today, 0
        if self.calls >= cap:
            return False
        self.calls += 1
        return True


_day = _Day()


async def ask(state: dict, questions: dict, *, timeout_s: float,
              transport: httpx.AsyncBaseTransport | None = None) -> dict[str, Any]:
    """One bounded POST. Returns {"status": "ok", "body": ...} or {"status": <failure>, "reason": ...}.
    No retry: a second attempt would double the spend and the human is waiting either way."""
    payload = {"model": MODEL, "state": state, "questions": questions}
    started = time.perf_counter()

    async def request():
        headers = {"Authorization": f"Bearer {settings.typesafe_api_key.strip()}"}
        async with (httpx.AsyncClient(headers=headers, timeout=timeout_s, trust_env=False, follow_redirects=False,
                                      transport=transport) as http,
                    http.stream("POST", ENDPOINT, json=payload) as response):
            if response.status_code != 200:
                return {"status": "provider_error", "reason": f"http_{response.status_code}"}
            data = bytearray()
            async for chunk in response.aiter_bytes():
                if len(data) + len(chunk) > MAX_RESPONSE_BYTES:
                    return {"status": "invalid_response", "reason": "response_too_large"}
                data.extend(chunk)
            return {"status": "ok", "body": validate_response(strict_json(data.decode("utf-8")), questions, MODEL)}

    try:
        result = await asyncio.wait_for(request(), timeout=timeout_s)
    except (TimeoutError, httpx.TimeoutException):
        result = {"status": "timeout", "reason": "deadline"}
    except httpx.HTTPError as e:
        result = {"status": "provider_error", "reason": f"transport: {type(e).__name__}"}
    except (ValueError, TypeError, RecursionError, UnicodeDecodeError):
        result = {"status": "invalid_response", "reason": "schema"}
    result["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return result


# ---- reading the answers -------------------------------------------------------------------------

def summarize(answers: dict) -> dict[str, Any]:
    cat, rev = answers["action_category"], answers["reversibility"]
    fit = answers.get("relevant_to_declared_task")
    return {
        "category": cat["choice"], "category_confidence": round(cat["confidence"], 3),
        "effects": {k: round(answers[k]["noul"], 3) for k in EFFECTS},
        "reversibility": rev["choice"], "reversibility_confidence": round(rev["confidence"], 3),
        "task_fit": round(fit["noul"], 3) if fit else None,
    }


def judge(summary: dict, operation: str | None = None) -> str:
    """safe | write | unsafe | unclear, from the summary alone. Safe requires a stated reason that
    fits: an agent that says nothing about why cannot be found truthful. A file write (`put`) is
    an overwrite by nature and the human already sees the path, so "deletes data" does not make
    one unsafe on its own."""
    effects, fit = summary["effects"], summary["task_fit"]
    if (fit is not None and fit >= TASK_FIT_MIN
            and summary["category"] == "READ" and summary["category_confidence"] >= SAFE_CATEGORY_CONFIDENCE
            and summary["reversibility"] in ("NOT_APPLICABLE", "EASY")
            and all(p <= SAFE_EFFECT_MAX for p in effects.values())):
        return "safe"
    harmful = [k for k in HARMFUL if not (k == "deletes_data" and operation == "put")]
    if (any(effects[k] >= UNSAFE_EFFECT_MIN for k in harmful)
            or (summary["category"] in ("DESTRUCTIVE", "SECURITY") and summary["category_confidence"] >= 0.5)
            or (fit is not None and fit <= TASK_FIT_UNTRUE)):
        return "unsafe"
    if effects["modifies_state"] >= UNSAFE_EFFECT_MIN or effects["persistent_change"] >= UNSAFE_EFFECT_MIN:
        return "write"
    return "unclear"


def guards(required: list[str], detail: dict, reason: str) -> list[str]:
    """Deterministic reasons an operation can never be approved in Jev's name, whatever it says."""
    from .access import hazard_level

    out = []
    if hazard_level(detail):
        out.append("hazard flagged")
    if any("**" in p for p in required):
        out.append("wildcard permission")
    if any(len(p.split("/")) > 2 and p.split("/")[2] == "user" for p in required):
        out.append("non-default remote user")
    if not (reason or "").strip():
        out.append("no reason given")
    return out


def describe(verdict: dict | None) -> str:
    """One phone-sized line. Empty when there is nothing recorded."""
    if not verdict:
        return ""
    if verdict.get("status") != "ok":
        return f"Jev: no verdict ({verdict.get('reason') or verdict.get('status')})"
    s = verdict["summary"]
    parts = [f"Jev: {verdict['verdict']}", f"{s['category']} {s['category_confidence']:.2f}"]
    loud = [f"{EFFECT_WORDS[k]} {s['effects'][k]:.2f}" for k in HARMFUL if s["effects"][k] >= UNSAFE_EFFECT_MIN]
    parts += loud[:3]
    if s["task_fit"] is None:
        parts.append("no reason to check")
    else:
        parts.append(f"reason {'fits' if s['task_fit'] >= TASK_FIT_MIN else 'unclear' if s['task_fit'] > TASK_FIT_UNTRUE else 'does not fit'} {s['task_fit']:.2f}")
    if verdict.get("auto", {}).get("eligible"):
        parts.append("would auto-approve" if verdict.get("mode") != "trust" else "auto-approved")
    return " · ".join(parts)


# ---- the entry point the gate calls --------------------------------------------------------------

async def _descriptor(db: AsyncSession, detail: dict) -> dict | None:
    from . import mcp_proxy
    from .models import Resource

    res = await db.get(Resource, detail.get("resource_id")) if detail.get("resource_id") else None
    if res is None or res.kind != "mcp":
        return None
    try:
        for t in await mcp_proxy.list_tools(res.name, res.config):
            if t.name == detail.get("tool"):
                return {"description": t.description or "", "input_schema": t.inputSchema or {}}
    except Exception:  # noqa: BLE001 - a descriptor is context, never a reason to fail the gate
        log.debug("tool descriptor unavailable for %s", detail.get("tool"))
    return None


async def assess(db: AsyncSession, required: list[str], reason: str, detail: dict, *,
                 transport: httpx.AsyncBaseTransport | None = None) -> dict | None:
    """Jev's verdict on one operation, or None when the feature is off or the request is not a
    single operation. Never raises: every failure is a recorded 'no verdict'."""
    cfg = await config(db)
    if cfg["mode"] == "off":
        return None
    resource_kind = None
    if detail.get("tool") is not None:
        resource_kind = "mcp"
    elif detail.get("host"):
        resource_kind = "ssh"
    descriptor = await _descriptor(db, detail) if resource_kind == "mcp" else None
    state, why = build_state(detail, reason, resource_kind=resource_kind, descriptor=descriptor)
    if state is None:
        if why == "not_a_single_operation":
            return None
        return {"provider": "jev", "model": MODEL, "mode": cfg["mode"], "status": "skipped", "reason": why,
                "verdict": "no_verdict", "auto": {"eligible": False, "blocked_by": [why]}}
    blocked = guards(required, detail, reason)
    base = {"provider": "jev", "model": MODEL, "mode": cfg["mode"], "questions": questions_spec()["version"],
            "operation": state["action"]["operation"],
            "state_sha256": hashlib.sha256(canonical(state).encode()).hexdigest(),
            "omitted": state["evidence"]["omitted_fields"]}
    if not _day.take(int(cfg["daily_cap"])):
        return {**base, "status": "skipped", "reason": "daily_cap", "verdict": "no_verdict",
                "auto": {"eligible": False, "blocked_by": ["daily cap reached", *blocked]}}
    questions = questions_for(state)
    result = await ask(state, questions, timeout_s=float(cfg["timeout_s"]), transport=transport)
    if result["status"] != "ok":
        return {**base, "status": result["status"], "reason": result.get("reason"),
                "latency_ms": result["latency_ms"], "verdict": "no_verdict",
                "auto": {"eligible": False, "blocked_by": ["no verdict", *blocked]}}
    body = result["body"]
    summary = summarize(body["answers"])
    verdict = judge(summary, state["action"]["operation"])
    if verdict != "safe":
        blocked = [f"verdict {verdict}", *blocked]
    return {**base, "status": "ok", "latency_ms": result["latency_ms"], "usage": body["usage"],
            "answers": body["answers"], "summary": summary, "verdict": verdict,
            "auto": {"eligible": not blocked, "blocked_by": blocked}}


def auto_approves(verdict: dict | None) -> bool:
    """Trust mode, a clean verdict and no guard tripped. Everything else is the human's."""
    return bool(verdict and verdict.get("mode") == "trust" and verdict.get("status") == "ok"
                and verdict.get("verdict") == "safe" and verdict.get("auto", {}).get("eligible"))


async def record(db: AsyncSession, req, agent, session_id: str | None, verdict: dict | None) -> None:
    """The verdict as an audit row of its own, so the request timeline and the audit search see it
    without the request's detail (which grants bind to) changing shape."""
    if not verdict:
        return
    line = {"request_id": req.id, "mode": verdict.get("mode"), "status": verdict.get("status"),
            "verdict": verdict.get("verdict"), "auto_eligible": verdict.get("auto", {}).get("eligible"),
            "blocked_by": verdict.get("auto", {}).get("blocked_by"), "latency_ms": verdict.get("latency_ms"),
            "usage": verdict.get("usage"), "summary": verdict.get("summary"), "note": describe(verdict)}
    if verdict.get("reason"):
        line["reason"] = verdict["reason"]
    await audit.record(db, tool="semantic", decision=verdict.get("verdict") or "no_verdict", agent=agent,
                       session_id=session_id, patterns=list(req.patterns), detail=line)


async def shadow_tally(db: AsyncSession) -> dict[str, int]:
    """The number that decides whether trust is earned: of the requests Jev would have approved,
    how many did the human deny?"""
    from sqlalchemy import select

    from .models import AccessRequest

    rows = (await db.execute(select(AccessRequest.status, AccessRequest.semantic)
                             .where(AccessRequest.semantic.is_not(None)))).all()
    out = {"verdicts": 0, "no_verdict": 0, "safe": 0, "would_auto": 0, "would_auto_denied": 0,
           "would_auto_approved": 0, "unsafe_approved": 0}
    for status, v in rows:
        if not isinstance(v, dict):  # rows written before none_as_null hold the JSON value null
            continue
        out["verdicts"] += 1
        if v.get("status") != "ok":
            out["no_verdict"] += 1
            continue
        if v.get("verdict") == "safe":
            out["safe"] += 1
        if v.get("verdict") == "unsafe" and status == "approved":
            out["unsafe_approved"] += 1
        if v.get("auto", {}).get("eligible"):
            out["would_auto"] += 1
            if status == "denied":
                out["would_auto_denied"] += 1
            elif status == "approved":
                out["would_auto_approved"] += 1
    return out
