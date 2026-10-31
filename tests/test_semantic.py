"""Jev as a second opinion: shadow mode records and shows a verdict without deciding anything;
trust mode approves only a clean verdict on an unflagged, exactly-bound read, and every failure
is a human decision as before."""

import json

import httpx
import pytest
import respx
from sqlalchemy import select, text

from keywright_server import approvals, mcp_server, semantic, settings_store
from keywright_server.config import settings
from keywright_server.models import AccessRequest, AuditEvent, Resource
from keywright_server.notify.base import request_summary

# ---- answer profiles the fake TypeSafe returns -------------------------------------------------

def _noul(p):
    return {"type": "noul", "noul": p}


def _choice(criteria, pick, conf):
    rest = (1 - conf) / max(1, len(criteria) - 1)
    probs = {c: (conf if c == pick else rest) for c in criteria}
    return {"type": "choice", "choice": pick, "probabilities": probs, "confidence": conf}


PROFILES = {
    "safe": {"effects": 0.02, "category": ("READ", 0.96), "reversibility": ("NOT_APPLICABLE", 0.9), "fit": 0.95},
    "destructive": {"effects": 0.9, "category": ("DESTRUCTIVE", 0.9), "reversibility": ("IRREVERSIBLE", 0.8), "fit": 0.9},
    "untruthful": {"effects": 0.02, "category": ("READ", 0.96), "reversibility": ("NOT_APPLICABLE", 0.9), "fit": 0.1},
    "unclear": {"effects": 0.3, "category": ("READ", 0.6), "reversibility": ("UNKNOWN", 0.5), "fit": 0.7},
    # a plain write: modifies state, nothing harmful
    "write": {"effects": {"modifies_state": 0.94, "persistent_change": 0.93}, "category": ("MUTATION", 0.7),
              "reversibility": ("MODERATE", 0.6), "fit": 0.9},
    # a file write Jev reads as an overwrite of whatever is there
    "overwrite": {"effects": {"modifies_state": 0.94, "persistent_change": 0.93, "deletes_data": 0.72},
                  "category": ("MUTATION", 0.63), "reversibility": ("UNKNOWN", 0.7), "fit": 0.87},
}


def answers_for(questions: dict, profile: str) -> dict:
    p = PROFILES[profile]
    out = {}
    for key, q in questions.items():
        if key in semantic.EFFECTS:
            e = p["effects"]
            out[key] = _noul(e.get(key, 0.05) if isinstance(e, dict) else e)
        elif key == "relevant_to_declared_task":
            out[key] = _noul(p["fit"])
        elif key == "action_category":
            out[key] = _choice(list(q["criteria"]), *p["category"])
        elif key == "reversibility":
            out[key] = _choice(list(q["criteria"]), *p["reversibility"])
        else:
            raise AssertionError(f"unexpected question {key}")
    return out


@pytest.fixture
def typesafe(monkeypatch):
    """Fake TypeSafe. `typesafe.profile` picks the answers; `typesafe.fail` makes it time out or 500."""
    monkeypatch.setattr(settings, "typesafe_api_key", "test-typesafe-key")
    monkeypatch.setattr(semantic, "_day", semantic._Day())

    class Fake:
        def __init__(self):
            self.profile = "safe"
            self.fail = None
            self.seen: list[dict] = []

        def respond(self, request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            self.seen.append(body)
            assert request.headers["authorization"] == "Bearer test-typesafe-key"
            if self.fail == "timeout":
                raise httpx.ReadTimeout("slow", request=request)
            if self.fail == "500":
                return httpx.Response(500, text="boom")
            return httpx.Response(200, json={"model": body["model"], "answers": answers_for(body["questions"], self.profile),
                                             "usage": {"input_tokens": 1500, "output_tokens": 200}})

    fake = Fake()
    with respx.mock(assert_all_called=False) as router:
        router.post(semantic.ENDPOINT).mock(side_effect=fake.respond)
        yield fake


@pytest.fixture
async def prod(db):
    res = Resource(kind="ssh", name="prod", default_mode="approval", config={"host": "127.0.0.1", "user": "root"})
    db.add(res)
    await db.commit()
    return res


async def set_mode(db, mode, **extra):
    await settings_store.put(db, "semantic", {"mode": mode, "timeout_s": 5, "daily_cap": 100, **extra})


async def run(db, agent, command, reason="check disk space", sid="s1"):
    return await mcp_server._ssh_run(db, agent, sid, {"host": "prod", "command": command, "reason": reason,
                                                        "wait_seconds": 0})


async def requests(db):
    return (await db.execute(select(AccessRequest).order_by(AccessRequest.created_at))).scalars().all()


# ---- what Jev is shown --------------------------------------------------------------------------

def test_state_for_each_operation_shape(prod_detail=None):
    state, why = semantic.build_state({"host": "prod", "command": "df -h", "user": "root", "resource_id": "r1"},
                                      "check disk", resource_kind="ssh")
    assert why is None
    assert state["action"] == {"protocol": "ssh", "operation": "exec", "command": "df -h", "resource_ref": "resource-a",
                               "remote_account_class": "service_account"}
    assert "prod" not in semantic.canonical(state) and "r1" not in semantic.canonical(state)
    assert state["declared_task"] == {"text": "check disk", "source": "untrusted_assertion"}
    assert state["evidence"]["action_complete"]

    state, _ = semantic.build_state({"host": "prod", "path": "/etc/x", "sha256": "ab", "bytes": 12, "user": "root"}, "")
    assert state["action"]["operation"] == "put" and "sha256" not in state["action"]
    assert state["evidence"]["omitted_fields"] == ["file_contents"] and "declared_task" not in state

    state, _ = semantic.build_state({"host": "prod", "path": "/var/log/syslog", "user": "root"}, "logs")
    assert state["action"] == {"protocol": "ssh", "operation": "get", "path": "/var/log/syslog",
                               "resource_ref": "resource-a", "remote_account_class": "service_account"}

    state, _ = semantic.build_state({"host": "a", "command": "cat f", "user": "root", "to_host": "b",
                                     "to_path": "/tmp/f", "to_user": "root", "append": False}, "move")
    assert state["action"]["operation"] == "capture"
    assert state["action"]["destination"] == {"resource_ref": "resource-b", "path": "/tmp/f", "append": False}

    state, _ = semantic.build_state({"server": "ha", "tool": "get_state", "arguments": {"entity_id": "light.x"},
                                     "resource_id": "r2"}, "read", resource_kind="mcp",
                                    descriptor={"description": "Read one entity", "input_schema": {"type": "object"}})
    assert state["action"]["tool_descriptor"] == {"description": "Read one entity", "input_schema": {"type": "object"}}
    assert state["action"]["arguments"] == {"entity_id": "light.x"}


def test_batched_and_pattern_requests_are_not_assessed():
    assert semantic.build_state({"operations": [{"patterns": [], "operation": {}}]}, "x") == (None, "not_a_single_operation")
    assert semantic.build_state({"bundles": {"read": ["a"]}}, "x") == (None, "not_a_single_operation")
    assert semantic.build_state({}, "x") == (None, "not_a_single_operation")


def test_secrets_never_leave():
    # a credential in the command line aborts the call rather than being sent
    state, why = semantic.build_state({"host": "p", "command": "curl -H 'Authorization: Bearer abc.def' x", "user": "root"}, "")
    assert state is None and why == "unsafe_or_unrepresentable"
    state, why = semantic.build_state({"host": "p", "command": "echo kw_abcdefghijklmnopqrstuvwxyz", "user": "root"}, "")
    assert state is None
    # a secret-looking key in tool arguments is dropped and the omission recorded
    state, _ = semantic.build_state({"server": "s", "tool": "t", "arguments": {"api_key": "x", "entity": "e"}}, "r")
    assert state["action"]["arguments"] == {"entity": "e"}
    assert state["evidence"]["omitted_fields"] == ["sensitive_or_payload_field"] and not state["evidence"]["action_complete"]
    # a secret in the reason aborts too
    state, why = semantic.build_state({"host": "p", "command": "ls", "user": "root"}, "use password=hunter2")
    assert state is None


# ---- reading the answers ------------------------------------------------------------------------

def _summary(profile):
    qs = semantic.questions_for({"declared_task": {"text": "x"}})
    return semantic.summarize(answers_for(qs, profile))


def test_judgement_thresholds():
    assert semantic.judge(_summary("safe")) == "safe"
    assert semantic.judge(_summary("destructive")) == "unsafe"
    assert semantic.judge(_summary("untruthful")) == "unsafe"
    assert semantic.judge(_summary("unclear")) == "unclear"
    # a write is a write, not a hazard; an overwrite is only a hazard when it is not a file put
    assert semantic.judge(_summary("write")) == "write"
    assert semantic.judge(_summary("overwrite"), "put") == "write"
    assert semantic.judge(_summary("overwrite"), "exec") == "unsafe"
    assert semantic.judge(_summary("write"), "put") == "write"
    # no reason: nothing to be truthful about, so never safe
    s = semantic.summarize(answers_for(semantic.questions_for({}), "safe"))
    assert s["task_fit"] is None and semantic.judge(s) == "unclear"


def test_guards_are_deterministic():
    detail = {"host": "prod", "command": "rm -rf /opt/*", "user": "root",
              "hazards": [{"severity": "high", "reason": "recursive delete"}]}
    assert semantic.guards(["ssh/prod/exec/rm"], detail, "cleanup") == ["hazard flagged"]
    assert semantic.guards(["ssh/prod/exec/**"], {"host": "prod", "command": "x | y"}, "r") == ["wildcard permission"]
    assert semantic.guards(["ssh/prod/exec/ls", "ssh/prod/user/deploy"], {"host": "prod", "command": "ls"}, "r") == [
        "non-default remote user"]
    assert semantic.guards(["ssh/prod/exec/ls"], {"host": "prod", "command": "ls"}, "  ") == ["no reason given"]
    assert semantic.guards(["ssh/prod/exec/ls"], {"host": "prod", "command": "ls"}, "list") == []


def test_one_line_reading():
    v = {"status": "ok", "verdict": "unsafe", "mode": "shadow", "summary": _summary("destructive"),
         "auto": {"eligible": False, "blocked_by": ["verdict unsafe"]}}
    line = semantic.describe(v)
    assert line.startswith("Jev: unsafe · DESTRUCTIVE 0.90") and "deletes data 0.90" in line and "reason fits 0.90" in line
    assert "modifies state" not in line
    v = {"status": "ok", "verdict": "write", "mode": "shadow", "summary": _summary("write"), "auto": {"eligible": False}}
    assert semantic.describe(v) == "Jev: write · MUTATION 0.70 · reason fits 0.90"
    assert semantic.describe({"status": "timeout", "reason": "deadline"}) == "Jev: no verdict (deadline)"
    assert semantic.describe(None) == ""


def test_trust_cannot_be_chosen_from_the_form(monkeypatch):
    with pytest.raises(ValueError, match="not available yet"):
        semantic.validate_config({"mode": "trust"})
    assert semantic.validate_config({"mode": "shadow", "timeout_s": "3", "daily_cap": "50"}) == {
        "mode": "shadow", "timeout_s": 3.0, "daily_cap": 50}
    with pytest.raises(ValueError):
        semantic.validate_config({"mode": "shadow", "timeout_s": "90"})
    monkeypatch.setattr(semantic, "TRUST_SELECTABLE", True)
    assert semantic.validate_config({"mode": "trust"})["mode"] == "trust"


# ---- through the gate ---------------------------------------------------------------------------

async def test_shadow_records_and_shows_but_never_decides(db, agent, prod, log_notifier, fake_ssh, typesafe):
    await set_mode(db, "shadow")
    typesafe.profile = "safe"
    out = await run(db, agent, "df -h")
    assert json.loads(out.content[0].text)["error"] == "approval_required"
    assert fake_ssh == []
    (req,) = await requests(db)
    assert req.status == "pending"
    v = req.semantic
    assert v["status"] == "ok" and v["verdict"] == "safe" and v["mode"] == "shadow"
    assert v["auto"] == {"eligible": True, "blocked_by": []}
    assert v["summary"]["category"] == "READ" and v["summary"]["task_fit"] == 0.95
    assert v["usage"] == {"input_tokens": 1500, "output_tokens": 200}
    # what went out: the command and the reason, not the host
    sent = typesafe.seen[-1]
    assert sent["model"] == semantic.MODEL and sent["state"]["action"]["command"] == "df -h"
    assert "prod" not in json.dumps(sent["state"]) and "relevant_to_declared_task" in sent["questions"]
    # the phone sees it, under the reason
    _, body = request_summary(req, agent)
    assert "Jev: safe · READ 0.96 · reason fits 0.95 · would auto-approve" in body
    # and the timeline has its own row
    ev = (await db.execute(select(AuditEvent).where(AuditEvent.tool == "semantic"))).scalar_one()
    assert ev.decision == "safe" and ev.detail["request_id"] == req.id and ev.detail["auto_eligible"] is True
    # the human still decides
    await approvals.decide(db, req.id, "once", via="ui")
    out = await run(db, agent, "df -h")
    assert out.structured_content["exit_code"] == 0 and fake_ssh


async def test_shadow_marks_unsafe_and_untruthful(db, agent, prod, log_notifier, typesafe):
    await set_mode(db, "shadow")
    typesafe.profile = "untruthful"
    await run(db, agent, "cat /etc/hostname", reason="check disk space")
    (req,) = await requests(db)
    assert req.status == "pending" and req.semantic["verdict"] == "unsafe"
    assert req.semantic["auto"]["blocked_by"] == ["verdict unsafe"]
    assert "reason does not fit 0.10" in request_summary(req, agent)[1]


async def test_no_verdict_on_timeout_or_error_is_still_a_human_decision(db, agent, prod, log_notifier, typesafe):
    await set_mode(db, "shadow")
    typesafe.fail = "timeout"
    await run(db, agent, "df -h", sid="s1")
    typesafe.fail = "500"
    await run(db, agent, "uptime", sid="s2")
    a, b = await requests(db)
    assert a.status == b.status == "pending"
    assert a.semantic["status"] == "timeout" and a.semantic["verdict"] == "no_verdict"
    assert b.semantic["status"] == "provider_error" and b.semantic["reason"] == "http_500"
    assert "Jev: no verdict (deadline)" in request_summary(a, agent)[1]


async def test_off_and_unconfigured_send_nothing(db, agent, prod, log_notifier, typesafe, monkeypatch):
    await set_mode(db, "off")
    await run(db, agent, "df -h", sid="s1")
    monkeypatch.setattr(settings, "typesafe_api_key", None)
    await set_mode(db, "shadow")
    await run(db, agent, "uptime", sid="s2")
    assert typesafe.seen == []
    assert all(r.semantic is None for r in await requests(db))


async def test_daily_cap_skips_without_calling(db, agent, prod, log_notifier, typesafe):
    await set_mode(db, "shadow", daily_cap=1)
    await run(db, agent, "df -h", sid="s1")
    await run(db, agent, "uptime", sid="s2")
    a, b = await requests(db)
    assert a.semantic["status"] == "ok" and b.semantic["status"] == "skipped" and b.semantic["reason"] == "daily_cap"
    assert len(typesafe.seen) == 1


async def test_batch_request_carries_no_verdict(db, agent, prod, log_notifier, typesafe):
    await set_mode(db, "shadow")
    out = await mcp_server._access_request(db, agent, "s1", {
        "operations": [{"host": "prod", "command": "df -h"}, {"host": "prod", "command": "uptime"}],
        "reason": "two reads", "wait_seconds": 0})
    assert json.loads(out.content[0].text)["status"] == "pending"
    (req,) = await requests(db)
    assert req.semantic is None and typesafe.seen == []


@pytest.fixture
def trust(monkeypatch):
    monkeypatch.setattr(semantic, "TRUST_SELECTABLE", True)


async def test_trust_approves_a_clean_read_once_and_exactly(db, agent, prod, log_notifier, fake_ssh, typesafe, trust):
    await set_mode(db, "trust")
    typesafe.profile = "safe"
    out = await run(db, agent, "df -h")
    assert out.structured_content["exit_code"] == 0 and fake_ssh == [("127.0.0.1", "df -h", "root")]
    (req,) = await requests(db)
    assert req.status == "approved" and req.decided_via == "jev" and req.decision_scope == "once"
    assert req.decision_options["extent"] == "exact" and req.semantic["mode"] == "trust"
    assert "auto-approved" in semantic.describe(req.semantic)
    # once means once: the same command asks again (and Jev is asked again)
    out = await run(db, agent, "df -h", sid="s2")
    assert out.structured_content["exit_code"] == 0 and len(typesafe.seen) == 2
    # the notifier was never asked to prompt for the auto-approved request
    assert all(e.tool != "notify" for e in (await db.execute(select(AuditEvent))).scalars().all())


@pytest.mark.parametrize("profile,fail,command,reason", [
    ("destructive", None, "df -h", "check disk"),           # Jev says unsafe
    ("write", None, "df -h", "check disk"),                 # a write is never auto-approved
    ("untruthful", None, "df -h", "check disk"),            # reason does not fit
    ("unclear", None, "df -h", "check disk"),               # not confidently safe
    ("safe", "timeout", "df -h", "check disk"),             # no verdict
    ("safe", "500", "df -h", "check disk"),                 # no verdict
    ("safe", None, "df -h", ""),                            # no reason to check
    ("safe", None, "rm -rf /opt/*", "cleanup"),             # hazard flagged
    ("safe", None, "bash -c 'ls /'", "look"),               # wildcard permission (exec/**)
])
async def test_trust_falls_through_to_the_human(db, agent, prod, log_notifier, fake_ssh, typesafe, trust,
                                               profile, fail, command, reason):
    await set_mode(db, "trust")
    typesafe.profile, typesafe.fail = profile, fail
    out = await run(db, agent, command, reason=reason)
    assert json.loads(out.content[0].text)["error"] == "approval_required"
    assert fake_ssh == []
    (req,) = await requests(db)
    assert req.status == "pending" and req.decided_via is None
    assert not semantic.auto_approves(req.semantic)


async def test_trust_setting_is_ignored_while_the_radio_is_disabled(db, agent, prod, log_notifier, fake_ssh, typesafe):
    """A `trust` row in the settings table (however it got there) behaves as shadow until the code says otherwise."""
    await set_mode(db, "trust")
    assert (await semantic.config(db))["mode"] == "shadow"
    await run(db, agent, "df -h")
    (req,) = await requests(db)
    assert req.status == "pending" and req.semantic["mode"] == "shadow" and fake_ssh == []


async def test_shadow_tally_counts_what_trust_would_have_done(db, agent, prod, log_notifier, typesafe):
    await set_mode(db, "shadow")
    typesafe.profile = "safe"
    await run(db, agent, "df -h", sid="s1")
    await run(db, agent, "uptime", sid="s2")
    typesafe.profile = "destructive"
    await run(db, agent, "id", sid="s3")
    a, b, c = await requests(db)
    await approvals.decide(db, a.id, "once", via="ui")
    await approvals.decide(db, b.id, "deny", via="ui")
    await approvals.decide(db, c.id, "once", via="ui")
    assert await semantic.shadow_tally(db) == {"verdicts": 3, "no_verdict": 0, "safe": 2, "would_auto": 2,
                                               "would_auto_denied": 1, "would_auto_approved": 1, "unsafe_approved": 1}


async def test_shadow_tally_skips_requests_jev_was_not_asked_about(db, agent, prod, log_notifier, typesafe):
    """A request made with Jev off stores no verdict; Settings must still render its tally, also
    for rows written before the column stored SQL NULL and holding the JSON value null instead."""
    await set_mode(db, "off")
    await run(db, agent, "df -h", sid="s1")
    await run(db, agent, "id", sid="s2")
    off_new, off_legacy = await requests(db)
    assert off_new.semantic is None
    await db.execute(text("UPDATE requests SET semantic = 'null' WHERE id = :id"), {"id": off_legacy.id})
    await db.commit()
    await set_mode(db, "shadow")
    typesafe.profile = "safe"
    await run(db, agent, "uptime", sid="s3")
    assert (await semantic.shadow_tally(db))["verdicts"] == 1
