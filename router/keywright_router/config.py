"""The rules file: where the mail is, which model labels it, and what to do when a rule matches.

Loaded once at start and validated completely, so a typo fails the container at boot instead
of on the first message that happens to reach that rule.

Recipients and tool names are literals. Message text reaches a call only through `{{field}}`
placeholders in free-text values (a subject, a body, a tool argument), never as an address or
a tool: a message cannot choose who hears about it or what runs.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

PREDICATES = {"from", "to", "subject", "subject_matches", "body", "body_matches", "has_attachment", "label"}
COMBINATORS = {"all", "any", "not"}
ACTIONS = {"reply", "send", "forward", "mcp", "attention", "move", "mark_read"}
FIELDS = {"from", "to", "subject", "date", "body", "label", "email_id", "rule"}
PLACEHOLDER = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")
ADDRESS = re.compile(r"^[^@\s<>{}]+@[^@\s<>{}]+\.[^@\s<>{}]+$")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    name: str
    when: Any
    do: list[dict[str, Any]]
    stop: bool = False


@dataclass(frozen=True)
class Config:
    kw_url: str
    kw_token: str
    session: str
    server: str
    account: str
    mailbox: str
    poll_seconds: int
    done_folder: str | None
    since: str | None
    gateway: str | None
    model: str | None
    labels: tuple[str, ...]
    max_body_chars: int
    rules: tuple[Rule, ...]
    unmatched: tuple[dict[str, Any], ...]
    state_path: Path
    pending_hours: float
    uses_llm: bool = field(default=False)


def load(path: str | os.PathLike[str], env: dict[str, str] | None = None) -> Config:
    env = dict(os.environ if env is None else env)
    try:
        raw = yaml.safe_load(Path(path).read_text()) or {}
    except (OSError, yaml.YAMLError) as e:
        raise ConfigError(f"{path}: {e}") from e
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected a mapping at the top level")
    kw = raw.get("keywright") or {}
    mail = raw.get("email") or {}
    llm = raw.get("llm") or {}

    token = env.get("KW_TOKEN", "")
    if not token:
        raise ConfigError("KW_TOKEN is not set; the router's Keywright token comes from the environment only")
    labels = tuple(str(x) for x in llm.get("labels") or [])
    if labels and "unclear" not in labels:
        labels = (*labels, "unclear")

    if mail.get("since"):
        try:
            datetime.fromisoformat(str(mail["since"]))
        except ValueError as e:
            raise ConfigError(f"email.since: {e} (use 2026-09-28 or 2026-09-28T09:00:00+00:00)") from e
    rules = tuple(_rule(i, r, labels) for i, r in enumerate(raw.get("rules") or []))
    names = [r.name for r in rules]
    if len(set(names)) != len(names):
        raise ConfigError("rule names must be unique")
    unmatched = tuple(_action("unmatched", i, a) for i, a in enumerate(raw.get("unmatched") or []))

    drafts = any(isinstance(spec, dict) and "llm" in spec
                 for a in [*(a for r in rules for a in r.do), *unmatched] for spec in a.values())
    uses_llm = drafts or any(_mentions_label(r.when) for r in rules)
    gateway, model = llm.get("gateway"), llm.get("model")
    if uses_llm and not (gateway and model):
        raise ConfigError("a rule uses `label` or an `llm:` draft, so llm.gateway and llm.model are required")
    if any(_mentions_label(r.when) for r in rules) and not labels:
        raise ConfigError("a rule tests `label`, so llm.labels must list the labels the model may choose")

    return Config(
        kw_url=env.get("KW_URL") or kw.get("url") or "http://keywright:8700",
        kw_token=token,
        session=str(kw.get("session") or "keywright-router"),
        server=str(mail.get("server") or "email"),
        account=_required(mail, "account", "email"),
        mailbox=str(mail.get("mailbox") or "INBOX"),
        poll_seconds=max(15, int(mail.get("poll_seconds") or 60)),
        done_folder=mail.get("done_folder") or None,
        since=str(mail["since"]) if mail.get("since") else None,
        gateway=gateway,
        model=model,
        labels=labels,
        max_body_chars=int(llm.get("max_body_chars") or 6000),
        rules=rules,
        unmatched=unmatched,
        state_path=Path(env.get("ROUTER_STATE") or raw.get("state") or "/data/router.db"),
        pending_hours=float(raw.get("pending_hours") or 6),
        uses_llm=uses_llm,
    )


def _required(section: dict, key: str, where: str) -> str:
    value = section.get(key)
    if not value:
        raise ConfigError(f"{where}.{key} is required")
    return str(value)


def _rule(i: int, raw: Any, labels: tuple[str, ...]) -> Rule:
    if not isinstance(raw, dict) or not raw.get("name"):
        raise ConfigError(f"rules[{i}]: each rule needs a name")
    name = str(raw["name"])
    if "when" not in raw:
        raise ConfigError(f"rule {name}: `when` is required (`when: {{all: []}}` matches every message)")
    _condition(name, raw["when"], labels)
    do = raw.get("do") or []
    if not isinstance(do, list) or not do:
        raise ConfigError(f"rule {name}: `do` must be a non-empty list of actions")
    return Rule(name=name, when=raw["when"], do=[_action(name, j, a) for j, a in enumerate(do)],
                stop=bool(raw.get("stop", False)))


def _condition(rule: str, cond: Any, labels: tuple[str, ...]) -> None:
    if not isinstance(cond, dict) or not cond:
        raise ConfigError(f"rule {rule}: a condition is a non-empty mapping, got {cond!r}")
    for key, value in cond.items():
        if key in ("all", "any"):
            if not isinstance(value, list):
                raise ConfigError(f"rule {rule}: `{key}` takes a list of conditions")
            for c in value:
                _condition(rule, c, labels)
        elif key == "not":
            _condition(rule, value, labels)
        elif key in ("subject_matches", "body_matches"):
            try:
                re.compile(str(value))
            except re.error as e:
                raise ConfigError(f"rule {rule}: bad regex in {key}: {e}") from e
        elif key == "has_attachment":
            if not isinstance(value, bool):
                raise ConfigError(f"rule {rule}: has_attachment is true or false")
        elif key == "label":
            wanted = value if isinstance(value, list) else [value]
            unknown = [w for w in wanted if w not in labels]
            if unknown:
                raise ConfigError(f"rule {rule}: label {unknown} is not in llm.labels {list(labels)}")
        elif key not in PREDICATES:
            raise ConfigError(f"rule {rule}: unknown condition `{key}` "
                              f"(known: {sorted(PREDICATES | COMBINATORS)})")


def _mentions_label(cond: Any) -> bool:
    if not isinstance(cond, dict):
        return False
    for key, value in cond.items():
        if key == "label":
            return True
        if key in ("all", "any") and any(_mentions_label(c) for c in value):
            return True
        if key == "not" and _mentions_label(value):
            return True
    return False


def _action(rule: str, j: int, raw: Any) -> dict[str, Any]:
    where = f"rule {rule} action {j}"
    if not isinstance(raw, dict) or len(raw) != 1:
        raise ConfigError(f"{where}: an action is a one-key mapping such as `reply: {{text: ...}}`")
    kind, spec = next(iter(raw.items()))
    if kind not in ACTIONS:
        raise ConfigError(f"{where}: unknown action `{kind}` (known: {sorted(ACTIONS)})")
    if kind in ("reply", "send", "forward"):
        if not isinstance(spec, dict):
            raise ConfigError(f"{where}: `{kind}` takes a mapping")
        if kind in ("send", "forward"):
            to = spec.get("to")
            to = [to] if isinstance(to, str) else to
            if not to or not all(isinstance(a, str) and ADDRESS.match(a) for a in to):
                raise ConfigError(f"{where}: `{kind}.to` must be one or more literal addresses; "
                                  "a recipient never comes from the message")
            spec = {**spec, "to": list(to)}
        if kind == "send" and not spec.get("subject"):
            raise ConfigError(f"{where}: `send.subject` is required")
        if kind in ("reply", "send") and ("text" in spec) == ("llm" in spec):
            raise ConfigError(f"{where}: `{kind}` needs exactly one of `text` (a template) or `llm` (an instruction)")
        _templates(where, spec, skip={"to"})
    elif kind == "mcp":
        if not isinstance(spec, dict) or not isinstance(spec.get("tool"), str) or "__" not in spec["tool"]:
            raise ConfigError(f"{where}: `mcp.tool` is the brokered name, <server>__<tool>")
        if PLACEHOLDER.search(spec["tool"]):
            raise ConfigError(f"{where}: `mcp.tool` must be literal")
        if not isinstance(spec.get("args", {}), dict):
            raise ConfigError(f"{where}: `mcp.args` is a mapping")
        _templates(where, spec.get("args", {}))
    elif kind == "attention":
        if not isinstance(spec, str) or not spec:
            raise ConfigError(f"{where}: `attention` is the message template")
        _templates(where, {"attention": spec})
    elif kind == "move":
        if not isinstance(spec, str) or not spec or PLACEHOLDER.search(spec):
            raise ConfigError(f"{where}: `move` takes a literal folder name")
    elif kind == "mark_read":
        spec = True
    return {kind: spec}


def _templates(where: str, spec: Any, skip: set[str] = frozenset()) -> None:
    if isinstance(spec, dict):
        for k, v in spec.items():
            if k not in skip:
                _templates(where, v)
    elif isinstance(spec, list):
        for v in spec:
            _templates(where, v)
    elif isinstance(spec, str):
        for name in PLACEHOLDER.findall(spec):
            if name not in FIELDS:
                raise ConfigError(f"{where}: unknown placeholder {{{{{name}}}}} (known: {sorted(FIELDS)})")
