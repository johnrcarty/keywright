"""Boolean routing over one message, and the `{{field}}` templates actions are written in.

Conditions are mappings. Several keys in one mapping must all hold; `all`, `any` and `not`
nest. Address tests are globs on the bare address, case-insensitive (`*@example.com`);
`subject`/`body` are case-insensitive substrings; `*_matches` are regular expressions.
`label` asks the model, once per message and only when a rule actually reaches that test.

A sender address is what the message claims. Mail from a domain with a strict DMARC reject
policy is hard to forge past the provider, mail from elsewhere is
not, so a rule on `from` decides what the router tries, and Keywright still decides what
it may do.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from email.utils import getaddresses, parseaddr
from typing import Any

from .config import PLACEHOLDER


@dataclass
class Message:
    email_id: str
    message_id: str | None
    sender: str
    recipients: list[str]
    subject: str
    date: str
    body: str
    attachments: list[str] = field(default_factory=list)
    references: str | None = None

    @property
    def sender_address(self) -> str:
        return parseaddr(self.sender)[1].lower()

    @property
    def recipient_addresses(self) -> list[str]:
        return [a.lower() for _, a in getaddresses(self.recipients) if a]

    @property
    def key(self) -> str:
        """Stable across folders; the UID alone changes when the message moves."""
        return self.message_id or f"uid:{self.email_id}"


Labeler = Callable[[], Awaitable[str]]


async def matches(cond: dict[str, Any], msg: Message, label: Labeler) -> bool:
    for key, value in cond.items():
        if not await _test(key, value, msg, label):
            return False
    return True


async def _test(key: str, value: Any, msg: Message, label: Labeler) -> bool:
    if key == "all":
        for c in value:
            if not await matches(c, msg, label):
                return False
        return True
    if key == "any":
        for c in value:
            if await matches(c, msg, label):
                return True
        return False
    if key == "not":
        return not await matches(value, msg, label)
    if key == "from":
        return glob_any([msg.sender_address], value)
    if key == "to":
        return glob_any(msg.recipient_addresses, value)
    if key == "subject":
        return _contains(msg.subject, value)
    if key == "body":
        return _contains(msg.body, value)
    if key == "subject_matches":
        return re.search(str(value), msg.subject or "") is not None
    if key == "body_matches":
        return re.search(str(value), msg.body or "") is not None
    if key == "has_attachment":
        return bool(msg.attachments) == bool(value)
    if key == "label":
        wanted = value if isinstance(value, list) else [value]
        return await label() in wanted
    raise ValueError(f"unknown condition {key}")  # config validation makes this unreachable


def glob_any(addresses: list[str], patterns: Any) -> bool:
    pats = [p.lower() for p in (patterns if isinstance(patterns, list) else [patterns])]
    return any(fnmatch.fnmatchcase(a, p) for a in addresses for p in pats)


def _contains(text: str, needles: Any) -> bool:
    hay = (text or "").lower()
    return any(str(n).lower() in hay for n in (needles if isinstance(needles, list) else [needles]))


def placeholders(template: Any) -> set[str]:
    if isinstance(template, str):
        return set(PLACEHOLDER.findall(template))
    if isinstance(template, dict):
        return set().union(*(placeholders(v) for v in template.values())) if template else set()
    if isinstance(template, list):
        return set().union(*(placeholders(v) for v in template)) if template else set()
    return set()


def render(template: Any, fields: dict[str, str]) -> Any:
    """Fill `{{field}}` placeholders in every string of a template. One pass: text that came from
    the message is inserted, never re-scanned, so a subject of `{{body}}` stays literal."""
    if isinstance(template, str):
        return PLACEHOLDER.sub(lambda m: fields.get(m.group(1), ""), template)
    if isinstance(template, dict):
        return {k: render(v, fields) for k, v in template.items()}
    if isinstance(template, list):
        return [render(v, fields) for v in template]
    return template
