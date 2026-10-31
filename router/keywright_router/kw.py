"""The router's only way out: brokered MCP calls and the LLM gateway, both through Keywright.

Calls never wait on the human (`_wait_seconds: 0`, `X-Keywright-Wait: 0`). A call that needs
approval comes back as Pending with the request id; the router parks the job and asks
`access_status` about that id on later polls instead of repeating the call, so one message
puts one prompt on the phone however long it takes to answer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx
from keywright import transport
from keywright.config import Profile


class KwError(Exception):
    """The call was refused, denied, locked or failed; retrying the same call will not help."""

    def __init__(self, kind: str, detail: dict[str, Any] | None = None):
        self.kind = kind
        self.detail = detail or {}
        super().__init__(f"{kind}: {json.dumps(self.detail)[:300]}")


class Pending(Exception):
    """Waiting on the human; `request_id` is the one to poll."""

    def __init__(self, request_id: str, patterns: list[str] | None = None):
        self.request_id = request_id
        self.patterns = patterns or []
        super().__init__(f"approval pending: {request_id}")


@dataclass
class Keywright:
    url: str
    token: str
    session: str
    timeout: float = 120.0

    @property
    def profile(self) -> Profile:
        return Profile(name="router", url=self.url, token=self.token)

    async def call(self, tool: str, args: dict[str, Any], reason: str) -> dict[str, Any]:
        """One brokered tool call. Returns the structured payload; raises Pending or KwError."""
        result = await transport.acall(self.profile, self.session, tool,
                                       {**args, "_reason": reason, "_wait_seconds": 0},
                                       read_timeout=self.timeout)
        data = transport.payload(result)
        if getattr(result, "is_error", False):
            kind = data.get("error") if isinstance(data.get("error"), str) else "upstream_error"
            if kind == "approval_required" and data.get("request_id"):
                raise Pending(data["request_id"], data.get("patterns"))
            raise KwError(kind, data)
        return data

    async def call_access(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        """One of Keywright's own tools (access_list_resources, access_request): the payload as it
        comes, errors included, since their answers are states rather than failures."""
        result = await transport.acall(self.profile, self.session, tool, args, read_timeout=30.0)
        return transport.payload(result)

    async def status(self, request_id: str) -> str:
        """pending | approved | denied | expired | not_found."""
        result = await transport.acall(self.profile, self.session, "access_status", {"request_id": request_id},
                                       read_timeout=30.0)
        data = transport.payload(result)
        return str(data.get("status") or data.get("error") or "not_found")

    async def attention(self, message: str, context: str) -> None:
        await transport.acall(self.profile, self.session, "request_attention",
                              {"message": message[:500], "context": context[:200]}, read_timeout=30.0)

    async def chat(self, gateway: str, model: str, messages: list[dict[str, str]], reason: str,
                   max_tokens: int = 800) -> str:
        headers = {"Authorization": f"Bearer {self.token}", "X-Keywright-Session": self.session,
                   "X-Keywright-Wait": "0", "X-Keywright-Reason": reason[:200]}
        body = {"model": model, "messages": messages, "temperature": 0, "max_tokens": max_tokens}
        async with httpx.AsyncClient(timeout=self.timeout) as http:
            r = await http.post(f"{self.url.rstrip('/')}/llm/{gateway}/v1/chat/completions",
                                json=body, headers=headers)
        try:
            data = r.json()
        except ValueError:
            data = {}
        if r.status_code != 200:
            err = data.get("error") if isinstance(data.get("error"), dict) else {}
            if err.get("code") == "approval_required" and err.get("request_id"):
                raise Pending(err["request_id"], [f"llm/{gateway}/model/{model}"])
            raise KwError(str(err.get("code") or f"http_{r.status_code}"), {"message": err.get("message")})
        try:
            return str(data["choices"][0]["message"]["content"] or "")
        except (KeyError, IndexError, TypeError) as e:
            raise KwError("bad_llm_response", {"body": str(data)[:300]}) from e
