from __future__ import annotations

from contextvars import ContextVar
from typing import Any

# Set per MCP call from the User-Agent header when it names a Keywright client; recorded on every
# audit row of that call. Kept out of the operation dict so exact-bound grants never see it.
client_agent: ContextVar[str | None] = ContextVar("client_agent", default=None)

from sqlalchemy.ext.asyncio import AsyncSession

from .models import Agent, AuditEvent


async def record(
    db: AsyncSession,
    *,
    tool: str,
    decision: str,
    agent: Agent | None = None,
    session_id: str | None = None,
    patterns: list[str] | None = None,
    detail: dict[str, Any] | None = None,
    exit_code: int | None = None,
    duration_ms: int | None = None,
    commit: bool = True,
) -> AuditEvent:
    ev = AuditEvent(
        agent_id=agent.id if agent else None,
        agent_name=agent.name if agent else "",
        session_id=session_id,
        tool=tool,
        patterns=list(patterns or []),
        decision=decision,
        detail=_scrub({**(detail or {}), **({"client": client_agent.get()} if client_agent.get() else {})}),
        exit_code=exit_code,
        duration_ms=duration_ms,
    )
    db.add(ev)
    if commit:
        await db.commit()
    return ev


def _scrub(value: Any) -> Any:
    """Redact nested credential fields before persistence, notifications, or display."""
    if isinstance(value, dict):
        return {
            k: "***" if any(s in k.lower() for s in (
                "token", "secret", "password", "authorization", "api_key", "apikey", "private_key", "credential",
            )) else _scrub(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, str) and len(value) > 4000:
        return value[:4000] + f"... [{len(value) - 4000} more]"
    return value
