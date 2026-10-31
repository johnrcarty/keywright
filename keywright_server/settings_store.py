"""UI-editable settings kept in the `settings` table, with a tiny in-process cache."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from .models import Setting

_cache: dict[str, dict[str, Any]] = {}


async def get(db: AsyncSession, key: str, default: dict[str, Any] | None = None) -> dict[str, Any]:
    row = await db.get(Setting, key)
    val = dict(row.value) if row else dict(default or {})
    _cache[key] = val
    return val


async def put(db: AsyncSession, key: str, value: dict[str, Any]) -> None:
    row = await db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value
    await db.commit()
    _cache[key] = dict(value)


def cached(key: str) -> dict[str, Any] | None:
    return _cache.get(key)


def cached_public_url() -> str | None:
    g = _cache.get("general") or {}
    return g.get("public_url") or None


async def warm(db: AsyncSession) -> None:
    from sqlalchemy import select

    for row in (await db.execute(select(Setting))).scalars().all():
        _cache[row.key] = dict(row.value)
