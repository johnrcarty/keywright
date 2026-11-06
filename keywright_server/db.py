from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import event, inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from .config import settings
from .models import Base

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_async_engine(settings.db_url, future=True)
        if settings.db_url.startswith("sqlite"):

            @event.listens_for(_engine.sync_engine, "connect")
            def _pragmas(dbapi_conn, _record):  # pragma: no cover - trivial
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA foreign_keys=ON")
                cur.execute("PRAGMA busy_timeout=5000")
                cur.close()

    return _engine


def sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(engine(), expire_on_commit=False)
    return _sessionmaker


@asynccontextmanager
async def session() -> AsyncIterator[AsyncSession]:
    async with sessionmaker()() as s:
        yield s


async def init_db() -> None:
    settings.ensure_dirs()
    async with engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        from .tasks import seed
        await seed(conn)
        await conn.run_sync(_upgrade_knowledge_columns)
        await conn.run_sync(_upgrade_knowledge_graph_columns)
        from .knowledge_index import init_local
        await conn.run_sync(init_local)
        await conn.run_sync(_upgrade_access_columns)
        await conn.run_sync(_upgrade_discovery_columns)
        await conn.run_sync(_upgrade_repository_columns)
        await conn.run_sync(_relocate_key_paths)
        await conn.execute(text("SELECT 1"))
    if settings.db_url.startswith("sqlite") and settings.db_path.exists():
        settings.db_path.chmod(0o600)


def _upgrade_knowledge_columns(conn) -> None:
    # Add metadata capacity only. Existing published chunks require explicit admin migration.
    columns = {c["name"] for c in inspect(conn).get_columns("knowledge_chunks")}
    if "section_path" not in columns:
        conn.execute(text("ALTER TABLE knowledge_chunks ADD COLUMN section_path JSON"))


def _upgrade_knowledge_graph_columns(conn) -> None:
    """Track derived link coverage without modifying publication or source identity."""
    columns = {c["name"] for c in inspect(conn).get_columns("knowledge_revisions")}
    if "link_version" not in columns:
        conn.execute(text("ALTER TABLE knowledge_revisions ADD COLUMN link_version INTEGER"))


def _upgrade_access_columns(conn) -> None:
    """Add nullable access constraints without changing existing authorization semantics.

    Run startup migrations before starting additional workers against the same database.
    """
    for table, column in (("grants", "constraints"), ("policies", "constraints"),
                          ("requests", "decision_options"), ("policies", "request_id"),
                          ("requests", "semantic")):
        columns = {c["name"] for c in inspect(conn).get_columns(table)}
        if column not in columns:
            column_type = "VARCHAR" if column == "request_id" else "JSON"
            conn.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {column_type}'))


def _upgrade_discovery_columns(conn) -> None:
    columns = {c['name'] for c in inspect(conn).get_columns('inventory_discovery_runs')}
    if 'source_fingerprint' not in columns:
        conn.execute(text('ALTER TABLE inventory_discovery_runs ADD COLUMN source_fingerprint VARCHAR'))


def _relocate_key_paths(conn) -> None:
    """A resource stores its SSH key as an absolute path. When the data dir moves (the Gatekeeper
    rename left /var/lib/gatekeeper/keys/<name> behind, a container mounts the dir somewhere
    else), a stored path that no longer exists is pointed at the same file name in this
    instance's keys dir, if that exists. Never invents a key: paths outside keys_dir that still
    exist are the admin's and stay as they are."""
    import json
    import os

    rows = conn.execute(text("SELECT id, config FROM resources WHERE kind = 'ssh'")).fetchall()
    for rid, raw in rows:
        cfg = json.loads(raw) if isinstance(raw, str) else dict(raw or {})
        kp = cfg.get("key_path") or ""
        if not kp or os.path.exists(kp):
            continue
        candidate = settings.keys_dir / os.path.basename(kp)
        if candidate.exists():
            cfg["key_path"] = str(candidate)
            conn.execute(text("UPDATE resources SET config = :c WHERE id = :i"), {"c": json.dumps(cfg), "i": rid})


async def reset_for_tests(url: str) -> None:
    """Point the module at a fresh engine (tests only)."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = create_async_engine(url, future=True)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        from .tasks import seed
        await seed(conn)
        from .knowledge_index import init_local
        await conn.run_sync(init_local)


def _upgrade_repository_columns(conn) -> None:
    columns = {c['name'] for c in inspect(conn).get_columns('work_repositories')}
    for name, definition in {
        'sync_connection_id': 'VARCHAR REFERENCES work_github_connections(id)',
        'source_metadata': "JSON NOT NULL DEFAULT '{}'",
        'import_enabled': 'BOOLEAN NOT NULL DEFAULT FALSE',
        'include_closed': 'BOOLEAN NOT NULL DEFAULT FALSE',
        'poll_seconds': 'INTEGER NOT NULL DEFAULT 300',
        'last_refreshed_at': 'TIMESTAMP',
    }.items():
        if name not in columns:
            conn.execute(text(f'ALTER TABLE work_repositories ADD COLUMN {name} {definition}'))
