"""What the router has seen and how far each message's job got. SQLite, one file on the data volume.

A job is the message's whole plan, rendered once: every call with its final arguments, and a
cursor. Rendering once matters: an approval covers one exact call, so a retry after the human
says yes must send the same arguments, including any text the model drafted.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Job:
    key: str
    email_id: str
    subject: str
    steps: list[dict[str, Any]]
    cursor: int = 0
    status: str = "running"  # running | pending | done | failed
    request_id: str | None = None
    note: str = ""
    created: float = field(default_factory=time.time)
    pending_since: float | None = None


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS jobs (
                key TEXT PRIMARY KEY, email_id TEXT, subject TEXT, steps TEXT, cursor INTEGER,
                status TEXT, request_id TEXT, note TEXT, created REAL, pending_since REAL, updated REAL);
            CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
        """)
        self.db.commit()

    def get_meta(self, k: str) -> str | None:
        row = self.db.execute("SELECT v FROM meta WHERE k = ?", (k,)).fetchone()
        return row[0] if row else None

    def set_meta(self, k: str, v: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)", (k, v))
        self.db.commit()

    def has(self, key: str) -> bool:
        return self.db.execute("SELECT 1 FROM jobs WHERE key = ?", (key,)).fetchone() is not None

    def save(self, job: Job) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (job.key, job.email_id, job.subject, json.dumps(job.steps), job.cursor, job.status, job.request_id,
             job.note, job.created, job.pending_since, time.time()))
        self.db.commit()

    def open_jobs(self) -> list[Job]:
        rows = self.db.execute(
            "SELECT key, email_id, subject, steps, cursor, status, request_id, note, created, pending_since "
            "FROM jobs WHERE status IN ('running', 'pending') ORDER BY created").fetchall()
        return [Job(key=r[0], email_id=r[1], subject=r[2], steps=json.loads(r[3]), cursor=r[4], status=r[5],
                    request_id=r[6], note=r[7], created=r[8], pending_since=r[9]) for r in rows]
