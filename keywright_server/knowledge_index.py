"""Replaceable retrieval indexes. Index hits are IDs, never authoritative document content.

The gateway rechecks collection, publication, expiry and version before returning any hit.
PostgreSQL is an optional, disposable index, independent of Keywright's broker database.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from time import perf_counter
from typing import Protocol

import httpx
from sqlalchemy import text

from .config import env

# Grammatical words otherwise dominate OR-based question retrieval after sections get smaller.
# Keep negation and domain terms. If a query consists only of these words, search it literally.
QUESTION_WORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "been", "but", "by", "can", "could", "did",
    "do", "does", "for", "from", "had", "has", "have", "how", "i", "if", "in", "into", "is",
    "it", "its", "may", "me", "my", "of", "on", "or", "our", "should", "than", "that", "the",
    "their", "them", "then", "there", "these", "they", "this", "those", "to", "was", "we",
    "were", "what", "when", "where", "which", "who", "why", "will", "with", "would", "you", "your",
})


def search_terms(query):
    words = re.findall(r"\w+", query, flags=re.UNICODE)
    meaningful = [word for word in words if word.casefold() not in QUESTION_WORDS]
    return (meaningful or words)[:32]


def init_local(conn):
    if conn.dialect.name != "sqlite":
        return
    conn.execute(text("""CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
        id UNINDEXED, resource_id UNINDEXED, title, body, tokenize='unicode61')"""))
    for action, suffix, statement in (
        ("INSERT", "insert", "INSERT INTO knowledge_fts VALUES (new.id, new.resource_id, new.title, new.body);"),
        ("DELETE", "delete", "DELETE FROM knowledge_fts WHERE id=old.id;"),
    ):
        conn.execute(text(f"CREATE TRIGGER IF NOT EXISTS knowledge_fts_{suffix} AFTER {action} "
                          f"ON knowledge_chunks BEGIN {statement} END"))


class RetrievalBackend(Protocol):
    async def search(self, collection: str, query: str, limit: int,
                     *, current_ids: list[str] | None = None) -> IndexSearch: ...
    async def replace(self, collection: str, chunks: list[dict]) -> None: ...


async def local_search(db, collection, query, limit=100, *, path_prefix=None):
    words = search_terms(query)
    if not words:
        return []
    if db.bind.dialect.name == "sqlite":
        result = await db.execute(text("""SELECT knowledge_fts.id FROM knowledge_fts
            JOIN knowledge_chunks c ON c.id=knowledge_fts.id
            JOIN knowledge_revisions r ON r.id=c.revision_id
            JOIN knowledge_documents d ON d.current_revision=r.id AND d.id=r.document_id
            WHERE knowledge_fts MATCH :query AND knowledge_fts.resource_id=:collection
              AND d.resource_id=:collection AND r.status='published'
              AND (CAST(:path_prefix AS TEXT) IS NULL OR substr(d.path, 1, length(:path_prefix))=:path_prefix)
              AND (r.expires_at IS NULL OR julianday(r.expires_at)>julianday('now'))
            ORDER BY bm25(knowledge_fts, 0, 0, 4, 1), knowledge_fts.id LIMIT :limit"""),
            {"query": " OR ".join('"' + w + '"' for w in words), "collection": collection,
             "limit": limit, "path_prefix": path_prefix})
    else:
        result = await db.execute(text("""SELECT c.id FROM knowledge_chunks c
            JOIN knowledge_revisions r ON r.id=c.revision_id
            JOIN knowledge_documents d ON d.current_revision=r.id AND d.id=r.document_id
            WHERE c.resource_id=:collection AND d.resource_id=:collection AND r.status='published'
              AND (CAST(:path_prefix AS TEXT) IS NULL OR substr(d.path, 1, length(:path_prefix))=:path_prefix)
              AND (r.expires_at IS NULL OR r.expires_at>CURRENT_TIMESTAMP)
              AND to_tsvector('simple', c.title || ' ' || c.body) @@ plainto_tsquery('simple', :query)
            ORDER BY ts_rank(to_tsvector('simple', c.title || ' ' || c.body),
                             plainto_tsquery('simple', :query)) DESC, c.id LIMIT :limit"""),
            {"query": " ".join(words), "collection": collection, "limit": limit, "path_prefix": path_prefix})
    return list(result.scalars())


def fusion_scores(*rankings):
    scores = {}
    for ranking in rankings:
        for rank, key in enumerate(dict.fromkeys(ranking), 1):
            scores[key] = scores.get(key, 0) + 1 / (60 + rank)
    return scores


def fuse(*rankings):
    scores = fusion_scores(*rankings)
    return sorted(scores, key=lambda key: (-scores[key], key))


@dataclass
class IndexSearch:
    """Untrusted retrieval signals; only the registry can establish visibility/freshness."""

    lexical: list[str] = field(default_factory=list)
    semantic: list[str] = field(default_factory=list)
    indexed_chunks: int = 0
    model_matches: int = 0
    compatible_chunks: int = 0
    lexical_scores: dict[str, float] = field(default_factory=dict)
    vector_distances: dict[str, float] = field(default_factory=dict)
    timings_ms: dict[str, float] = field(default_factory=dict)

    @property
    def ids(self):
        return fuse(self.lexical, self.semantic)


def elapsed_ms(start):
    return round((perf_counter() - start) * 1000, 3)


class IndexUnavailable(Exception):
    pass


class PgVectorBackend:
    def __init__(self):
        self.dsn = env("KNOWLEDGE_PG_URL", "")
        self.url = env("KNOWLEDGE_EMBEDDING_URL", "").rstrip("/")
        self.key = env("KNOWLEDGE_EMBEDDING_KEY", "")
        self.model = env("KNOWLEDGE_EMBEDDING_MODEL", "")
        # Changing a model/endpoint invalidates old vectors even when dimensions match.
        self.fingerprint = hashlib.sha256((self.url + "\n" + self.model).encode()).hexdigest()

    @asynccontextmanager
    async def connection(self):
        try:
            import asyncpg
            conn = await asyncpg.connect(self.dsn, timeout=10, command_timeout=30)
            try:
                yield conn
            finally:
                await conn.close()
        except Exception:  # noqa: BLE001 - never expose driver errors containing connection credentials
            # Driver errors and HTTP bodies can contain credentials or document content.
            raise IndexUnavailable("Knowledge index unavailable; check server configuration and connectivity.") from None

    async def embeddings(self, texts):
        if not self.url or not self.key or not self.model:
            raise IndexUnavailable("Configure a LiteLLM embedding endpoint, model and scoped API key.")
        try:
            async with httpx.AsyncClient(timeout=45, follow_redirects=False, trust_env=False) as client:
                response = await client.post(self.url + "/embeddings",
                    headers={"Authorization": "Bearer " + self.key},
                    json={"model": self.model, "input": texts, "encoding_format": "float"})
                response.raise_for_status()
                rows = sorted(response.json()["data"], key=lambda r: r["index"])
            if [r["index"] for r in rows] != list(range(len(texts))):
                raise ValueError("Missing embedding")
            vectors = [r["embedding"] for r in rows]
            dimension = len(vectors[0])
            if not 1 <= dimension <= 16000:
                raise ValueError("Invalid dimension")
            for vector in vectors:
                if len(vector) != dimension or any(type(x) not in (int, float) or not math.isfinite(x) for x in vector):
                    raise ValueError("Invalid vector")
                if not any(vector):
                    raise ValueError("Zero vector")
            return vectors
        except (httpx.HTTPError, KeyError, TypeError, ValueError, IndexError):
            raise IndexUnavailable("Embedding request failed; check the configured LiteLLM model and key.") from None

    async def replace(self, collection, chunks):
        vectors = []
        for start in range(0, len(chunks), 32):
            vectors.extend(await self.embeddings([c["title"] + "\n" + c["body"] for c in chunks[start:start + 32]]))
        if vectors and any(len(v) != len(vectors[0]) for v in vectors):
            raise IndexUnavailable("Embedding dimensions changed during indexing.")
        async with self.connection() as conn, conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock(hashtext($1))", collection)
            await conn.execute("DELETE FROM knowledge_search_chunks WHERE collection=$1", collection)
            await conn.executemany("""INSERT INTO knowledge_search_chunks
                    (id, collection, model, title, body, embedding) VALUES ($1,$2,$3,$4,$5,$6::vector)""",
                [(c["id"], collection, self.fingerprint, c["title"], c["body"], json.dumps(v))
                 for c, v in zip(chunks, vectors, strict=True)])

    async def search(self, collection, query, limit=100, *, current_ids=None):
        started = stage = perf_counter()
        vector = (await self.embeddings([query]))[0]
        timings = {"embedding": elapsed_ms(stage)}
        stage = perf_counter()
        async with self.connection() as conn:
            timings["index_connect"] = elapsed_ms(stage)
            # Coverage and rankings must describe the same index, even during an atomic rebuild.
            async with conn.transaction(isolation="repeatable_read", readonly=True):
                stage = perf_counter()
                coverage = await conn.fetchrow("""SELECT count(*) AS indexed,
                    count(*) FILTER (WHERE model=$3) AS model_matches,
                    count(*) FILTER (WHERE model=$3 AND vector_dims(embedding)=$4) AS compatible
                    FROM knowledge_search_chunks
                    WHERE collection=$1 AND ($2::text[] IS NULL OR id=ANY($2::text[]))""",
                    collection, current_ids, self.fingerprint, len(vector))
                timings["index_coverage"] = elapsed_ms(stage)
                stage = perf_counter()
                # Apply authoritative current scope before ranking/limit, including exact vector search.
                semantic = await conn.fetch("""SELECT id, embedding <=> $4::vector AS distance
                    FROM knowledge_search_chunks
                    WHERE collection=$1 AND model=$2 AND vector_dims(embedding)=$3
                      AND ($6::text[] IS NULL OR id=ANY($6::text[]))
                    ORDER BY embedding <=> $4::vector, id LIMIT $5""",
                    collection, self.fingerprint, len(vector), json.dumps(vector), limit, current_ids)
                timings["vector_search"] = elapsed_ms(stage)
                stage = perf_counter()
                lexical = await conn.fetch("""SELECT id, ts_rank(search, plainto_tsquery('simple', $2)) AS score
                    FROM knowledge_search_chunks
                    WHERE collection=$1 AND search @@ plainto_tsquery('simple', $2)
                      AND ($4::text[] IS NULL OR id=ANY($4::text[]))
                    ORDER BY ts_rank(search, plainto_tsquery('simple', $2)) DESC, id LIMIT $3""",
                    collection, query, limit, current_ids)
                timings["external_text_search"] = elapsed_ms(stage)
        timings["backend_total"] = elapsed_ms(started)
        return IndexSearch(
            lexical=[r["id"] for r in lexical], semantic=[r["id"] for r in semantic],
            indexed_chunks=coverage["indexed"], model_matches=coverage["model_matches"],
            compatible_chunks=coverage["compatible"],
            lexical_scores={r["id"]: float(r["score"]) for r in lexical},
            vector_distances={r["id"]: float(r["distance"]) for r in semantic}, timings_ms=timings,
        )


def backend() -> RetrievalBackend | None:
    return PgVectorBackend() if env("KNOWLEDGE_PG_URL") else None
