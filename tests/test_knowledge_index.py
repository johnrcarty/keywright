"""Embedding contract tests and opt-in real PostgreSQL/pgvector integration.

KNOWLEDGE_TEST_PG_URL must point at an isolated disposable test database.
"""
import json
import os
from pathlib import Path

import httpx
import pytest

from keywright_server import knowledge_index as idx


@pytest.fixture
def backend(monkeypatch):
    monkeypatch.setenv("KW_KNOWLEDGE_EMBEDDING_URL", "https://embeddings.test/v1")
    monkeypatch.setenv("KW_KNOWLEDGE_EMBEDDING_KEY", "scoped-test-key")
    monkeypatch.setenv("KW_KNOWLEDGE_EMBEDDING_MODEL", "knowledge-embedding")
    return idx.PgVectorBackend()


async def test_embeddings_restore_order_and_keep_credentials_server_side(backend, respx_mock):
    route = respx_mock.post("https://embeddings.test/v1/embeddings").respond(200, json={"data": [
        {"index": 1, "embedding": [0, 1]}, {"index": 0, "embedding": [1, 0]}]})
    assert await backend.embeddings(["first", "second"]) == [[1, 0], [0, 1]]
    request = route.calls.last.request
    assert request.headers["Authorization"] == "Bearer scoped-test-key"
    assert json.loads(request.content) == {"model": "knowledge-embedding", "input": ["first", "second"], "encoding_format": "float"}


@pytest.mark.parametrize("data", [[], [{"index": 1, "embedding": [1, 0]}],
    [{"index": 0, "embedding": [0, 0]}], [{"index": 0, "embedding": [True, 1]}],
    [{"index": 0, "embedding": ["private-token", 1]}], [{"index": 0, "embedding": []}]])
async def test_malformed_embeddings_fail_closed(backend, respx_mock, data):
    respx_mock.post("https://embeddings.test/v1/embeddings").respond(200, json={"data": data})
    with pytest.raises(idx.IndexUnavailable, match="Embedding request failed") as error:
        await backend.embeddings(["input"])
    assert "private-token" not in str(error.value)


async def test_http_errors_do_not_expose_provider_body(backend, respx_mock):
    respx_mock.post("https://embeddings.test/v1/embeddings").respond(403, text="scoped-test-key private document")
    with pytest.raises(idx.IndexUnavailable) as error:
        await backend.embeddings(["input"])
    assert "scoped-test-key" not in str(error.value) and "private document" not in str(error.value)


def test_reciprocal_rank_fusion_is_deterministic_and_deduplicates():
    assert idx.fuse(["a", "b", "b"], ["b", "c"]) == ["b", "a", "c"]


def test_question_terms_preserve_negation_identifiers_and_literal_only_queries():
    assert idx.search_terms("Does SHH not restore reader_pairing keys without approval?") == [
        "SHH", "not", "restore", "reader_pairing", "keys", "without", "approval"]
    assert idx.search_terms("to be or not to be") == ["not"]
    assert idx.search_terms("To Be") == ["To", "Be"]
    assert idx.search_terms("the " * 40 + "snapshot") == ["snapshot"]


@pytest.mark.skipif(not os.environ.get("KNOWLEDGE_TEST_PG_URL"), reason="Requires isolated pgvector database")
async def test_real_pgvector_hybrid_scope_replacement_and_model_change(backend, monkeypatch, respx_mock):
    import asyncpg

    backend.dsn = os.environ["KNOWLEDGE_TEST_PG_URL"]
    conn = await asyncpg.connect(backend.dsn)
    try:
        await conn.execute(Path("deploy/knowledge-schema.sql").read_text())
        await conn.execute("TRUNCATE knowledge_search_chunks")
    finally:
        await conn.close()
    def respond(request):
        inputs = json.loads(request.content)["input"]
        vectors = [[0, 1] if "finance" in text else [1, 0] for text in inputs]
        return httpx.Response(200, json={"data": [{"index": n, "embedding": v} for n, v in enumerate(vectors)]})
    respx_mock.post("https://embeddings.test/v1/embeddings").mock(side_effect=respond)
    await backend.replace("project-a", [
        {"id": "architecture", "title": "Storage", "body": "SQLite persistence decisions"},
        {"id": "billing", "title": "Costs", "body": "finance budgets"}])
    await backend.replace("project-b", [{"id": "private", "title": "Private SQLite", "body": "Private SQLite secrets"}])
    ranked = (await backend.search("project-a", "SQLite", 10)).ids
    assert ranked[0] == "architecture" and set(ranked) == {"architecture", "billing"}
    # No word overlap: retrieval still finds the semantically matching vector.
    assert (await backend.search("project-a", "durable datastore", 10)).ids[0] == "architecture"
    assert (await backend.search("missing", "SQLite", 10)).ids == []
    current = await backend.search("project-a", "durable datastore", 10, current_ids=["architecture", "new-unindexed"])
    assert current.ids == ["architecture"]
    assert (current.indexed_chunks, current.model_matches, current.compatible_chunks) == (1, 1, 1)
    assert current.vector_distances["architecture"] == 0
    assert all(v >= 0 for v in current.timings_ms.values())
    assert (await backend.search("project-a", "SQLite", 10, current_ids=[])).ids == []
    assert (await backend.search("project-a", "SQLite", 10, current_ids=["private"])).ids == []
    # Failure before replacement preserves the last complete index.
    original = backend.embeddings
    async def fail(texts):
        raise idx.IndexUnavailable("unavailable")
    monkeypatch.setattr(backend, "embeddings", fail)
    with pytest.raises(idx.IndexUnavailable):
        await backend.replace("project-a", [{"id": "new", "title": "New", "body": "New"}])
    monkeypatch.setattr(backend, "embeddings", original)
    assert (await backend.search("project-a", "SQLite", 10)).ids[0] == "architecture"
    backend.fingerprint = "changed-model"
    assert (await backend.search("project-a", "durable datastore", 10)).ids == []
    assert (await backend.search("project-a", "SQLite", 10)).ids[0] == "architecture"  # full-text still valid
    mismatch = await backend.search("project-a", "SQLite", 10, current_ids=["architecture"])
    assert (mismatch.indexed_chunks, mismatch.model_matches, mismatch.compatible_chunks) == (1, 0, 0)
    await backend.replace("project-a", [{"id": "new", "title": "New", "body": "New persistence"}])
    assert (await backend.search("project-a", "datastore", 10)).ids == ["new"]
    assert (await backend.search("project-b", "SQLite", 10)).ids == ["private"]
    await backend.replace("project-a", [])
    assert (await backend.search("project-a", "datastore", 10)).ids == []

    # Current-ID filtering happens before both candidate limits, not after top-k selection.
    chunks = [{"id": f"other-{n}", "title": "needle", "body": "needle"} for n in range(105)]
    chunks.append({"id": "target", "title": "Target", "body": "finance needle"})
    await backend.replace("scope-eval", chunks)
    scoped = await backend.search("scope-eval", "needle", 1, current_ids=["target"])
    assert scoped.semantic == scoped.lexical == ["target"]
    assert scoped.compatible_chunks == 1

    async def changed_dimension(texts):
        return [[1, 0, 0] for _ in texts]
    monkeypatch.setattr(backend, "embeddings", changed_dimension)
    incompatible = await backend.search("scope-eval", "needle", 1, current_ids=["target"])
    assert incompatible.lexical == ["target"] and incompatible.semantic == []
    assert (incompatible.indexed_chunks, incompatible.model_matches, incompatible.compatible_chunks) == (1, 1, 0)


@pytest.mark.skipif(not os.environ.get("KNOWLEDGE_TEST_PG_URL"), reason="Requires isolated PostgreSQL database")
async def test_postgres_broker_text_search_applies_literal_prefix():
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from keywright_server import knowledge as k
    from keywright_server.db import _upgrade_knowledge_columns
    from keywright_server.models import Base

    url = os.environ["KNOWLEDGE_TEST_PG_URL"].replace("postgresql://", "postgresql+asyncpg://", 1)
    engine = create_async_engine(url)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
            # Exercise the additive upgrade against the pre-section schema in this disposable DB.
            await connection.execute(text("ALTER TABLE knowledge_chunks DROP COLUMN section_path"))
            await connection.run_sync(_upgrade_knowledge_columns)
            await connection.run_sync(_upgrade_knowledge_columns)
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            collection = await k.create_collection(db, "PostgresScopeEvaluation")
            for path in ("projects/a_b%/x.md", "projects/axbZ/x.md", "projects/A_b%/x.md"):
                rev = await k.propose(db, collection.id, path=path, title="Needle", body="needle")
                await k.review(db, rev.id, True)
            unscoped = await idx.local_search(db, collection.id, "needle")
            assert len(unscoped) == 3
            scoped = await idx.local_search(db, collection.id, "needle", path_prefix="projects/a_b%/")
            assert len(scoped) == 1
            assert await idx.local_search(db, collection.id, "needle", path_prefix="projects/missing/") == []
            await db.execute(text("UPDATE knowledge_chunks SET section_path=NULL WHERE resource_id=:rid"),
                             {"rid": collection.id})
            await k.lock_writes(db)
            rebuilt = await k.rechunk(db, collection.id)
            assert rebuilt["changed_documents"] == 3
            assert (await k.rechunk(db, collection.id))["changed_documents"] == 0
            # Session rollback leaves no fixture rows; the database itself is disposable.
    finally:
        await engine.dispose()
