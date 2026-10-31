"""Knowledge authorization, publication, source integrity and retrieval acceptance tests."""
import asyncio
import hashlib
import json
import subprocess
from datetime import timedelta
from types import SimpleNamespace

import httpx
import mcp_types as types
import pytest
from sqlalchemy import delete, func, select, text

from keywright_server import audit, mcp_proxy
from keywright_server import knowledge as k
from keywright_server import knowledge_index as idx
from keywright_server.db import session
from keywright_server.mcp_server import _proxy_call, on_call_tool, on_list_tools
from keywright_server.models import Agent, AuditEvent, Policy, now


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch):
    for name in ("PG_URL", "EMBEDDING_URL", "EMBEDDING_KEY", "EMBEDDING_MODEL", "GIT_ROOT"):
        monkeypatch.delenv("KW_KNOWLEDGE_" + name, raising=False)


@pytest.fixture
async def collection(db):
    res = await k.create_collection(db, "ProjectKnowledge", "Project-specific knowledge")
    await db.commit()
    return res


async def publish(db, res, body="# Storage\nUse SQLite for broker state.\n", **kwargs):
    rev = await k.propose(db, res.id, path=kwargs.pop("path", "architecture.md"),
                          title=kwargs.pop("title", "Storage architecture"), body=body,
                          kind=kwargs.pop("kind", "documentation"), **kwargs)
    await k.review(db, rev.id, True)
    await db.commit()
    return rev


async def legacy_chunks(db, res, rev):
    body = k.markdown(rev)
    await db.execute(delete(k.Chunk).where(k.Chunk.revision_id == rev.id))
    db.add(k.Chunk(id=f"{rev.id}:0", resource_id=res.id, revision_id=rev.id, ordinal=0,
                  line_start=1, line_end=len(body.splitlines()), title=rev.title, body=body, section_path=None))
    await db.commit()


async def call(agent, res, tool, arguments=None):
    async with session() as db:
        a = await db.get(Agent, agent.id)
        result = await _proxy_call(db, a, "knowledge-test", res.name, tool,
                                  {**(arguments or {}), "_wait_seconds": 0})
        return result.structured_content


async def allow(db, agent, res, *tools):
    for tool in tools:
        db.add(Policy(agent_id=agent.id, pattern=f"mcp/{res.name}/tools/{tool}", effect="allow"))
    await db.commit()


async def test_markdown_publication_provenance_search_and_list(db, collection):
    body = "# Why SQLite?\n\nKeep broker state separate from the retrieval index.\n"
    rev = await publish(db, collection, body, source="git:architecture.md", source_version="abc123")
    result = await k.search(db, collection.id, "retrieval")
    hit = result["results"][0]
    assert hit["text"] == body and hit["line_start"] == 1 and hit["line_end"] == 3
    assert hit["source_version"] == "abc123" and hit["revision"] == rev.id
    assert hit["sha256"] == hashlib.sha256(body.encode()).hexdigest()
    assert result["mode"] == "text" and hit["content_role"] == "reference_data"
    assert (await k.get_document(db, collection.id, rev.document_id))["markdown"] == body
    assert (await k.list_documents(db, collection.id))["documents"][0]["revision"] == rev.id
    assert k.blob_path(rev.sha256).read_text() == body
    assert k.blob_path(rev.sha256).stat().st_mode & 0o777 == 0o600


async def test_proposals_are_not_searchable_until_review(db, collection, agent):
    rev = await k.propose(db, collection.id, path="lessons.md", title="Lesson", body="Unreviewed specialsecret",
                          agent=agent, rationale="Learned during a session")
    await db.commit()
    assert not (await k.search(db, collection.id, "specialsecret"))["results"]
    assert not (await k.list_documents(db, collection.id))["documents"]
    with pytest.raises(k.KnowledgeError, match="not found"):
        await k.get_document(db, collection.id, rev.document_id)
    await k.review(db, rev.id, False)
    await db.commit()
    with pytest.raises(k.KnowledgeError, match="already"):
        await k.review(db, rev.id, True)
    assert rev.status == "rejected"


async def test_revisions_stale_proposals_and_archive(db, collection):
    first = await publish(db, collection, "oldneedle")
    proposal = await k.propose(db, collection.id, path="architecture.md", title="Proposed",
                               body="pendingneedle", expected_revision=first.id)
    second = await publish(db, collection, "newneedle", expected_revision=first.id)
    with pytest.raises(k.KnowledgeError, match="changed after"):
        await k.review(db, proposal.id, True)
    assert not (await k.search(db, collection.id, "oldneedle"))["results"]
    assert (await k.search(db, collection.id, "newneedle"))["results"][0]["revision"] == second.id
    assert k.markdown(first) == "oldneedle"
    assert await db.scalar(select(func.count()).select_from(k.Chunk)) == 1
    await k.archive(db, collection.id, second.document_id, second.id)
    await db.commit()
    assert not (await k.search(db, collection.id, "newneedle"))["results"]
    with pytest.raises(k.KnowledgeError):
        await k.get_document(db, collection.id, second.document_id)


async def test_operational_expiry_applies_to_search_get_and_list(db, collection):
    rev = await publish(db, collection, "temporaryneedle", kind="operational", retention_days=1)
    assert (await k.search(db, collection.id, "temporaryneedle"))["results"]
    rev.expires_at = now() - timedelta(seconds=1)
    await db.commit()
    assert not (await k.search(db, collection.id, "temporaryneedle"))["results"]
    assert not (await k.list_documents(db, collection.id))["documents"]
    with pytest.raises(k.KnowledgeError):
        await k.get_document(db, collection.id, rev.document_id)


async def test_foreign_stale_and_expired_backend_hits_never_return_content(db, collection, monkeypatch):
    other = await k.create_collection(db, "PrivateKnowledge")
    foreign = await publish(db, other, "foreignsecret")
    stale = await publish(db, collection, "stalesecret")
    current = await publish(db, collection, "currentcontent", expected_revision=stale.id)
    expired = await publish(db, collection, "expiredsecret", path="task.md", kind="operational")
    expired.expires_at = now() - timedelta(days=1)
    await db.commit()
    class UntrustedBackend:
        async def search(self, resource_id, query, limit, *, current_ids):
            assert resource_id == collection.id
            assert current_ids == [k.chunk_id(current.id, 0)]
            return idx.IndexSearch(semantic=[k.chunk_id(foreign.id, 0), k.chunk_id(stale.id, 0), k.chunk_id(expired.id, 0), k.chunk_id(current.id, 0)],
                                   indexed_chunks=1, model_matches=1, compatible_chunks=1)
    monkeypatch.setattr(idx, "backend", UntrustedBackend)
    result = await k.search(db, collection.id, "semantic synonym")
    assert [r["text"] for r in result["results"]] == ["currentcontent"]
    assert "secret" not in json.dumps(result)
    with pytest.raises(k.KnowledgeError):
        await k.get_document(db, collection.id, foreign.document_id)


async def test_backend_outage_falls_back_without_leaking_errors(db, collection, monkeypatch):
    await publish(db, collection, "localneedle")
    class BrokenBackend:
        async def search(self, *args, **kwargs):
            raise idx.IndexUnavailable("credential-secret")
    monkeypatch.setattr(idx, "backend", BrokenBackend)
    result = await k.search(db, collection.id, "localneedle")
    assert result["results"] and result["mode"] == "text"
    assert result["warning"] and "credential-secret" not in json.dumps(result)


async def test_semantic_coverage_tracks_publication_and_rebuild(db, collection, monkeypatch):
    first = await publish(db, collection, "Automobile battery legacyprocedure", title="Automobiles")
    indexed = {k.chunk_id(first.id, 0)}

    class SnapshotBackend:
        async def search(self, resource_id, query, limit, *, current_ids):
            present = sorted(indexed & set(current_ids))
            return idx.IndexSearch(semantic=present, indexed_chunks=len(present),
                                   model_matches=len(present), compatible_chunks=len(present))

    monkeypatch.setattr(idx, "backend", SnapshotBackend)
    before = await k.search(db, collection.id, "vehicle energy storage", diagnostics=True)
    assert before["index_status"] == "current" and before["mode"] == "hybrid"
    assert before["results"][0]["retrieval"]["vector_rank"] == 1
    assert before["results"][0]["retrieval"]["local_text_rank"] is None
    current = await publish(db, collection, "Automobile battery revisedprocedure", title="Automobiles", expected_revision=first.id)
    stale = await k.search(db, collection.id, "vehicle energy storage", diagnostics=True)
    assert stale["index_status"] == "missing" and stale["mode"] == "text"
    assert not stale["results"] and stale["warning"]
    assert stale["diagnostics"]["index"]["missing_current_chunks"] == 1
    literal = await k.search(db, collection.id, "revisedprocedure")
    assert literal["results"][0]["revision"] == current.id
    assert "diagnostics" not in literal and "retrieval" not in literal["results"][0]
    indexed.add(k.chunk_id(current.id, 0))
    rebuilt = await k.search(db, collection.id, "vehicle energy storage")
    assert rebuilt["index_status"] == "current" and not rebuilt["warning"]
    assert rebuilt["results"][0]["revision"] == current.id
    await publish(db, collection, "Unindexed extra document", path="second.md")
    partial = await k.search(db, collection.id, "vehicle energy storage", diagnostics=True)
    assert partial["index_status"] == "partial" and partial["mode"] == "hybrid" and partial["warning"]
    assert partial["diagnostics"]["index"]["current_chunks"] == 2
    assert partial["diagnostics"]["index"]["compatible_current_chunks"] == 1


@pytest.mark.parametrize("model_matches,reason", [(0, "model_mismatched_current_chunks"),
                                               (1, "dimension_mismatched_current_chunks")])
async def test_incompatible_vectors_preserve_text_and_explain_coverage(db, collection, monkeypatch, model_matches, reason):
    rev = await publish(db, collection, "literalneedle")

    class IncompatibleBackend:
        async def search(self, *args, **kwargs):
            return idx.IndexSearch(lexical=[k.chunk_id(rev.id, 0)], indexed_chunks=1, model_matches=model_matches)

    monkeypatch.setattr(idx, "backend", IncompatibleBackend)
    result = await k.search(db, collection.id, "literalneedle", diagnostics=True)
    assert result["index_status"] == "incompatible" and result["mode"] == "text" and result["warning"]
    assert result["diagnostics"]["index"][reason] == 1
    assert result["results"][0]["text"] == "literalneedle"


async def test_empty_scope_avoids_backend_and_unknown_coverage_is_not_zero(db, collection, monkeypatch):
    class BrokenBackend:
        async def search(self, *args, **kwargs):
            raise idx.IndexUnavailable("provider-secret")

    await publish(db, collection, "literalneedle", path="projects/other/overview.md")
    disabled = await k.search(db, collection.id, "literalneedle", diagnostics=True)
    assert disabled["index_status"] == "disabled"
    assert disabled["diagnostics"]["index"]["compatible_current_chunks"] is None
    monkeypatch.setattr(idx, "backend", BrokenBackend)
    empty = await k.search(db, collection.id, "literalneedle", path_prefix="projects/example/", diagnostics=True)
    assert empty["index_status"] == "empty" and not empty["warning"] and not empty["results"]
    outage = await k.search(db, collection.id, "literalneedle", diagnostics=True)
    assert outage["index_status"] == "unavailable" and outage["warning"]
    assert outage["diagnostics"]["index"]["compatible_current_chunks"] is None
    assert "provider-secret" not in json.dumps(outage)


async def test_path_scope_precedes_local_candidate_limit_and_rechecks_backend_ids(db, collection, monkeypatch):
    for n in range(105):
        await publish(db, collection, "needle", title="needle", path=f"projects/other/{n}.md")
    target = await publish(db, collection, "needle " + "background " * 100, path="projects/example/overview.md")
    unscoped = await k.search(db, collection.id, "needle", 5)
    assert all(h["revision"] != target.id for h in unscoped["results"])
    scoped = await k.search(db, collection.id, "needle", 5, path_prefix="projects/example/")
    assert [h["revision"] for h in scoped["results"]] == [target.id]
    foreign = await publish(db, collection, "foreignsecret", path="projects/other/secret.md")

    class MaliciousBackend:
        async def search(self, resource_id, query, limit, *, current_ids):
            assert current_ids == [k.chunk_id(target.id, 0)]
            return idx.IndexSearch(semantic=[k.chunk_id(foreign.id, 0), k.chunk_id(target.id, 0)],
                                   indexed_chunks=1, model_matches=1, compatible_chunks=1)

    monkeypatch.setattr(idx, "backend", MaliciousBackend)
    result = await k.search(db, collection.id, "needle", path_prefix="projects/example/", diagnostics=True)
    assert [h["revision"] for h in result["results"]] == [target.id]
    assert result["diagnostics"]["candidates"]["rejected"] == 1
    assert "foreignsecret" not in json.dumps(result) and foreign.id not in json.dumps(result)


async def test_path_prefix_is_literal_and_case_sensitive(db, collection):
    for path in ("projects/a_b%/x.md", "projects/axbZ/x.md", "projects/A_b%/x.md"):
        await publish(db, collection, "needle", path=path)
    result = await k.search(db, collection.id, "needle", path_prefix="projects/a_b%/")
    assert [h["path"] for h in result["results"]] == ["projects/a_b%/x.md"]


@pytest.mark.parametrize("prefix", ["", "/projects/", "../", "projects/../", "projects//", "./projects/",
                                  "projects\\example", "projects/\x00", ".", "projects/\x7f"])
def test_invalid_search_prefix(prefix):
    with pytest.raises(k.KnowledgeError):
        k.valid_path_prefix(prefix)


async def test_search_revalidates_expiry_after_slow_backend(db, collection, monkeypatch):
    rev = await publish(db, collection, "needle", kind="operational")

    class SlowBackend:
        async def search(self, *args, **kwargs):
            monkeypatch.setattr(k, "now", lambda: rev.expires_at + timedelta(seconds=1))
            return idx.IndexSearch(semantic=[k.chunk_id(rev.id, 0)], indexed_chunks=1, model_matches=1, compatible_chunks=1)

    monkeypatch.setattr(idx, "backend", SlowBackend)
    result = await k.search(db, collection.id, "needle", diagnostics=True)
    assert result["results"] == [] and result["mode"] == "text"
    assert result["diagnostics"]["candidates"]["rejected"] == 1


async def test_mcp_search_exposes_scope_and_diagnostics_with_existing_read_permission(db, collection, agent):
    await publish(db, collection, "needle", path="projects/example/x.md")
    await publish(db, collection, "needle", path="projects/other/x.md")
    await allow(db, agent, collection, "knowledge_search")
    result = await call(agent, collection, "knowledge_search",
                        {"query": "needle", "path_prefix": "projects/example/", "diagnostics": True})
    assert [h["path"] for h in result["results"]] == ["projects/example/x.md"]
    assert result["diagnostics"]["index"]["current_chunks"] == 1


async def test_mcp_auth_policy_isolation_and_revocation(db, collection, agent):
    rev = await publish(db, collection)
    assert (await call(agent, collection, "knowledge_list"))["error"] == "locked"
    await allow(db, agent, collection, "knowledge_list", "knowledge_get", "knowledge_search")
    assert (await call(agent, collection, "knowledge_list"))["documents"]
    assert (await call(agent, collection, "knowledge_get", {"document_id": rev.document_id}))["markdown"]
    other = await k.create_collection(db, "OtherKnowledge")
    private = await publish(db, other, "Private decision")
    assert (await call(agent, other, "knowledge_list"))["error"] == "locked"
    assert (await call(agent, collection, "knowledge_get", {"document_id": private.document_id}))["error"] == "knowledge_conflict"
    ctx = SimpleNamespace(request=SimpleNamespace(headers={"authorization": "Bearer gk_testtoken"}))
    names = {t.name for t in (await on_list_tools(ctx, None)).tools}
    assert "ProjectKnowledge__knowledge_search" in names
    assert not any(n.startswith("OtherKnowledge__") for n in names)
    discovery = await on_call_tool(ctx, types.CallToolRequestParams(name="access_list_resources", arguments={}))
    assert [r["resource"] for r in discovery.structured_content["resources"]] == ["mcp/ProjectKnowledge"]
    db.add(Policy(agent_id=agent.id, pattern="mcp/ProjectKnowledge/**", effect="deny"))
    await db.commit()
    assert (await call(agent, collection, "knowledge_search", {"query": "SQLite"}))["error"] == "denied"
    ctx = SimpleNamespace(request=SimpleNamespace(headers={}))
    result = await on_call_tool(ctx, types.CallToolRequestParams(name="ProjectKnowledge__knowledge_list", arguments={}))
    assert result.structured_content["error"] == "unauthorized"


async def test_mcp_proposal_attribution_and_no_promotion(db, collection, agent):
    await allow(db, agent, collection, "knowledge_propose", "knowledge_search")
    args = {"path": "lessons.md", "title": "Lesson", "body": "Use transactions", "rationale": "Session discovery"}
    result = await call(agent, collection, "knowledge_propose", args)
    assert result["status"] == "pending"
    rev = await db.get(k.Revision, result["proposal_id"])
    assert rev.proposed_by == agent.id and rev.attribution == "agent:" + agent.id
    assert not (await call(agent, collection, "knowledge_search", {"query": "transactions"}))["results"]
    assert (await call(agent, collection, "knowledge_approve", {"id": rev.id}))["error"] == "invalid_arguments"
    event = await db.scalar(select(AuditEvent).where(AuditEvent.detail["tool"].as_string() == "knowledge_propose"))
    assert event.agent_id == agent.id and event.decision == "allow"


@pytest.mark.parametrize("tool,args", [
    ("knowledge_search", {"query": "x", "collection": "OtherKnowledge"}),
    ("knowledge_search", {"query": "x", "limit": True}),
    ("knowledge_search", {"query": "x", "limit": 31}),
    ("knowledge_search", {"query": "x", "diagnostics": "true"}),
    ("knowledge_search", {"query": "x", "path_prefix": "../"}),
    ("knowledge_propose", {"path": "../secret.md", "title": "X", "body": "X", "rationale": "X"}),
    ("knowledge_propose", {"path": "a.md", "title": "X", "body": "X", "rationale": "X", "status": "published"}),
    ("knowledge_propose", {"path": "a.md", "title": "X", "body": "X", "rationale": "X", "agent_id": "other"}),
])
async def test_strict_mcp_arguments(db, collection, agent, tool, args):
    assert (await call(agent, collection, tool, args))["error"] == "invalid_arguments"
    assert await db.scalar(select(func.count()).select_from(k.Revision)) == 0


async def test_proposal_rolls_back_when_audit_fails(db, collection, agent, monkeypatch):
    await allow(db, agent, collection, "knowledge_propose")
    async def fail(*args, **kwargs):
        raise RuntimeError("Audit unavailable")
    monkeypatch.setattr(audit, "record", fail)
    with pytest.raises(RuntimeError):
        await call(agent, collection, "knowledge_propose", {"path": "new.md", "title": "New", "body": "Text", "rationale": "Useful"})
    async with session() as fresh:
        assert await fresh.scalar(select(func.count()).select_from(k.Revision)) == 0
        assert await fresh.scalar(select(func.count()).select_from(k.Document)) == 0


async def test_concurrent_reviews_only_publish_once(db, collection):
    rev = await k.propose(db, collection.id, path="new.md", title="New", body="Reviewed once")
    await db.commit()
    async def approve():
        async with session() as tx:
            await k.lock_writes(tx)
            try:
                await k.review(tx, rev.id, True)
                await tx.commit()
                return True
            except k.KnowledgeError:
                return False
    assert sorted(await asyncio.gather(approve(), approve())) == [False, True]
    assert await db.scalar(select(func.count()).select_from(k.Chunk)) == 1


def test_chunking_preserves_complete_oversized_lines():
    body = "# Heading\n" + "longline" * 1000 + "\nshort\n"
    chunks = list(k.chunk_markdown(body))
    assert "".join(c[2] for c in chunks) == body
    assert len(chunks[0][2]) > 2400
    assert chunks[0][:2] == (1, 2)
    assert chunks[-1][:2] == (3, 3)


async def test_rechunk_preserves_reviewed_source_invalidates_old_ids_and_is_idempotent(db, collection, monkeypatch):
    rev = await publish(db, collection, "# Project\n\n## Backup\n\nRestore a new profile.\n\n## Release\n\nPromote accepted images.\n",
                        source="pinned repository", source_version="abc123")
    await legacy_chunks(db, collection, rev)
    before = await k.get_document(db, collection.id, rev.document_id)

    class OldIndex:
        async def search(self, *args, current_ids, **kwargs):
            count = int(f"{rev.id}:0" in current_ids)
            return idx.IndexSearch(semantic=[f"{rev.id}:0"], indexed_chunks=count,
                                   model_matches=count, compatible_chunks=count)

        async def replace(self, *args):
            raise AssertionError("Rechunking must not write to the semantic index")

    monkeypatch.setattr(idx, "backend", OldIndex)
    assert (await k.search(db, collection.id, "accepted"))["index_status"] == "current"
    await db.commit()
    await k.lock_writes(db)
    result = await k.rechunk(db, collection.id)
    await db.commit()
    assert result == {"version": k.CHUNK_VERSION, "documents": 1, "changed_documents": 1, "chunks": 2}
    assert await k.get_document(db, collection.id, rev.document_id) == before
    after = await k.search(db, collection.id, "accepted", diagnostics=True)
    assert after["index_status"] == "missing" and after["warning"] and after["mode"] == "text"
    assert after["results"][0]["section_path"] == ["Project", "Release"]
    assert after["results"][0]["chunk_version"] == k.CHUNK_VERSION
    assert f"{rev.id}:0" not in [h["chunk_id"] for h in after["results"]]
    assert await db.scalar(select(func.count()).select_from(k.Revision)) == 1
    assert await db.scalar(text("SELECT count(*) FROM knowledge_fts")) == 2
    await db.commit()
    await k.lock_writes(db)
    again = await k.rechunk(db, collection.id)
    await db.commit()
    assert again["changed_documents"] == 0 and again["chunks"] == 2
    assert await db.scalar(text("SELECT count(*) FROM knowledge_fts")) == 2


async def test_rechunk_excludes_foreign_archived_expired_and_pending(db, collection):
    other = await k.create_collection(db, "OtherChunkScope")
    foreign = await publish(db, other, "Foreign", path="other.md")
    await legacy_chunks(db, other, foreign)
    current = await publish(db, collection, "Current", path="current.md")
    await legacy_chunks(db, collection, current)
    expired = await publish(db, collection, "Expired", path="expired.md", kind="operational")
    await legacy_chunks(db, collection, expired)
    expired.expires_at = now() - timedelta(days=1)
    archived = await publish(db, collection, "Archived", path="archived.md")
    await k.archive(db, collection.id, archived.document_id, archived.id)
    await k.propose(db, collection.id, path="pending.md", title="Pending", body="Not published")
    await db.commit()
    await k.lock_writes(db)
    result = await k.rechunk(db, collection.id)
    await db.commit()
    assert result["documents"] == result["changed_documents"] == 1
    ids = set(await db.scalars(select(k.Chunk.id)))
    assert ids == {f"{foreign.id}:0", f"{expired.id}:0", k.chunk_id(current.id, 0)}


async def test_failed_rechunk_rolls_back_every_document_and_text_index(db, collection):
    first = await publish(db, collection, "# First\n\nReadable text.\n", path="a.md")
    second = await publish(db, collection, "# Second\n\nOriginal text.\n", path="b.md")
    await legacy_chunks(db, collection, first)
    await legacy_chunks(db, collection, second)
    original_ids = {f"{first.id}:0", f"{second.id}:0"}
    rid = collection.id
    k.blob_path(second.sha256).write_text("Tampered canonical file")
    await k.lock_writes(db)
    with pytest.raises(k.KnowledgeError, match="integrity"):
        await k.rechunk(db, rid)
    await db.rollback()
    assert set(await db.scalars(select(k.Chunk.id))) == original_ids
    assert set(await db.scalars(text("SELECT id FROM knowledge_fts"))) == original_ids


def test_nullable_chunk_metadata_upgrade_does_not_rechunk_existing_rows():
    from sqlalchemy import create_engine

    from keywright_server.db import _upgrade_knowledge_columns

    engine = create_engine("sqlite:///:memory:")
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE knowledge_chunks (id TEXT PRIMARY KEY, body TEXT)"))
            conn.execute(text("INSERT INTO knowledge_chunks VALUES ('rev_old:0', 'Original passage')"))
            _upgrade_knowledge_columns(conn)
            _upgrade_knowledge_columns(conn)
            assert conn.execute(text("SELECT id,body,section_path FROM knowledge_chunks")).one() == (
                "rev_old:0", "Original passage", None)
    finally:
        engine.dispose()


@pytest.mark.parametrize("path", ["../x.md", "/root/x.md", "a/../x.md", "a//x.md", "./x.md", "x.txt", "a\\x.md", "x\x00.md"])
def test_invalid_source_paths(path):
    with pytest.raises(k.KnowledgeError):
        k.valid_path(path)


async def test_git_import_uses_committed_regular_file(db, tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    def git(*args):
        return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
    git("init")
    (root / "runbook.md").write_text("Committed version")
    (root / "link.md").symlink_to("runbook.md")
    git("add", "runbook.md", "link.md")
    git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "Fixture")
    (root / "runbook.md").write_text("Uncommitted version")
    monkeypatch.setenv("KW_KNOWLEDGE_GIT_ROOT", str(root))
    body, commit = await k.git_markdown("runbook.md")
    assert body == "Committed version" and len(commit) == 40
    with pytest.raises(k.KnowledgeError, match="regular"):
        await k.git_markdown("link.md")


async def test_markdown_integrity_failure(db, collection):
    rev = await publish(db, collection, "Integrity fixture")
    k.blob_path(rev.sha256).write_text("Tampered")
    with pytest.raises(k.KnowledgeError, match="integrity"):
        await k.get_document(db, collection.id, rev.document_id)


async def test_fts_query_escaping_and_pagination(db, collection):
    await publish(db, collection)
    await publish(db, collection, "SQLite operations", path="runbook.md")
    assert (await k.search(db, collection.id, '"SQLite" OR * NOT ('))["results"]
    first = await k.list_documents(db, collection.id, limit=1)
    second = await k.list_documents(db, collection.id, offset=first["next_offset"], limit=1)
    assert second["next_offset"] is None
    assert first["documents"][0]["path"] != second["documents"][0]["path"]
    assert not (await k.search(db, collection.id, "***"))["results"]


async def test_ui_create_publish_search_review_export_csrf(live_server, db, agent):
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}, follow_redirects=True) as http:
        assert (await http.get("/ui/knowledge")).url.path == "/ui/login"
        await http.post("/ui/login", data={"password": "adminpass123"})
        denied = await http.post("/ui/knowledge/collections", data={"name": "Blocked"}, headers={"Origin": "https://evil.invalid"})
        assert denied.status_code == 403
        page = await http.post("/ui/knowledge/collections", data={"name": "ProjectDocs"})
        assert page.status_code == 200 and "ProjectDocs" in page.text
        res = await db.scalar(select(k.Resource).where(k.Resource.name == "ProjectDocs"))
        assert res.default_mode == "locked"
        page = await http.post(f"/ui/knowledge/{res.id}/publish", data={"path": "decisions/sql.md", "title": "SQL decision",
            "body": "# SQL\n<script>alert('x')</script>\nUse transactions.", "kind": "decision"})
        assert "SQL decision" in page.text
        doc = await db.scalar(select(k.Document))
        denied = await http.post(f"/ui/knowledge/{res.id}/rechunk", headers={"Origin": "https://evil.invalid"})
        assert denied.status_code == 403
        page = await http.post(f"/ui/knowledge/{res.id}/rechunk")
        assert "Updated search passages for 0 documents" in page.text
        page = await http.get(f"/ui/knowledge/documents/{doc.id}")
        assert "&lt;script&gt;" in page.text and "<script>alert('x')</script>" not in page.text
        download = await http.get(f"/ui/knowledge/documents/{doc.id}?download=true")
        assert download.text.startswith("# SQL") and "attachment" in download.headers["content-disposition"]
        page = await http.get("/ui/knowledge", params={"collection": res.id, "q": "transactions"})
        assert "Search results" in page.text and "SQL decision" in page.text
        await allow(db, agent, res, "knowledge_propose")
        proposal = await call(agent, res, "knowledge_propose", {"path": "memory.md", "title": "Lesson", "body": "New lesson", "rationale": "Session summary"})
        page = await http.get("/ui/knowledge/proposals/" + proposal["proposal_id"])
        assert "Changes from current publication" in page.text and "Session summary" in page.text
        page = await http.post("/ui/knowledge/proposals/" + proposal["proposal_id"], data={"action": "approve"})
        assert "Lesson" in page.text
        page = await http.get("/ui/access", params={"resource": res.id})
        assert "knowledge_search" in page.text and "knowledge_propose" in page.text
        page = await http.get(f"/ui/resources/{res.id}")
        assert page.url.path == "/ui/knowledge"
        events = list(await db.scalars(select(AuditEvent.tool)))
        assert {"knowledge.publish", "knowledge.review", "knowledge.get", "knowledge.search", "knowledge.rechunk"} <= set(events)


async def test_local_index_startup_is_idempotent(db, collection):
    from keywright_server.db import init_db
    await publish(db, collection, "survivesstartup")
    await init_db()
    await init_db()
    assert len((await k.search(db, collection.id, "survivesstartup"))["results"]) == 1
    assert await db.scalar(text("SELECT count(*) FROM knowledge_fts")) == 1


async def test_proxy_cannot_bypass_broker(collection):
    with pytest.raises(ValueError):
        await mcp_proxy.call_tool(collection.config, "knowledge_list", {})
