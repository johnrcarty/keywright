import json
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select, text

from keywright_server import knowledge as k
from keywright_server import knowledge_graph as graph
from keywright_server.db import session
from keywright_server.mcp_server import _proxy_call
from keywright_server.models import Policy, now


@pytest.fixture
async def collection(db):
    res = await k.create_collection(db, "GraphKnowledge")
    await db.commit()
    return res


async def publish(db, collection, path, body="# Note", **kwargs):
    rev = await k.propose(db, collection.id, path=path, title=kwargs.pop("title", path), body=body, **kwargs)
    await k.review(db, rev.id, True)
    await db.commit()
    return await db.get(k.Document, rev.document_id), rev


def test_extract_links_preserves_lines_and_ignores_non_prose():
    body = '''---
title: "[[metadata]]"
---
# Note
[[notes/Other#Heading|Label]] and [guide](../Guide%20one.md#part "title")
`[[inline]]` and `` [code](skip.md) ``
```md
[[fenced]]
```
~~~
[code](skip.md)
~~~
    [[indented]]
<!-- [[comment]]
[comment](skip.md) -->
![image](image.png) [external](https://example.com/a.md) [mail](mailto:a@example.com)
\\[[escaped]] \\[escaped](skip.md)
[Reference][doc] and [doc][] and [doc]
[doc]: ../Reference.md "Title"
[parentheses](../note(one).md) [spaces](<../With spaces.md>)
![[Embedded note]] [[#Local heading]]
'''
    refs = [(r.target_ref, r.syntax, r.line_number) for r in graph.extract(body, "notes/start.md")]
    assert refs == [
        ("../Guide%20one.md#part", "markdown", 5), ("notes/Other#Heading", "wiki", 5),
        ("../Reference.md", "markdown", 18),
        ("../With spaces.md", "markdown", 20), ("../note(one).md", "markdown", 20),
        ("#Local heading", "wiki", 21), ("Embedded note", "wiki", 21),
    ]


@pytest.mark.parametrize("ref,syntax,path", [
    ("../decision.md#why", "markdown", "decision.md"),
    ("/root.md", "markdown", "root.md"), ("./near", "wiki", "notes/near.md"),
    ("Project/Overview", "wiki", "Project/Overview.md"),
    ("Guide%20one.md", "markdown", "notes/Guide one.md"),
    ("#Heading", "markdown", "notes/start.md"),
    ("../../escape.md", "markdown", None), ("https://example.com/doc.md", "wiki", None),
    ("//other/secret.md", "markdown", None), ("file:///etc/secret.md", "markdown", None),
    ("javascript:alert(1)", "markdown", None), ("a.md?token=secret", "markdown", None),
    ("%2e%2e/%2e%2e/out.md", "markdown", None), ("other\\secret.md", "wiki", None),
    ("image.png", "wiki", None), ("%00.md", "markdown", None),
])
def test_path_resolution_is_collection_relative(ref, syntax, path):
    assert graph.target_path("notes/start.md", ref, syntax) == path


def test_short_wiki_names_resolve_only_when_unambiguous():
    assert graph.resolve("a/start.md", "Note", "wiki", {"b/Note.md": "one"}) == "one"
    assert graph.resolve("a/start.md", "Note", "wiki", {"b/Note.md": "one", "c/Note.md": "two"}) is None
    assert graph.resolve("a/start.md", "Note", "wiki", {"Note.md": "root", "b/Note.md": "one"}) == "root"
    assert graph.resolve("a/start.md", "Note.md", "markdown", {"b/Note.md": "one"}) is None


def test_upgrade_preserves_old_publications_and_is_repeatable():
    from sqlalchemy import create_engine

    from keywright_server.db import _upgrade_knowledge_graph_columns

    engine = create_engine("sqlite:///:memory:")
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE knowledge_revisions (id TEXT PRIMARY KEY, status TEXT, sha256 TEXT)"))
            conn.execute(text("INSERT INTO knowledge_revisions VALUES ('rev_old', 'published', 'original-hash')"))
            _upgrade_knowledge_graph_columns(conn)
            _upgrade_knowledge_graph_columns(conn)
            row = conn.execute(text("SELECT id, status, sha256, link_version FROM knowledge_revisions")).one()
            assert tuple(row) == ("rev_old", "published", "original-hash", None)
    finally:
        engine.dispose()


async def test_publication_backlinks_late_targets_and_current_revisions(db, collection):
    a, rev = await publish(db, collection, "a.md", "[[b]] [[not-yet]]")
    initial = await graph.snapshot(db, collection.id)
    assert not initial["edges"] and len(initial["unresolved"]) == 2
    b, _ = await publish(db, collection, "b.md", "[[c]]")
    c, _ = await publish(db, collection, "c.md")
    snapshot = await graph.snapshot(db, collection.id)
    assert {(e["source"], e["target"]) for e in snapshot["edges"]} == {(a.id, b.id), (b.id, c.id)}
    assert snapshot["unindexed_documents"] == 0
    incoming = await graph.neighbors(db, collection.id, c.id, depth=2, direction="incoming")
    assert {n["id"]: n["distance"] for n in incoming["nodes"]} == {c.id: 0, b.id: 1, a.id: 2}
    outgoing = await graph.neighbors(db, collection.id, c.id, direction="outgoing")
    assert [n["id"] for n in outgoing["nodes"]] == [c.id]
    await publish(db, collection, "a.md", "[[c]]", expected_revision=rev.id)
    changed = await graph.snapshot(db, collection.id)
    assert {(e["source"], e["target"]) for e in changed["edges"]} == {(a.id, c.id), (b.id, c.id)}
    assert not changed["unresolved"]
    assert await db.scalar(select(func.count()).select_from(graph.Link).where(graph.Link.source_revision_id == rev.id)) == 0


async def test_pending_rejected_archived_expired_and_cross_collection_are_invisible(db, collection):
    foreign = await k.create_collection(db, "PrivateKnowledge")
    await db.commit()
    hidden, _ = await publish(db, foreign, "hidden.md", title="Private title")
    source, _ = await publish(db, collection, "source.md", "[[hidden]] [[pending]] [[archived]] [[expired]]")
    pending = await k.propose(db, collection.id, path="pending.md", title="Pending title", body="[[source]]")
    rejected = await k.propose(db, collection.id, path="rejected.md", title="Rejected title", body="[[source]]")
    await k.review(db, rejected.id, False)
    archived, archived_rev = await publish(db, collection, "archived.md", "[[source]]")
    expired, expired_rev = await publish(db, collection, "expired.md", "[[source]]", kind="operational")
    await k.archive(db, collection.id, archived.id, archived_rev.id)
    expired_rev.expires_at = now() - timedelta(seconds=1)
    await db.commit()
    result = await graph.neighbors(db, collection.id, source.id, depth=3)
    assert [n["id"] for n in result["nodes"]] == [source.id]
    assert len(result["unresolved"]) == 4 and not result["edges"]
    serialized = json.dumps(result)
    for value in (hidden.id, "Private title", pending.id, "Pending title", archived.id, expired.id):
        assert value not in serialized
    for doc_id in (hidden.id, pending.document_id, archived.id, expired.id):
        with pytest.raises(k.KnowledgeError, match="not found"):
            await graph.neighbors(db, collection.id, doc_id)
    # Admin global view can see both collections, but must not resolve between them.
    global_view = await graph.snapshot(db)
    assert len(global_view["nodes"]) == 2 and not global_view["edges"]


async def test_ambiguity_after_new_publication_does_not_trust_cached_target(db, collection):
    a, _ = await publish(db, collection, "one/Note.md")
    source, _ = await publish(db, collection, "start.md", "[[Note]]")
    assert (await graph.snapshot(db, collection.id))["edges"][0]["target"] == a.id
    await publish(db, collection, "two/Note.md")
    result = await graph.snapshot(db, collection.id)
    assert not result["edges"] and result["unresolved"][0]["source"] == source.id


async def test_rebuild_is_atomic_and_does_not_change_publication(db, collection):
    _, rev_a = await publish(db, collection, "a.md", "[[b]]")
    _, rev_b = await publish(db, collection, "b.md")
    before = (rev_a.id, rev_a.sha256, rev_a.reviewed_at)
    await db.execute(text("DELETE FROM knowledge_links"))
    rev_a.link_version = rev_b.link_version = None
    await db.commit()
    assert (await graph.snapshot(db, collection.id))["unindexed_documents"] == 2
    await k.lock_writes(db)
    stats = await graph.rebuild(db, collection.id)
    await db.commit()
    assert stats == {"documents": 2, "links": 1}
    assert before == (rev_a.id, rev_a.sha256, rev_a.reviewed_at)
    await graph.rebuild(db, collection.id)
    await db.commit()
    assert await db.scalar(select(func.count()).select_from(graph.Link)) == 1
    k.blob_path(rev_b.sha256).write_text("corrupt")
    with pytest.raises(k.KnowledgeError, match="integrity"):
        await graph.rebuild(db, collection.id)
    await db.rollback()
    assert await db.scalar(select(func.count()).select_from(graph.Link)) == 1


async def test_limits_are_explicit_and_local_depth_is_bounded(db, collection):
    docs = []
    for i in range(5):
        doc, _ = await publish(db, collection, f"{i}.md", f"[[{i + 1}]]")
        docs.append(doc)
    result = await graph.neighbors(db, collection.id, docs[0].id, depth=3, direction="outgoing", limit=3)
    assert result["truncated"] and result["matched_nodes"] == 4 and len(result["nodes"]) == 3
    assert docs[4].id not in json.dumps(result)
    with pytest.raises(k.KnowledgeError):
        await graph.neighbors(db, collection.id, docs[0].id, depth=4)
    with pytest.raises(k.KnowledgeError):
        graph.extract("[[a]] " * 1001, "start.md")


async def test_mcp_neighbors_uses_existing_gate_and_cannot_select_foreign_scope(db, collection, agent):
    doc, _ = await publish(db, collection, "a.md", "[[b]]")
    args = {"document_id": doc.id, "_wait_seconds": 0}
    denied = await _proxy_call(db, agent, None, collection.name, "knowledge_neighbors", args)
    assert denied.is_error
    db.add(Policy(agent_id=agent.id, pattern=f"mcp/{collection.name}/tools/knowledge_neighbors", effect="allow"))
    await db.commit()
    result = await _proxy_call(db, agent, None, collection.name, "knowledge_neighbors", args)
    assert not result.is_error and result.structured_content["nodes"][0]["id"] == doc.id
    assert result.meta["keywright"]["audit_id"]
    invalid = await _proxy_call(db, agent, None, collection.name, "knowledge_neighbors", {**args, "collection": "foreign"})
    assert invalid.is_error and invalid.structured_content["error"] == "invalid_arguments"


async def test_rollback_removes_links_and_publication(db, collection):
    rev = await k.propose(db, collection.id, path="new.md", title="New", body="[[missing]]")
    await db.commit()
    revision_id = rev.id
    async with session() as tx:
        await k.lock_writes(tx)
        await k.review(tx, revision_id, True)
        await tx.rollback()
    async with session() as tx:
        assert (await tx.get(k.Revision, revision_id)).status == "pending"
        assert await tx.scalar(select(func.count()).select_from(graph.Link)) == 0


async def test_graph_ui_auth_preview_scope_and_rebuild(live_server, db, collection):
    doc, _ = await publish(db, collection, "a.md", "[[missing]]")
    async with httpx.AsyncClient(base_url=live_server, headers={"Origin": live_server}) as client:
        assert (await client.get("/ui/knowledge/graph/data")).status_code in (303, 401)
        await client.post("/ui/login", data={"password": "adminpass123"})
        page = await client.get("/ui/knowledge/graph", params={"collection": collection.id, "document": doc.id})
        assert page.status_code == 200 and 'id="knowledge-canvas"' in page.text
        response = await client.get("/ui/knowledge/graph/data", params={"collection": collection.id})
        assert response.status_code == 200 and response.json()["nodes"][0]["id"] == doc.id
        preview = await client.get("/ui/knowledge/graph/preview/" + doc.id)
        assert preview.json()["markdown"] == "[[missing]]"
        blocked = await client.post("/ui/knowledge/graph/rebuild", data={"collection": collection.id},
                                    headers={"Origin": "https://evil.invalid"})
        assert blocked.status_code == 403
        assert (await client.post("/ui/knowledge/graph/rebuild", data={"collection": collection.id})).status_code == 303
        assert (await client.get("/ui/knowledge/graph/data?depth=4")).status_code == 422
        await k.archive(db, collection.id, doc.id, doc.current_revision)
        await db.commit()
        assert (await client.get("/ui/knowledge/graph/preview/" + doc.id)).status_code == 404


def test_plain_collection_paths_ignore_code_urls_host_paths_and_link_destinations():
    body = '''Preparation note: feedback/example/preparation.md
Source note: guides/review.md@rev_example; current document feedback/example/checkout.md
[linked](guides/linked.md) [[guides/wiki]] ![image](guides/image.md)
https://example.test/guides/web.md /srv/guides/host.md git:guides/git.md
`guides/code.md`
```text
guides/fenced.md
```
<!-- guides/comment.md -->
../../../escape.md
'''
    refs = graph.extract(body, 'feedback/example/checkout.md')
    assert [(r.target_ref, r.syntax, r.line_number) for r in refs] == [
        ('feedback/example/preparation.md', 'path', 1),
        ('guides/review.md', 'path', 2),
        ('guides/linked.md', 'markdown', 3), ('guides/wiki', 'wiki', 3),
    ]
    assert graph.target_path('feedback/example/checkout.md', 'guides/review.md', 'path') == 'guides/review.md'
    assert graph.target_path('feedback/example/checkout.md', '../preparation.md', 'path') == 'feedback/preparation.md'


async def test_existing_plain_paths_and_source_metadata_rebuild_without_rewriting_notes(db, collection):
    target, _ = await publish(db, collection, 'feedback/example/preparation.md')
    source, rev = await publish(db, collection, 'feedback/example/checkout.md',
        'Preparation note: feedback/example/preparation.md',
        source='Continuation of feedback/example/preparation.md; observed follow-up')
    before = (rev.id, rev.sha256, rev.reviewed_at, rev.source, k.markdown(rev))
    await db.execute(text('DELETE FROM knowledge_links'))
    rev.link_version = 1
    await db.commit()
    assert (await graph.snapshot(db, collection.id))['unindexed_documents'] == 1
    await k.lock_writes(db)
    result = await graph.rebuild(db, collection.id)
    await db.commit()
    assert result == {'documents': 2, 'links': 2}
    snapshot = await graph.neighbors(db, collection.id, source.id)
    assert {n['id'] for n in snapshot['nodes']} == {source.id, target.id}
    assert {(e['source_field'], e['relation']) for e in snapshot['edges']} == {
        ('markdown', 'references'), ('source', 'source_reference')}
    assert before == (rev.id, rev.sha256, rev.reviewed_at, rev.source, k.markdown(rev))
    await graph.rebuild(db, collection.id)
    await db.commit()
    assert await db.scalar(select(func.count()).select_from(graph.Link)) == 2


async def test_plain_and_source_references_respect_current_collection_visibility(db, collection):
    other = await k.create_collection(db, 'OtherPlainReferences')
    hidden, _ = await publish(db, other, 'notes/private.md', title='Private target')
    source, _ = await publish(db, collection, 'notes/source.md', 'See notes/private.md',
                              source='Source notes/private.md@rev_example')
    initial = await graph.snapshot(db)
    assert not initial['edges'] and len(initial['unresolved']) == 2
    local, rev = await publish(db, collection, 'notes/private.md')
    linked = await graph.neighbors(db, collection.id, source.id)
    assert {e['target'] for e in linked['edges']} == {local.id}
    assert hidden.id not in json.dumps(linked) and 'Private target' not in json.dumps(linked)
    await k.archive(db, collection.id, local.id, rev.id)
    await db.commit()
    after = await graph.neighbors(db, collection.id, source.id)
    assert not after['edges'] and len(after['unresolved']) == 2
    assert local.id not in json.dumps(after) and hidden.id not in json.dumps(after)
