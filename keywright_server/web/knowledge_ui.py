"""Admin knowledge publishing and proposal review; agent access stays behind MCP policy."""
import difflib

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .. import audit, knowledge_index
from .. import knowledge as k
from ..db import session
from ..models import Resource, now
from . import auth
from .admin import redirect, render
from .security import require_same_origin

router = APIRouter(dependencies=[Depends(require_same_origin), Depends(auth.require_admin)])


@router.get("/ui/knowledge")
async def home(request: Request, collection: str = "", q: str = "", offset: int = 0):
    async with session() as db:
        collections = list(await db.scalars(select(Resource).where(Resource.kind == "mcp").order_by(Resource.name)))
        collections = [r for r in collections if r.config.get("adapter") == "knowledge"]
        selected = next((r for r in collections if r.id == collection), None)
        documents, proposals, results = {"documents": [], "next_offset": None}, [], None
        if selected:
            documents = await k.list_documents(db, selected.id, max(0, offset), 50)
            proposals = (await db.execute(select(k.Revision, k.Document).join(k.Document)
                .where(k.Document.resource_id == selected.id, k.Revision.status == "pending")
                .order_by(k.Revision.created_at).limit(100))).all()
            if q.strip():
                try:
                    results = await k.search(db, selected.id, q)
                except k.KnowledgeError as exc:
                    results = {"results": [], "mode": "text", "warning": str(exc)}
                await audit.record(db, tool="knowledge.search", decision="read", detail={"collection": selected.id})
    return render(request, "knowledge.html", collections=collections, selected=selected, documents=documents,
                  proposals=proposals, results=results, q=q, kinds=k.KINDS,
                  semantic=knowledge_index.backend() is not None)


@router.post("/ui/knowledge/collections")
async def create(request: Request):
    form = await request.form()
    try:
        async with session() as db:
            await k.lock_writes(db)
            res = await k.create_collection(db, str(form.get("name", "")).strip(), str(form.get("description", "")))
            await audit.record(db, tool="knowledge.collection.create", decision="saved", detail={"collection": res.id})
            rid = res.id
    except (k.KnowledgeError, IntegrityError) as exc:
        return redirect("/ui/knowledge", str(exc) if isinstance(exc, k.KnowledgeError) else "Collection already exists.")
    return redirect("/ui/knowledge?collection=" + rid, "Collection created. Grant agents access using Access rules.")


@router.post("/ui/knowledge/{rid}/publish")
async def publish(request: Request, rid: str):
    form = await request.form()
    try:
        body, version = str(form.get("body", "")), ""
        path = str(form.get("path", ""))
        source = str(form.get("source", ""))
        if form.get("import_git") == "1":
            body, version = await k.git_markdown(path)
            source = "git:" + path
        async with session() as db:
            await k.lock_writes(db)
            rev = await k.propose(db, rid, path=path, title=str(form.get("title", "")), body=body,
                kind=str(form.get("kind", "documentation")), source=source, source_version=version,
                expected_revision=str(form.get("expected_revision", "")) or None,
                retention_days=int(form.get("retention_days", "30")))
            await k.review(db, rev.id, True)
            await audit.record(db, tool="knowledge.publish", decision="published",
                detail={"collection": rid, "revision": rev.id, "sha256": rev.sha256, "source_version": version})
    except (k.KnowledgeError, ValueError, IntegrityError) as exc:
        return redirect("/ui/knowledge?collection=" + rid,
            str(exc) if isinstance(exc, k.KnowledgeError) else "Invalid or conflicting document; refresh and retry.")
    return redirect("/ui/knowledge?collection=" + rid, "Published and text-indexed. Rebuild the semantic index to update it.")


@router.get("/ui/knowledge/documents/{did}")
async def document(request: Request, did: str, download: bool = False):
    async with session() as db:
        doc = await db.get(k.Document, did)
        if not doc:
            return redirect("/ui/knowledge", "Document not found.")
        try:
            res = await k.collection(db, doc.resource_id)
            data = await k.get_document(db, res.id, did)
        except k.KnowledgeError as exc:
            return redirect("/ui/knowledge", str(exc))
        await audit.record(db, tool="knowledge.get", decision="read", detail={"document": did, "revision": data["revision"]})
    if download:
        return PlainTextResponse(data["markdown"], media_type="text/markdown",
                                 headers={"Content-Disposition": 'attachment; filename="knowledge.md"'})
    return render(request, "knowledge_document.html", doc=data, collection=res, kinds=k.KINDS)


@router.get("/ui/knowledge/proposals/{revision_id}")
async def proposal(request: Request, revision_id: str):
    async with session() as db:
        rev = await db.get(k.Revision, revision_id)
        if not rev:
            return redirect("/ui/knowledge", "Proposal not found.")
        doc = await db.get(k.Document, rev.document_id)
        try:
            res = await k.collection(db, doc.resource_id)
            body = k.markdown(rev)
            old = await db.get(k.Revision, doc.current_revision) if doc.current_revision else None
            previous = k.markdown(old) if old else ""
        except k.KnowledgeError as exc:
            return redirect("/ui/knowledge", str(exc))
        diff = "".join(difflib.unified_diff(previous.splitlines(True), body.splitlines(True),
                                          fromfile="Current published Markdown", tofile="Proposed Markdown"))
    return render(request, "knowledge_proposal.html", revision=rev, doc=doc, collection=res, body=body, diff=diff)


@router.post("/ui/knowledge/proposals/{revision_id}")
async def review(request: Request, revision_id: str):
    form = await request.form()
    try:
        if form.get("action") not in ("approve", "reject"):
            raise k.KnowledgeError("Choose approve or reject.")
        async with session() as db:
            await k.lock_writes(db)
            rev = await k.review(db, revision_id, form["action"] == "approve")
            doc = await db.get(k.Document, rev.document_id)
            rid = doc.resource_id
            await audit.record(db, tool="knowledge.review", decision=rev.status,
                               detail={"revision": rev.id, "collection": rid, "sha256": rev.sha256})
    except k.KnowledgeError as exc:
        return redirect("/ui/knowledge/proposals/" + revision_id, str(exc))
    return redirect("/ui/knowledge?collection=" + rid, "Proposal " + rev.status + ".")


@router.post("/ui/knowledge/{rid}/archive")
async def archive(request: Request, rid: str):
    form = await request.form()
    try:
        async with session() as db:
            await k.lock_writes(db)
            await k.archive(db, rid, str(form.get("document_id", "")), str(form.get("expected_revision", "")))
            await audit.record(db, tool="knowledge.archive", decision="archived",
                               detail={"collection": rid, "document": str(form.get("document_id", ""))})
    except k.KnowledgeError as exc:
        return redirect("/ui/knowledge?collection=" + rid, str(exc))
    return redirect("/ui/knowledge?collection=" + rid, "Archived. This document is no longer returned to agents.")


@router.post("/ui/knowledge/{rid}/reindex")
async def reindex(rid: str):
    try:
        async with session() as db:
            count = await k.reindex(db, rid)
            res = await k.collection(db, rid)
            res.config = {**res.config, "knowledge_indexed_at": now().isoformat(), "knowledge_indexed_chunks": count}
            await audit.record(db, tool="knowledge.reindex", decision="indexed", detail={"collection": rid, "chunks": count})
    except (k.KnowledgeError, knowledge_index.IndexUnavailable) as exc:
        return redirect("/ui/knowledge?collection=" + rid, str(exc))
    return redirect("/ui/knowledge?collection=" + rid, f"Indexed {count} chunks for hybrid retrieval.")


@router.post("/ui/knowledge/{rid}/rechunk")
async def rechunk(rid: str):
    try:
        async with session() as db:
            await k.lock_writes(db)
            result = await k.rechunk(db, rid)
            await audit.record(db, tool="knowledge.rechunk", decision="rechunked", detail={"collection": rid, **result})
    except k.KnowledgeError as exc:
        return redirect("/ui/knowledge?collection=" + rid, str(exc))
    message = (f"Updated search passages for {result['changed_documents']} documents. "
               "Published content and review history are unchanged.")
    if result["changed_documents"] and knowledge_index.backend() is not None:
        message += " Rebuild the semantic index to include the new passages."
    return redirect("/ui/knowledge?collection=" + rid, message)
