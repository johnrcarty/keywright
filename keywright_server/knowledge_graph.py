"""Derived, explicit document links. Visibility always comes from the knowledge registry.

Stored target IDs are hints only: resolution uses current published documents on
every read, so later publications, ambiguity, expiry and archival cannot leak or
resurrect a hidden target. No cross-collection resolution or inferred relations.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

from sqlalchemy import delete, select

from . import knowledge as k
from .models import KnowledgeLink as Link
from .models import Resource, now

VERSION = 2
MAX_LINKS = 1000
MAX_NODES = 500
MAX_EDGES = 5000


@dataclass(frozen=True)
class Reference:
    target_ref: str
    syntax: str
    line_number: int


def _blank(text: str) -> str:
    return "".join("\n" if c == "\n" else " " for c in text)


def _prose(body: str) -> str:
    """Mask code/comments while preserving source offsets and line numbers."""
    lines, fence, width, frontmatter = [], "", 0, False
    for index, line in enumerate(body.splitlines(keepends=True)):
        if index == 0 and line.strip() == "---":
            frontmatter = True
            lines.append(_blank(line))
            continue
        if frontmatter:
            if line.strip() in ("---", "..."):
                frontmatter = False
            lines.append(_blank(line))
            continue
        mark = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if fence:
            if mark and mark[1][0] == fence and len(mark[1]) >= width and not mark[2].strip():
                fence = ""
            lines.append(_blank(line))
        elif mark:
            fence, width = mark[1][0], len(mark[1])
            lines.append(_blank(line))
        elif line.startswith(("    ", "\t")):
            lines.append(_blank(line))
        else:
            lines.append(line)
    text = re.sub(r"<!--.*?(?:-->|\Z)", lambda m: _blank(m[0]), "".join(lines), flags=re.DOTALL)
    return re.sub(r"(?<!`)(`+)(?!`).*?(?<!`)\1(?!`)", lambda m: _blank(m[0]), text, flags=re.DOTALL)


def _destination(text: str, start: int) -> tuple[str, int] | None:
    """Read a Markdown destination and optional title after an opening parenthesis."""
    i = start
    while i < len(text) and text[i].isspace():
        i += 1
    begin = i
    if i < len(text) and text[i] == "<":
        end = text.find(">", i + 1)
        if end < 0 or "\n" in text[i:end]:
            return None
        value, i = text[i + 1:end], end + 1
    else:
        depth = 0
        while i < len(text):
            c = text[i]
            if c == "\\" and i + 1 < len(text):
                i += 2
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0:
                    break
                depth -= 1
            elif c.isspace() and depth == 0:
                break
            i += 1
        value = text[begin:i]
    while i < len(text) and text[i].isspace():
        i += 1
    if i < len(text) and text[i] in ('"', "'", "("):
        delimiter = ")" if text[i] == "(" else text[i]
        i += 1
        while i < len(text) and text[i] != delimiter:
            i += 2 if text[i] == "\\" else 1
        i += 1
        while i < len(text) and text[i].isspace():
            i += 1
    return (value, i + 1) if i < len(text) and text[i] == ")" else None


def target_path(source_path: str, ref: str, syntax: str) -> str | None:
    """Normalize within the collection, rejecting schemes and root escapes."""
    value = ref.split("|", 1)[0].strip() if syntax == "wiki" else re.sub(r"\\([\\`*{}\[\]()#+.!_<> -])", r"\1", ref)
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme or parsed.netloc or parsed.query or value.startswith("//"):
        return None
    path = unquote(parsed.path)
    if not path:
        return source_path if parsed.fragment else None
    if "\\" in path or ":" in path or any(ord(c) < 32 or ord(c) == 127 for c in path):
        return None
    suffix = PurePosixPath(path).suffix
    if suffix and suffix != ".md":
        return None
    if not suffix:
        path += ".md"
    rooted = path.startswith("/") or (syntax in {"wiki", "path", "source"} and not path.startswith(("./", "../")))
    parts = [] if rooted else source_path.split("/")[:-1]
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(segment)
    result = "/".join(parts)
    return result if result and len(result) <= 240 else None


def path_references(text: str, source_path: str, syntax: str = "path") -> list[Reference]:
    """Recognize whitespace-delimited collection paths, never URLs or host paths.

    Qualified plain paths are collection-root relative; ./ and ../ remain relative
    to the note. Markdown and wiki delimiters are handled by their existing parsers.
    """
    pattern = r"(?<!\S)((?:[\w.-]+/)+[\w.-]+\.md)(?=$|[\s,;.!?@])"
    refs = []
    for match in re.finditer(pattern, text):
        path = target_path(source_path, match[1], syntax)
        if path is not None and path != source_path:
            refs.append(Reference(match[1], syntax, text.count("\n", 0, match.start()) + 1))
    return refs


def extract(body: str, source_path: str) -> list[Reference]:
    text = _prose(body)
    found = []
    definitions = {}
    definition = re.compile(r"^ {0,3}\[([^\]\n]+)\]:[ \t]*(<[^>\n]+>|\S+)[^\n]*", re.MULTILINE)
    for match in definition.finditer(text):
        definitions[" ".join(match[1].casefold().split())] = match[2].strip("<>")
    text = definition.sub(lambda m: _blank(m[0]), text)

    def add(ref, syntax, offset):
        if target_path(source_path, ref, syntax) is not None:
            found.append(Reference(ref[:2000], syntax, text.count("\n", 0, offset) + 1))
            if len(found) > MAX_LINKS:
                raise k.KnowledgeError(f"A document may contain at most {MAX_LINKS} internal links.")

    wiki = re.compile(r"(?<!\\)\[\[([^\]\n]{1,2000})\]\]")
    for match in wiki.finditer(text):
        add(match[1].split("|", 1)[0].strip(), "wiki", match.start())
    text = wiki.sub(lambda m: _blank(m[0]), text)
    label = re.compile(r"(?<![\\!\[])\[((?:\\.|[^\[\]\n])+)\]")
    cursor = 0
    for match in label.finditer(text):
        if match.start() < cursor:
            continue
        end = match.end()
        if text[end:end + 1] == "(":
            dest = _destination(text, end + 1)
            if dest:
                add(dest[0], "markdown", match.start())
                cursor = dest[1]
        else:
            ref_label = match[1]
            if text[end:end + 1] == "[":
                close = text.find("]", end + 1)
                if close < 0:
                    continue
                ref_label = text[end + 1:close] or ref_label
                cursor = close + 1
            ref = definitions.get(" ".join(ref_label.casefold().split()))
            if ref:
                add(ref, "markdown", match.start())
    found.extend(path_references(text, source_path))
    if len(found) > MAX_LINKS:
        raise k.KnowledgeError(f"A document may contain at most {MAX_LINKS} internal links.")
    return sorted(set(found), key=lambda r: (r.line_number, r.target_ref, r.syntax))


def resolve(source_path: str, ref: str, syntax: str, paths: dict[str, str]) -> str | None:
    path = target_path(source_path, ref, syntax)
    if path is None:
        return None
    if path in paths:
        return paths[path]
    # Short wiki names may identify one unique basename. Ambiguous names stay unresolved.
    if syntax == "wiki" and "/" not in ref.split("#", 1)[0]:
        matches = [doc_id for name, doc_id in paths.items() if PurePosixPath(name).name == path]
        if len(matches) == 1:
            return matches[0]
    return None


async def _rows(db, resource_id: str | None):
    query = (select(k.Document, k.Revision, Resource)
             .join(k.Revision, k.Document.current_revision == k.Revision.id)
             .join(Resource, Resource.id == k.Document.resource_id)
             .where(Resource.kind == "mcp", Resource.config["adapter"].as_string() == "knowledge",
                    k.Revision.status == "published",
                    (k.Revision.expires_at.is_(None)) | (k.Revision.expires_at > now()))
             .order_by(Resource.name, k.Document.path))
    if resource_id is not None:
        query = query.where(k.Document.resource_id == resource_id)
    return (await db.execute(query)).all()


async def index_revision(db, doc, rev, body: str, *, paths: dict[str, str] | None = None) -> int:
    refs = extract(body, doc.path)
    refs.extend(path_references(rev.source or "", doc.path, "source"))
    if len(refs) > MAX_LINKS:
        raise k.KnowledgeError(f"A document may contain at most {MAX_LINKS} internal links.")
    if paths is None:
        paths = {d.path: d.id for d, _, _ in await _rows(db, doc.resource_id)}
    await db.execute(delete(Link).where(Link.source_document_id == doc.id))
    db.add_all([Link(source_document_id=doc.id, source_revision_id=rev.id,
                     target_document_id=resolve(doc.path, ref.target_ref, ref.syntax, paths),
                     target_ref=ref.target_ref, syntax=ref.syntax, line_number=ref.line_number,
                     origin="explicit", relation="source_reference" if ref.syntax == "source" else "references") for ref in refs])
    rev.link_version = VERSION
    await db.flush()
    return len(refs)


async def rebuild(db, resource_id: str | None = None) -> dict:
    """Caller owns the locked, audited transaction; corrupted source rolls it all back."""
    if resource_id is not None:
        await k.collection(db, resource_id)
    rows = await _rows(db, resource_id)
    paths = defaultdict(dict)
    for doc, _, _ in rows:
        paths[doc.resource_id][doc.path] = doc.id
    links = 0
    for doc, rev, _ in rows:
        links += await index_revision(db, doc, rev, k.markdown(rev), paths=paths[doc.resource_id])
    return {"documents": len(rows), "links": links}


async def snapshot(db, resource_id: str | None = None, *, document_id: str | None = None,
                   depth: int = 1, direction: str = "both", limit: int = MAX_NODES) -> dict:
    if type(depth) is not int or not 1 <= depth <= 3 or type(limit) is not int or not 1 <= limit <= MAX_NODES:
        raise k.KnowledgeError("Graph depth must be 1–3 and node limit 1–500.")
    if direction not in ("both", "outgoing", "incoming"):
        raise k.KnowledgeError("Choose both, outgoing or incoming links.")
    if resource_id is not None:
        await k.collection(db, resource_id)
    rows = await _rows(db, resource_id)
    nodes = {doc.id: {**k.provenance(doc, rev), "id": doc.id, "collection_id": res.id,
                     "collection": res.name, "url": f"/ui/knowledge/documents/{doc.id}"}
             for doc, rev, res in rows}
    if document_id and document_id not in nodes:
        raise k.KnowledgeError("Document not found in this collection's published knowledge.")
    paths = defaultdict(dict)
    revisions = {}
    for doc, rev, res in rows:
        paths[res.id][doc.path] = doc.id
        revisions[doc.id] = rev.id
    # Join to authoritative current revisions; historical links never enter this snapshot.
    query = (select(Link).join(k.Document, k.Document.id == Link.source_document_id)
             .join(k.Revision, k.Revision.id == Link.source_revision_id)
             .where(k.Document.current_revision == Link.source_revision_id, k.Revision.status == "published",
                    (k.Revision.expires_at.is_(None)) | (k.Revision.expires_at > now()))
             .order_by(Link.source_document_id, Link.line_number, Link.id))
    if resource_id is not None:
        query = query.where(k.Document.resource_id == resource_id)
    links = (await db.scalars(query)).all()
    edges, unresolved = [], []
    incoming, outgoing = defaultdict(set), defaultdict(set)
    for link in links:
        source = nodes.get(link.source_document_id)
        if source is None or revisions[source["id"]] != link.source_revision_id:
            continue
        target = resolve(source["path"], link.target_ref, link.syntax, paths[source["collection_id"]])
        edge = {"id": link.id, "source": source["id"], "target": target, "target_ref": link.target_ref,
                "relation": link.relation, "origin": link.origin, "line_number": link.line_number,
                "source_field": "source" if link.syntax == "source" else "markdown", "syntax": link.syntax,
                "source_revision": link.source_revision_id}
        if target:
            edges.append(edge)
            outgoing[source["id"]].add(target)
            incoming[target].add(source["id"])
        else:
            unresolved.append(edge)
    distances = {}
    if document_id:
        distances[document_id] = 0
        frontier = [document_id]
        for level in range(1, depth + 1):
            following = set()
            for source in frontier:
                if direction in ("both", "outgoing"):
                    following.update(outgoing[source])
                if direction in ("both", "incoming"):
                    following.update(incoming[source])
            frontier = sorted(following - distances.keys(), key=lambda i: (nodes[i]["path"], i))
            distances.update({i: level for i in frontier})
        selected = list(distances)[:limit]
        matched = len(distances)
    else:
        selected, matched = list(nodes)[:limit], len(nodes)
    included = set(selected)
    selected_edges = [edge for edge in edges if edge["source"] in included and edge["target"] in included]
    selected_unresolved = [edge for edge in unresolved if edge["source"] in included]
    for doc_id in selected:
        nodes[doc_id].update(incoming=len(incoming[doc_id]), outgoing=len(outgoing[doc_id]),
                             distance=distances.get(doc_id))
    return {"nodes": [nodes[i] for i in selected], "edges": selected_edges[:MAX_EDGES],
            "unresolved": selected_unresolved[:MAX_EDGES], "center": document_id,
            "depth": depth, "direction": direction, "total_nodes": len(nodes), "matched_nodes": matched,
            "truncated": matched > limit or len(selected_edges) > MAX_EDGES or len(selected_unresolved) > MAX_EDGES,
            "unindexed_documents": sum(rev.link_version != VERSION for _, rev, _ in rows),
            "notice": k.CONTENT_NOTICE, "generated_at": now().isoformat()}


async def neighbors(db, resource_id: str, document_id: str, depth: int = 1,
                    direction: str = "both", limit: int = 50) -> dict:
    return await snapshot(db, resource_id, document_id=document_id, depth=depth, direction=direction, limit=limit)
