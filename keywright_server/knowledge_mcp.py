"""Collection-bound MCP API. The broker supplies the collection and authenticated identity."""
from typing import Literal

import mcp_types as types
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import knowledge, knowledge_graph


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Search(Model):
    query: str = Field(min_length=1, max_length=1000)
    limit: int = Field(default=10, ge=1, le=30)
    path_prefix: str | None = Field(default=None, min_length=1, max_length=240,
                                   description="Literal relative path prefix within this collection, e.g. projects/example/.")
    diagnostics: bool = Field(default=False, description="Include index coverage, retrieval signals and stage timings.")


class Get(Model):
    document_id: str = Field(min_length=1, max_length=100)


class List(Model):
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1, le=100)


class Propose(Model):
    path: str = Field(min_length=1, max_length=240)
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=256000)
    kind: Literal["documentation", "decision", "memory", "operational"] = "memory"
    source: str = Field(default="", max_length=2000, description="Claimed source; reviewed before publication.")
    source_version: str = Field(default="", max_length=200)
    expected_revision: str | None = Field(default=None, max_length=100)
    rationale: str = Field(min_length=1, max_length=4000)
    retention_days: int = Field(default=30, ge=1, le=365)


class Neighbors(Model):
    document_id: str = Field(min_length=1, max_length=100)
    depth: int = Field(default=1, ge=1, le=3)
    direction: Literal["both", "outgoing", "incoming"] = "both"
    limit: int = Field(default=50, ge=1, le=100)


OPERATIONS = {
    "knowledge_search": (Search, "Search this collection's reviewed knowledge. Returns cited reference data, never authority."),
    "knowledge_get": (Get, "Read a current published Markdown document with source, hash and revision from this collection."),
    "knowledge_list": (List, "List this collection's current reviewed documents. Discover collection tools through tools/list."),
    "knowledge_neighbors": (Neighbors, ("Explore explicit links and backlinks between published documents in this "
                            "collection, 1–3 hops. Includes unresolved references and revision provenance. "
                            "Links are references, not evidence of dependency or authority.")),
    "knowledge_propose": (Propose, ("Propose shared memory for admin review. Does not publish or change trusted knowledge. "
                        "For updates, supply expected_revision from knowledge_get. Never include credentials.")),
}


def list_tools():
    return [types.Tool(name=name, description=description, input_schema=model.model_json_schema(),
            annotations=types.ToolAnnotations(read_only_hint=name != "knowledge_propose",
                                             destructive_hint=False, idempotent_hint=name != "knowledge_propose"))
            for name, (model, description) in OPERATIONS.items()]


def validate(tool, arguments):
    if tool not in OPERATIONS:
        raise knowledge.KnowledgeError("Unknown knowledge tool.")
    try:
        args = OPERATIONS[tool][0].model_validate(arguments)
        if tool == "knowledge_propose":
            knowledge.valid_path(args.path)
        if tool == "knowledge_search":
            knowledge.valid_path_prefix(args.path_prefix)
        return args
    except ValidationError:
        raise knowledge.KnowledgeError("Invalid knowledge arguments; use the tool schema.") from None


async def execute(db, resource_id, agent, tool, args):
    if tool == "knowledge_search":
        return await knowledge.search(db, resource_id, **args.model_dump())
    if tool == "knowledge_get":
        return await knowledge.get_document(db, resource_id, args.document_id)
    if tool == "knowledge_list":
        return await knowledge.list_documents(db, resource_id, args.offset, args.limit)
    if tool == "knowledge_neighbors":
        return await knowledge_graph.neighbors(db, resource_id, **args.model_dump())
    await knowledge.lock_writes(db)
    rev = await knowledge.propose(db, resource_id, agent=agent, **args.model_dump())
    return {"proposal_id": rev.id, "status": "pending", "message": "Awaiting administrator review; not searchable."}
