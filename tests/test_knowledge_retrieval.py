"""Public text-retrieval baseline. Real-model hybrid quality is a separate release gate."""
import json
from pathlib import Path

import pytest

from keywright_server import knowledge as k

FIXTURE = json.loads((Path(__file__).parent / "fixtures/knowledge_retrieval.json").read_text())


@pytest.mark.parametrize("case", FIXTURE["queries"], ids=lambda case: case["id"])
async def test_synthetic_retrieval_quality(db, monkeypatch, case):
    monkeypatch.delenv("KW_KNOWLEDGE_PG_URL", raising=False)
    collection = await k.create_collection(db, "SyntheticReleaseBenchmark")
    sources = {}
    revisions = {}
    for document in FIXTURE["documents"]:
        revision = await k.propose(db, collection.id, **document, kind="documentation")
        await k.review(db, revision.id, True)
        sources[document["path"]] = document["body"].splitlines(keepends=True)
        revisions[document["path"]] = revision.id
    await db.commit()
    result = await k.search(db, collection.id, case["query"], limit=5,
                            path_prefix=case["path_prefix"], diagnostics=True)
    assert result["mode"] == "text"
    hits = result["results"]
    for hit in hits:
        assert hit["revision"] == revisions[hit["path"]]
        assert hit["text"] == "".join(sources[hit["path"]][hit["line_start"] - 1:hit["line_end"]])
        assert hit["citation"] == f"{hit['path']}@{hit['revision']}:L{hit['line_start']}-L{hit['line_end']}"
        if case["path_prefix"]:
            assert hit["path"].startswith(case["path_prefix"])
    if case["expected_path"] is None:
        assert not hits
    else:
        relevant = [rank for rank, hit in enumerate(hits, 1)
                    if hit["path"] == case["expected_path"] and case["expected_text"] in hit["text"]]
        assert relevant and min(relevant) <= case["max_rank"], [(h["path"], h["text"]) for h in hits]
