import json
from itertools import pairwise
from pathlib import Path

from keywright_server.knowledge_chunking import chunks


def check_citations(body, result):
    lines = body.splitlines(keepends=True)
    covered = set()
    last_end = 0
    for chunk in result:
        assert chunk.text == "".join(lines[chunk.line_start - 1:chunk.line_end])
        assert chunk.line_end > last_end
        last_end = chunk.line_end
        covered.update(range(chunk.line_start, chunk.line_end + 1))
    assert covered == set(range(1, len(lines) + 1))


def test_headings_stay_with_content_and_breadcrumbs_follow_hierarchy():
    body = "# Project\n\n## Backup\n\nRestore into a new profile.\n\n### Pairing\n\nPairing is excluded.\n\n## Release\n\nPromote images.\n"
    result = list(chunks(body))
    check_citations(body, result)
    assert [c.section_path for c in result] == [("Project", "Backup"), ("Project", "Backup", "Pairing"), ("Project", "Release")]
    assert result[0].text.startswith("# Project")
    assert result[1].text.startswith("### Pairing")
    assert all(not c.text.rstrip().splitlines()[-1].startswith("#") for c in result)


def test_fenced_code_headings_do_not_create_sections_and_setext_does():
    body = "Project\n=======\n\n```markdown\n# Not a heading\n```\n\n~~~python\n## Still code\n~~~~\n\nRelease\n-------\n\nPromote images.\n"
    result = list(chunks(body))
    check_citations(body, result)
    assert [c.section_path for c in result] == [("Project",), ("Project", "Release")]
    assert "# Not a heading" in result[0].text and "## Still code" in result[0].text


def test_oversized_lines_remain_complete_and_heading_attached():
    body = "# Heading\n\n" + "longline" * 1000 + "\nshort\n"
    result = list(chunks(body))
    check_citations(body, result)
    assert result[0].line_start == 1 and result[0].line_end == 3
    assert len(result[0].text) > 2400
    assert result[1].text == "short\n"


def test_long_sections_prefer_paragraphs_and_bounded_overlap_makes_progress():
    body = "# Long\n\n" + "".join(f"Paragraph {i}: " + "x" * 40 + "\n\n" for i in range(12))
    result = list(chunks(body, size=200, overlap=70))
    check_citations(body, result)
    assert len(result) > 3
    assert all(c.section_path == ("Long",) for c in result)
    lines = body.splitlines(keepends=True)
    for previous, current in pairwise(result):
        assert len("".join(lines[current.line_start - 1:previous.line_end])) <= 70
    assert any(a.line_end >= b.line_start for a, b in pairwise(result))


def test_crlf_unicode_and_terminal_heading_preserve_source():
    body = "# Café\r\n\r\nOxygen 🫁 readings.\r\n\r\n## Unfinished"
    result = list(chunks(body))
    check_citations(body, result)
    assert result[-1].text.endswith("## Unfinished")


def test_synthetic_corpus_has_no_orphan_headings():
    corpus = json.loads((Path(__file__).parent / "fixtures/knowledge_corpus.json").read_text())
    for doc in corpus:
        result = list(chunks(doc["markdown"]))
        check_citations(doc["markdown"], result)
        assert all(not c.text.rstrip().splitlines()[-1].startswith("#") for c in result)
        if doc["path"].endswith("example/overview.md"):
            lines = doc["markdown"].splitlines()
            release_line = lines.index("Build a candidate from committed sources.") + 1
            release = next(c for c in result if c.line_start <= release_line <= c.line_end)
            assert release.section_path[-1] == "Validation and release workflow"
            assert "Restore documents" not in release.text
            backup_line = lines.index("Restore documents into a new empty workspace.") + 1
            backup = next(c for c in result if c.line_start <= backup_line <= c.line_end)
            assert backup.line_end >= backup_line + 1
            assert backup.section_path[-1] == "Backup and recovery"
