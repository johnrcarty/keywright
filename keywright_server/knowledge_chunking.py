"""Section-aware, line-exact Markdown chunks. Size is a target, not a line truncation limit."""
from __future__ import annotations

import re
from dataclasses import dataclass

VERSION = "sections-v2"
ATX = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*)|[ \t]*)$")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
SETEXT = re.compile(r"^ {0,3}(=+|-+)[ \t]*$")


@dataclass(frozen=True)
class MarkdownChunk:
    line_start: int
    line_end: int
    text: str
    section_path: tuple[str, ...]


def _headings(lines):
    headings = {}
    fence = None
    index = 0
    while index < len(lines):
        line = lines[index].rstrip("\r\n")
        marker = FENCE.match(line)
        if fence:
            if marker and marker[1][0] == fence[0] and len(marker[1]) >= fence[1] and not marker[2].strip():
                fence = None
        elif marker:
            # Backticks in a backtick fence's info string do not open a fenced block.
            if marker[1][0] != "`" or "`" not in marker[2]:
                fence = (marker[1][0], len(marker[1]))
        else:
            heading = ATX.match(line)
            if heading:
                title = re.sub(r"[ \t]+#+[ \t]*$", "", heading[2] or "").strip()
                headings[index] = (len(heading[1]), title, 1)
            elif (line.strip() and not line.startswith(("    ", "\t")) and index + 1 < len(lines)
                  and (underline := SETEXT.match(lines[index + 1].rstrip("\r\n")))):
                headings[index] = (1 if underline[1][0] == "=" else 2, line.strip(), 2)
                index += 1
        index += 1
    return headings


def _sections(lines, headings):
    start, index, content = 0, 0, False
    stack = []
    sections = []
    while index < len(lines):
        if index in headings:
            level, title, width = headings[index]
            if content:
                sections.append((start, index, tuple(name for _, name in stack)))
                start, content = index, False
            stack = [(depth, name) for depth, name in stack if depth < level]
            stack.append((level, title))
            index += width
        else:
            content |= bool(lines[index].strip())
            index += 1
    if start < len(lines):
        # A source ending in an unaccompanied heading cannot gain invented body text.
        # Keep that tail with the preceding section instead of emitting a heading-only chunk.
        if not content and sections:
            previous_start, _, breadcrumb = sections.pop()
            sections.append((previous_start, len(lines), breadcrumb))
        else:
            sections.append((start, len(lines), tuple(name for _, name in stack)))
    return sections


def chunks(body, size=2400, overlap=240):
    """Yield exact contiguous source lines, with bounded full-line overlap within sections.

    An indivisible long line or leading heading block plus its first content line can exceed
    `size`. The existing document byte limit is the hard ceiling; no partial-line citations
    or synthetic breadcrumbs are inserted into excerpt text.
    """
    if size < 1 or overlap < 0 or overlap >= size:
        raise ValueError("Require a positive size and overlap smaller than size.")
    lines = body.splitlines(keepends=True)
    headings = _headings(lines)
    heading_lines = {n for start, (_, _, width) in headings.items() for n in range(start, start + width)}
    for first, end, breadcrumb in _sections(lines, headings):
        start = frontier = first
        while start < end:
            minimum = max(start + 1, frontier + 1)
            if start == first:
                # Consecutive parent/child headings and whitespace belong with actual content.
                cursor = start
                while cursor < end and (cursor in heading_lines or not lines[cursor].strip()):
                    cursor += 1
                minimum = min(cursor + 1, end)
            cut, length = start, 0
            while cut < end:
                if cut >= minimum and length + len(lines[cut]) > size:
                    break
                length += len(lines[cut])
                cut += 1
            if cut < end:
                # Prefer a complete paragraph; an oversized paragraph falls back to whole lines.
                boundaries = [n for n in range(minimum, cut + 1) if not lines[n - 1].strip()]
                if boundaries:
                    cut = boundaries[-1]
            yield MarkdownChunk(start + 1, cut, "".join(lines[start:cut]), breadcrumb)
            if cut == end:
                break
            next_start, length = cut, 0
            while next_start > minimum and length + len(lines[next_start - 1]) <= overlap:
                if next_start - 1 in heading_lines:
                    break
                next_start -= 1
                length += len(lines[next_start])
            start = next_start if any(line.strip() for line in lines[next_start:cut]) else cut
            frontier = cut
