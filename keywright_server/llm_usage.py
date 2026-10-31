"""Bounded observation of response usage; never persists response content."""
from __future__ import annotations

import json
import math
from typing import Any


def numeric_usage(value: Any) -> dict | None:
    if not isinstance(value, dict):
        return None
    out = {}
    for name, count in value.items():
        if (type(count) is int or type(count) is float and math.isfinite(count)) and count >= 0:
            out[name.replace("_tokens", "")] = count
        elif isinstance(count, dict):
            nested = numeric_usage(count)
            if nested:
                out[name.replace("_tokens", "")] = nested
    return out or None


class UsageObserver:
    """Read JSON or SSE incrementally, retaining at most one bounded event/body.

    Anthropic deltas and OpenAI usage chunks contain cumulative counts: replace
    each reported field, never sum successive events for the same request.
    """

    LIMIT = 1_000_000

    def __init__(self, streaming: bool):
        self.streaming = streaming
        self.buffer = bytearray()
        self.data: list[bytes] = []
        self.size = 0
        self.skipping = False
        self.dropping_line = False
        self.usage: dict = {}
        self.failed = False

    def observe(self, data: Any):
        if not isinstance(data, dict):
            return
        if data.get("type") in ("error", "response.failed") or data.get("error"):
            self.failed = True
        containers = [data]
        for field in ("message", "response"):
            if isinstance(data.get(field), dict):
                containers.append(data[field])
        for container in containers:
            self.usage.update(numeric_usage(container.get("usage")) or {})

    def parse(self, raw: bytes):
        try:
            self.observe(json.loads(raw))
        except (ValueError, RecursionError):
            pass

    def feed(self, chunk: bytes):
        if not self.streaming:
            if not self.skipping and len(self.buffer) + len(chunk) <= self.LIMIT:
                self.buffer.extend(chunk)
            else:
                self.skipping = True
                self.buffer.clear()
            return
        # Split before retaining bytes so even one enormous chunk is bounded.
        for index, part in enumerate(chunk.split(b"\n")):
            if index:
                if not self.dropping_line:
                    self.line(bytes(self.buffer).rstrip(b"\r"))
                self.dropping_line = False
                self.buffer.clear()
            if len(self.buffer) + self.size + len(part) > self.LIMIT:
                self.skipping = True
                self.dropping_line = True
                self.buffer.clear()
                self.data.clear()
            elif not self.dropping_line:
                self.buffer.extend(part)

    def line(self, line: bytes):
        if not line:
            if not self.skipping and self.data:
                self.parse(b"\n".join(self.data))
            self.data.clear()
            self.size = 0
            self.skipping = False
        elif not self.skipping and line.startswith(b"data:"):
            value = line[5:].removeprefix(b" ")
            self.data.append(value)
            self.size += len(value)

    def finish(self):
        if not self.streaming and not self.skipping and self.buffer:
            self.parse(bytes(self.buffer))
        self.buffer.clear()
        self.data.clear()
