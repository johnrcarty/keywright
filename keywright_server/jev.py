"""The TypeSafe System One protocol for Jev: endpoint, pinned model, the question spec and the
response validator. Pure: no configuration, database or network, so the offline evaluator under
experiments/ can share it without initialising the broker."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

ENDPOINT = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-1.13.0"
MAX_RESPONSE_BYTES = 128 * 1024
QUESTION_PATH = Path(__file__).with_name("semantic_questions.json")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def strict_json(text: str):
    def _object(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key] = value
        return out

    def _invalid(_):
        raise ValueError("non-finite JSON value")

    return json.loads(text, object_pairs_hook=_object, parse_constant=_invalid)


_spec: dict | None = None


def questions_spec() -> dict:
    global _spec
    if _spec is None:
        _spec = json.loads(QUESTION_PATH.read_text())
    return _spec


def _probability(value) -> bool:
    return type(value) in (float, int) and math.isfinite(value) and 0 <= value <= 1


def validate_response(body: dict, questions: dict, model: str) -> dict:
    if not isinstance(body, dict) or set(body) != {"model", "answers", "usage"} or body["model"] != model:
        raise ValueError("invalid response envelope")
    answers, usage = body["answers"], body["usage"]
    if not isinstance(answers, dict) or set(answers) != set(questions):
        raise ValueError("answer IDs differ")
    if (not isinstance(usage, dict) or set(usage) != {"input_tokens", "output_tokens"}
            or any(type(v) is not int or not 0 <= v <= 100_000_000 for v in usage.values())):
        raise ValueError("invalid usage")
    for key, question in questions.items():
        answer = answers[key]
        if not isinstance(answer, dict) or answer.get("type") != question["type"]:
            raise ValueError("invalid answer type")
        if answer["type"] == "noul":
            if set(answer) != {"type", "noul"} or not _probability(answer["noul"]):
                raise ValueError("invalid noul")
        elif answer["type"] == "choice":
            if set(answer) != {"type", "choice", "probabilities", "confidence"}:
                raise ValueError("invalid choice fields")
            probs = answer["probabilities"]
            if (not isinstance(probs, dict) or set(probs) != set(question["criteria"])
                    or any(not _probability(v) for v in probs.values())
                    or not math.isclose(sum(probs.values()), 1, abs_tol=0.015)
                    or not isinstance(answer["choice"], str) or answer["choice"] not in probs
                    or probs[answer["choice"]] < max(probs.values()) - 1e-9
                    or not _probability(answer["confidence"])):
                raise ValueError("invalid choice")
        else:
            raise ValueError("unsupported answer type")
    return body
