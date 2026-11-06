"""Public project reports using the caller's GitHub CLI identity, without a broker.

Only the explicitly supplied title/body and client version are included. Never
collect configuration, credentials, logs, machine names or conversation history.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPOSITORY = "https://github.com/johnrcarty/keywright"
ISSUES_URL = REPOSITORY + "/issues"


def prepare(kind: str, title: str, body: str) -> dict[str, str]:
    from . import __version__

    if kind not in ("bug", "connector"):
        raise ValueError("Choose bug or connector.")
    title, body = title.strip(), body.strip()
    if not title or len(title) > 200 or any(ord(c) < 32 or ord(c) == 127 for c in title):
        raise ValueError("Title must be 1–200 characters on one line.")
    if not body or len(body) > 50000 or "\x00" in body:
        raise ValueError("Supply a report body of 1–50,000 characters.")
    label = "Bug" if kind == "bug" else "Connector request"
    return {"repository": REPOSITORY, "title": f"[{label}] {title}",
            "body": f"{body}\n\n---\nSubmitted with Keywright {__version__} (`kw issue {kind}`).\n"}


def submit(report: dict[str, str]) -> str:
    # Pin github.com even when GH_HOST or the current checkout targets another server.
    env = {**os.environ, "GH_HOST": "github.com", "GH_PROMPT_DISABLED": "1"}
    try:
        result = subprocess.run(
            ["gh", "issue", "create", "--repo", REPOSITORY,
             "--title", report["title"], "--body-file", "-"],
            input=report["body"], text=True, capture_output=True, timeout=60, env=env, check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("Install GitHub CLI and run `gh auth login --hostname github.com`, then retry.") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Submission timed out; outcome unknown. Check {ISSUES_URL} before retrying.") from None
    except OSError:
        raise RuntimeError("Could not start GitHub CLI; check its installation and permissions.") from None
    if result.returncode:
        # gh diagnostics can contain report text or credentials; do not echo them.
        raise RuntimeError("GitHub CLI could not confirm submission. Check `gh auth status --hostname github.com` "
                           f"and {ISSUES_URL} before retrying.")
    url = result.stdout.strip()
    if not re.fullmatch(re.escape(ISSUES_URL) + r"/[0-9]+", url):
        raise RuntimeError(f"GitHub CLI returned no recognized issue URL. Check {ISSUES_URL} before retrying.")
    return url


def run(args) -> int:
    try:
        if args.body_file == "-":
            body = sys.stdin.read(50001)
        elif args.body_file:
            with Path(args.body_file).open(encoding="utf-8") as source:
                body = source.read(50001)
        else:
            body = args.body
        report = prepare(args.kind, args.title, body)
    except (ValueError, OSError):
        message = "Could not read a valid report. Use a one-line title (1–200 characters) and body (1–50,000)."
        if args.json:
            print(json.dumps({"error": "invalid_arguments", "message": message}))
        else:
            print("kw: " + message, file=sys.stderr)
        return 2
    if not args.submit:
        if args.json:
            print(json.dumps({"status": "preview", **report}))
        else:
            print(f"Repository: {REPOSITORY}\nTitle: {report['title']}\n\n{report['body']}")
            print("kw: Preview only. Review for private data; add --submit to publish this public issue.",
                  file=sys.stderr)
        return 0
    try:
        url = submit(report)
    except RuntimeError as exc:
        if args.json:
            print(json.dumps({"error": "submission_failed", "message": str(exc)}))
        else:
            print("kw: " + str(exc), file=sys.stderr)
        return 6
    print(json.dumps({"status": "submitted", "url": url}) if args.json else url)
    return 0
