import io
import json
import subprocess
from types import SimpleNamespace

import pytest

from keywright import cli, issues


def test_preview_without_broker_or_gh(monkeypatch, capsys):
    def unexpected(*args, **kwargs):
        pytest.fail("Preview must not invoke GitHub or a broker")

    monkeypatch.setattr(subprocess, "run", unexpected)
    monkeypatch.setattr(cli, "Gate", unexpected)
    monkeypatch.setenv("KW_TOKEN", "private-token-must-not-be-collected")
    assert cli.main(["issue", "connector", "--title", "Support service", "--body", "Read status", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "preview" and data["title"] == "[Connector request] Support service"
    assert "private-token" not in str(data) and "Read status" in data["body"]


def test_submit_preserves_literal_body_and_pins_repository(monkeypatch, tmp_path, capsys):
    body = "Steps:\n1. Run `status`\n2. Literal $(hostname) and $TOKEN\nExpected: works\nActual: failed\n"
    report = tmp_path / "report.txt"
    report.write_text(body)
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=issues.ISSUES_URL + "/123\n", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setenv("GH_HOST", "enterprise.example")
    assert cli.main(["issue", "bug", "--title", "Broken status", "--body-file", str(report),
                     "--submit", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "submitted", "url": issues.ISSUES_URL + "/123"}
    assert len(calls) == 1
    command, options = calls[0]
    assert command == ["gh", "issue", "create", "--repo", issues.REPOSITORY,
                       "--title", "[Bug] Broken status", "--body-file", "-"]
    assert options["input"].startswith(body.strip() + "\n")
    assert options["env"]["GH_HOST"] == "github.com" and options["env"]["GH_PROMPT_DISABLED"] == "1"
    assert not options.get("shell") and options["timeout"] == 60


def test_stdin_preview(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("Requested operations\nRead cluster status"))
    assert cli.main(["issue", "connector", "--title", "New connector", "--body-file", "-", "--dry-run"]) == 0
    captured = capsys.readouterr()
    assert "Read cluster status" in captured.out and "Preview only" in captured.err


@pytest.mark.parametrize("failure", [FileNotFoundError(), subprocess.TimeoutExpired("gh", 60),
                                     SimpleNamespace(returncode=1, stdout="", stderr="private-token"),
                                     SimpleNamespace(returncode=0, stdout="https://evil.test/1", stderr="")])
def test_submission_errors_no_retry_or_sensitive_output(monkeypatch, capsys, failure):
    calls = []

    def run(*args, **kwargs):
        calls.append(args)
        if isinstance(failure, Exception):
            raise failure
        return failure

    monkeypatch.setattr(subprocess, "run", run)
    assert cli.main(["issue", "bug", "--title", "Bug", "--body", "Details", "--submit", "--json"]) == 6
    output = capsys.readouterr().out
    assert json.loads(output)["error"] == "submission_failed"
    assert "private-token" not in output and "evil.test" not in output and len(calls) == 1


@pytest.mark.parametrize("title,body", [("", "ok"), ("bad\nline", "ok"), ("x" * 201, "ok"),
                                      ("ok", ""), ("ok", "x" * 50001), ("ok", "bad\x00data")])
def test_invalid_report_never_submits(monkeypatch, capsys, title, body):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("Must not submit invalid content"))
    assert cli.main(["issue", "bug", "--title", title, "--body", body, "--submit", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "invalid_arguments"


def test_missing_report_file(capsys, tmp_path):
    assert cli.main(["issue", "bug", "--title", "Bug", "--body-file", str(tmp_path / "missing"), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "invalid_arguments"
