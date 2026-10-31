"""Session identity: env wins, the SessionStart hook persists the conversation id, and the
per-process fallback cannot be revived by PID reuse."""
import os

import pytest

from keywright import session


def test_env_wins(monkeypatch):
    monkeypatch.setenv("KW_SESSION", "cephloom:job-42")
    monkeypatch.setenv("CODEX_THREAD_ID", "thread-123")
    assert session.resolve() == ("cephloom:job-42", "KW_SESSION")


def test_env_is_truncated(monkeypatch):
    monkeypatch.setenv("KW_SESSION", "x" * 300)
    value, _ = session.resolve()
    assert len(value) == session.MAX_LEN


def test_session_start_hook_writes_env_file(tmp_path, monkeypatch):
    target = tmp_path / "env"
    monkeypatch.setenv("CLAUDE_ENV_FILE", str(target))
    line = session.session_start_hook({"session_id": "abc-123 def"})
    assert line == "export KW_SESSION=claude:abc-123def"
    assert target.read_text().startswith("export KW_SESSION=claude:abc-123def")
    monkeypatch.delenv("CLAUDE_ENV_FILE")
    assert session.session_start_hook({"session_id": "x"}) is None


def test_per_process_identity_is_stable_and_swept(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.delenv("KW_SESSION", raising=False)
    pid = os.getpid()
    info = session._proc_field(pid)
    assert info is not None
    start = info[2]
    first = session._per_process(pid, start, "shell")
    assert first.startswith("shell:") and session._per_process(pid, start, "shell") == first
    d = session.runtime_dir()
    stale = d / f"999999-1-{session._boot_id()}"
    stale.write_text("shell:old")
    wrong_boot = d / f"{pid}-{start}-deadbeef"
    wrong_boot.write_text("shell:old")
    session._sweep(d)
    assert not stale.exists() and not wrong_boot.exists()
    # a "reused" pid with a different start time is a different identity
    assert session._per_process(pid, "0", "shell") != first


def test_resolve_finds_an_ancestor_or_says_why(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.delenv("KW_SESSION", raising=False)
    monkeypatch.delenv("CODEX_THREAD_ID", raising=False)
    value, source = session.resolve()
    assert (value is None and source.startswith("none")) or source.startswith("process ")


def test_codex_thread_survives_hidden_ancestry_and_separates_conversations(monkeypatch):
    monkeypatch.delenv("KW_SESSION", raising=False)
    monkeypatch.setenv("CODEX_THREAD_ID", "thread-123")
    monkeypatch.setattr(session, "_agent_ancestor", lambda: None)
    assert session.resolve() == ("codex:thread-123", "CODEX_THREAD_ID")
    monkeypatch.setattr(session, "_agent_ancestor", lambda: (123, "0", "codex"))
    assert session.resolve() == ("codex:thread-123", "CODEX_THREAD_ID")
    monkeypatch.setenv("CODEX_THREAD_ID", "thread-456")
    assert session.resolve() == ("codex:thread-456", "CODEX_THREAD_ID")
    monkeypatch.setattr(session.sys, "platform", "darwin")
    assert session.resolve() == ("codex:thread-456", "CODEX_THREAD_ID")


@pytest.mark.parametrize("value", ["", " bad ", "x\nAuthorization:bad", "é", "x" * 123])
def test_invalid_codex_metadata_falls_back_without_echoing_it(monkeypatch, value):
    monkeypatch.delenv("KW_SESSION", raising=False)
    monkeypatch.setenv("CODEX_THREAD_ID", value)
    monkeypatch.setattr(session, "_agent_ancestor", lambda: None)
    assert session.resolve()[0] is None
