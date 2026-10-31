from keywright.setup import check, claude_code, codex


def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('CLAUDE_CONFIG_DIR', str(tmp_path / '.claude'))
    monkeypatch.setenv('CODEX_HOME', str(tmp_path / '.codex'))
    monkeypatch.setattr(check.shutil, 'which', lambda name: None)


def test_codex_only_setup_does_not_require_claude(tmp_path, monkeypatch):
    isolated(tmp_path, monkeypatch)
    codex.apply()
    lines = check.integration_checks()
    assert not any(ok is False for ok, _ in lines)
    assert any(ok is True and 'codex instructions' in text for ok, text in lines)
    assert not (tmp_path / '.claude').exists()


def test_existing_codex_without_setup_is_reported(tmp_path, monkeypatch):
    isolated(tmp_path, monkeypatch)
    (tmp_path / '.codex').mkdir()
    assert any(ok is False and 'codex instructions' in text for ok, text in check.integration_checks())


def test_override_that_hides_codex_setup_is_reported(tmp_path, monkeypatch):
    isolated(tmp_path, monkeypatch)
    codex.apply()
    (tmp_path / '.codex' / 'AGENTS.override.md').write_text('Unrelated global override')
    assert any(ok is False and 'codex instructions' in text for ok, text in check.integration_checks())


def test_claude_checks_still_detect_missing_hooks(tmp_path, monkeypatch):
    isolated(tmp_path, monkeypatch)
    codex.apply()
    (tmp_path / '.claude').mkdir()
    assert any(ok is False and 'claude code hooks' in text for ok, text in check.integration_checks())
    claude_code.apply()
    assert not any(ok is False for ok, _ in check.integration_checks())


def test_no_agent_setup_is_reported(tmp_path, monkeypatch):
    isolated(tmp_path, monkeypatch)
    assert any(ok is False and 'agent integration' in text for ok, text in check.integration_checks())
