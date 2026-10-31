import pytest

from keywright.patterns import matches, resource_of, specificity, validate


@pytest.mark.parametrize("pat,path,ok", [
    ("ssh/nvr/exec/ls", "ssh/nvr/exec/ls", True),
    ("ssh/nvr/exec/*", "ssh/nvr/exec/ls", True),
    ("ssh/nvr/exec/*", "ssh/nvr/exec/docker/ps", False),
    ("ssh/nvr/exec/**", "ssh/nvr/exec/docker/ps", True),
    ("ssh/nvr/exec/**", "ssh/nvr/exec", True),
    ("ssh/nvr/exec/docker", "ssh/nvr/exec/docker/ps", True),  # literal prefix rule
    ("ssh/nvr/exec/docker/ps", "ssh/nvr/exec/docker", False),
    ("ssh/*/exec/journalctl", "ssh/pve/exec/journalctl", True),
    ("ssh/**", "mcp/ha/tools/x", False),
    ("**", "mcp/ha/tools/x", True),
    ("mcp/ha/tools/get_state", "mcp/ha/tools/get_state", True),
    ("mcp/ha/tools/get_state", "mcp/ha/tools/call_service", False),
])
def test_matches(pat, path, ok):
    assert matches(pat, path) is ok


def test_validate():
    assert validate(" /ssh/nvr/exec/ls/ ") == "ssh/nvr/exec/ls"
    with pytest.raises(ValueError):
        validate("http/foo")
    with pytest.raises(ValueError):
        validate("ssh/**/exec")
    with pytest.raises(ValueError):
        validate("ssh/nvr/exec/rm -rf")


def test_resource_of_and_specificity():
    assert resource_of("ssh/nvr/exec/ls") == ("ssh", "nvr")
    assert resource_of("ssh") is None
    assert specificity("ssh/nvr/exec/ls") > specificity("ssh/nvr/exec/*") > specificity("ssh/nvr/exec/**")


@pytest.mark.parametrize("pat,path,ok", [
    ("mcp/ha/tools/call/entity_id=light.*", "mcp/ha/tools/call/entity_id=light.kitchen", True),
    ("mcp/ha/tools/call/entity_id=light.*", "mcp/ha/tools/call/entity_id=switch.x", False),
    ("mcp/ha/tools/call", "mcp/ha/tools/call/service=light.turn_on", True),  # tool covers qualified
    ("mcp/ha/tools/call/service=light.turn_on", "mcp/ha/tools/call", False),
    ("mcp/ha/tools/call/service=light.*", "mcp/ha/tools/call/service=light.turn_on/x", True),  # prefix rule
    ("ssh/nvr/exec/doc*", "ssh/nvr/exec/docker/ps", True),
    ("ssh/nvr/exec/*/ps", "ssh/nvr/exec/docker/ps/x", False),
])
def test_value_globs(pat, path, ok):
    assert matches(pat, path) is ok


def test_value_glob_covers_and_overlaps():
    from keywright.patterns import covers, overlaps
    t = "mcp/ha/tools/call"
    assert covers(f"{t}/entity_id=light.*", f"{t}/entity_id=light.kitchen")
    assert covers(f"{t}/entity_id=light.*", f"{t}/entity_id=light.k*")
    assert not covers(f"{t}/entity_id=light.k*", f"{t}/entity_id=light.*")
    assert covers(t, f"{t}/entity_id=light.*")
    assert not covers(f"{t}/entity_id=light.*", f"{t}/entity_id=*")
    assert overlaps(f"{t}/entity_id=light.*", f"{t}/entity_id=light.kitchen")
    assert overlaps(f"{t}/entity_id=light.*", f"{t}/entity_id=l*")
    assert not overlaps(f"{t}/entity_id=light.*", f"{t}/entity_id=switch.x")
    assert overlaps(t, f"{t}/entity_id=switch.x")
    assert specificity(f"{t}/entity_id=light.kitchen") > specificity(f"{t}/entity_id=light.*") > specificity(f"{t}/*")


def test_validate_value_globs():
    assert validate("mcp/ha/tools/call/entity_id=light.*") == "mcp/ha/tools/call/entity_id=light.*"
    for bad in ("mcp/ha/tools/call/*light", "mcp/ha/tools/call/li*ght", "mcp/ha/tools/call/entity_id=a b"):
        with pytest.raises(ValueError):
            validate(bad)


def test_tool_prefix_glob_is_valid_and_matches():
    p = validate("mcp/ha-mcp/tools/ha_get_*")
    assert matches(p, "mcp/ha-mcp/tools/ha_get_state") and not matches(p, "mcp/ha-mcp/tools/ha_call_service")


def test_llm_patterns_and_model_segments():
    from keywright.patterns import model_segment, resource_of, validate

    assert validate("llm/litellm/model/claude-sonnet-5") == "llm/litellm/model/claude-sonnet-5"
    assert resource_of("llm/litellm/model/x") == ("llm", "litellm")
    assert model_segment("openrouter/anthropic/claude-sonnet-5") == "openrouter_anthropic_claude-sonnet-5"
    assert model_segment("gpt-5.6") == "gpt-5.6"
    with pytest.raises(ValueError):
        validate("http/api/x")
