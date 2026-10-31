import pytest

from keywright_server import bundles


def test_parse_and_format_roundtrip():
    text = "read-only: tools/ha_get_*, tools/ha_search\ndestructive: mcp/ha/tools/ha_restart, tools/ha_call_service/service=turn_off"
    parsed = bundles.parse(text, "ha")
    assert parsed == {"read-only": ["tools/ha_get_*", "tools/ha_search"],
                      "destructive": ["tools/ha_restart", "tools/ha_call_service/service=turn_off"]}
    assert bundles.parse(bundles.format_text(parsed), "ha") == parsed
    assert bundles.expand("ha", parsed, "read-only") == ["mcp/ha/tools/ha_get_*", "mcp/ha/tools/ha_search"]
    assert bundles.expand("ha", parsed, "nope") is None
    assert bundles.parse("# comment\n\n", "ha") == {}


@pytest.mark.parametrize("bad", [
    "read-only tools/x",            # no colon
    "bad name!: tools/x",           # name chars
    "a: tools/x\na: tools/y",       # duplicate
    "a: ",                          # empty
    "a: tools",                     # too short
    "a: bundle/b",                  # nested bundle
    "a: tools/x y",                 # invalid segment
    "a: mcp/other/tools/x",         # another resource
])
def test_parse_rejects(bad):
    with pytest.raises(ValueError):
        bundles.parse(bad, "ha")


def test_suggest_groups_by_verb():
    out = bundles.suggest(["ha_get_state", "ha_list_areas", "ha_call_service", "ha_remove_area", "ha_restart",
                           "ha_config_set_automation", "ha_search", "mystery"])
    assert out["read-only"] == ["tools/ha_get_state", "tools/ha_list_areas", "tools/ha_search"]
    assert out["control"] == ["tools/ha_call_service"]
    assert out["destructive"] == ["tools/ha_remove_area", "tools/ha_restart"]
    assert out["config-write"] == ["tools/ha_config_set_automation"]
    assert out["other"] == ["tools/mystery"]
    for name, entries in out.items():
        bundles.parse(f"{name}: {', '.join(entries)}", "ha")
