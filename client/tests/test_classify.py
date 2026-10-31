import pytest

from keywright.classify import classify

H = "ssh/nvr/exec"


@pytest.mark.parametrize("cmd,expected", [
    ("ls -la /opt", [f"{H}/ls"]),
    ("sudo journalctl -u myapp -n 50", [f"{H}/**"]),
    ("sudo -u myapp docker ps -a", [f"{H}/**"]),
    ("docker compose up -d", [f"{H}/docker/compose/up"]),
    ("docker logs --tail 100 myapp 2>&1 | tail -20", [f"{H}/**"]),
    ("systemctl status myapp && df -h", [f"{H}/systemctl/status", f"{H}/df"]),
    ("cat /etc/os-release; uptime", [f"{H}/cat", f"{H}/uptime"]),
    ("FOO=bar env BAZ=1 timeout 30s qm list", [f"{H}/**"]),
    ("/usr/bin/pct exec 101 -- ls", [f"{H}/pct/exec"]),
    ("git -C /opt/x status", [f"{H}/git/status"]),
    ("echo $(whoami)", [f"{H}/**"]),
    ("bash -c 'rm -rf /'", [f"{H}/**"]),
    ("ls; eval foo", [f"{H}/**"]),
    (r"find / -name x -exec rm {} \;", [f"{H}/**"]),
    ("find /var/log -name '*.log'", [f"{H}/find"]),
    ("xargs -0 rm < list", [f"{H}/**"]),
    ("ls > /tmp/out", [f"{H}/**"]),
    ("", [f"{H}/**"]),
    ("unterminated 'quote", [f"{H}/**"]),
])
def test_classify(cmd, expected):
    assert classify("nvr", cmd) == expected


T = "mcp/ha/tools/call_service"


@pytest.mark.parametrize("args,keys,expected", [
    ({"service": "light.turn_on"}, [], [T]),
    ({"service": "light.turn_on"}, None, [T]),
    ({"other": 1}, ["service"], [T]),
    ({"service": "light.turn_on"}, ["service", "entity_id"], [f"{T}/service=light.turn_on"]),
    ({"service": "light.turn_on", "entity_id": ["light.a", "light.b"]}, ["service", "entity_id"],
     [f"{T}/service=light.turn_on", f"{T}/entity_id=light.a", f"{T}/entity_id=light.b"]),
    ({"data": {"entity_id": "light.a"}}, ["data.entity_id"], [f"{T}/data.entity_id=light.a"]),
    ({"data": {"entity_id": {"nested": 1}}}, ["data.entity_id"], [T]),
    ({"service": "x/y z*"}, ["service"], [f"{T}/service=x_y_z_"]),
    ({"service": True, "n": 3}, ["service", "n"], [f"{T}/service=True", f"{T}/n=3"]),
    ({"service": ""}, ["service"], [f"{T}/service=_"]),
])
def test_classify_mcp(args, keys, expected):
    from keywright.classify import classify_mcp
    assert classify_mcp("ha", "call_service", args, keys) == expected


def test_classify_mcp_paths_validate():
    from keywright.classify import classify_mcp
    from keywright.patterns import validate
    for p in classify_mcp("ha", "t", {"a": "we!rd va/lue**", "b": ["x", 1]}, ["a", "b"]):
        assert validate(p) == p


def test_compose_flags_before_the_subcommand():
    # `docker compose -f x up` used to classify as .../compose/-f: too narrow to match any rule.
    assert classify("h", "docker compose -f /etc/x/compose.yaml up -d") == ["ssh/h/exec/docker/compose/up"]
    assert classify("h", "docker compose --file=x.yml --profile prod --dry-run pull") == ["ssh/h/exec/docker/compose/pull"]
    assert classify("h", "docker compose -f x.yml -f y.yml down") == ["ssh/h/exec/docker/compose/down"]
    # an unknown flag might take a value that looks like a subcommand, so it is not guessed at
    for c in ("docker compose --unknown up", "docker compose -f x.yml", "docker compose --dry-run=1 up"):
        assert classify("h", c) == ["ssh/h/exec/**"]
