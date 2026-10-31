"""Turn a shell command line into the permission paths it needs.

This is a scope guard, not a sandbox: it exists so an agent that asked for
`journalctl` doesn't quietly run `rm -rf`. Anything the parser can't reason
about safely (command substitution, eval, `bash -c`, xargs ...) requires the
host-wide pattern `ssh/<host>/exec/**`.
"""

from __future__ import annotations

import re
import shlex
from typing import Any

from .patterns import qualifier

WRAPPERS_WITH_ARGS = {"sudo", "env", "nice", "timeout", "nohup", "time", "command", "builtin", "stdbuf", "ionice"}
# bins whose first subcommand meaningfully changes what they do
SUBCOMMAND_BINS = {
    "docker", "podman", "systemctl", "git", "qm", "pct", "pvesh", "pvesm", "pveum", "apt", "apt-get",
    "kubectl", "ha", "npm", "pip", "uv", "zfs", "zpool", "ceph", "rados", "rbd", "virsh", "nmcli",
    "ip", "ufw", "iptables", "nft", "snap", "brew", "gh", "vzdump", "go", "cargo", "deno", "pnpm", "yarn", "bun",
    "poetry",
}
TWO_LEVEL = {("docker", "compose"), ("docker", "container"), ("docker", "image"), ("docker", "volume"),
             ("docker", "network"), ("podman", "compose"), ("git", "remote"), ("git", "stash"), ("ip", "link"),
             ("ip", "addr"), ("ip", "route")}
# Flags that may sit between a two-level bin and its real subcommand (`docker compose -f x.yml up`).
# Only listed flags are skipped: an unknown flag might take a value that looks like a subcommand.
_COMPOSE_VALUE_FLAGS = {"-f", "--file", "-p", "--project-name", "--project-directory", "--env-file", "--profile",
                        "--ansi", "--parallel", "--progress"}
_COMPOSE_BOOL_FLAGS = {"--compatibility", "--dry-run", "--all-resources"}
LEVEL_FLAGS = {("docker", "compose"): (_COMPOSE_VALUE_FLAGS, _COMPOSE_BOOL_FLAGS),
               ("podman", "compose"): (_COMPOSE_VALUE_FLAGS, _COMPOSE_BOOL_FLAGS)}
SHELLS = {"bash", "sh", "zsh", "dash", "fish", "ksh", "eval", "exec", "source", ".", "xargs", "python", "python3",
          "perl", "ruby", "node", "su", "screen", "tmux", "ssh", "script", "at", "batch", "crontab", "watch"}
# Bins that run project code by design. Bare names always fail closed; the others only for the
# subcommands that execute something (`go version` stays narrow, `go test` does not).
RUNNERS = {"pytest", "py.test", "tox", "nox", "mvn", "gradle", "rake", "npx", "uvx", "pipx", "ansible",
           "ansible-playbook", "terraform", "tofu", "pulumi"}
RUNNER_SUBCOMMANDS = {
    "npm": {"run", "test", "start", "exec", "x", "create", "init", "publish"},
    "pnpm": {"run", "test", "start", "exec", "dlx", "create", "init", "publish"},
    "yarn": {"run", "test", "start", "exec", "dlx", "create", "init", "publish"},
    "bun": {"run", "test", "x", "create", "init", "publish"},
    "go": {"run", "test", "generate", "tool", "vet"},
    "cargo": {"run", "test", "bench", "build", "install", "publish", "xtask"},
    "deno": {"run", "test", "task", "eval", "compile", "repl", "bench"},
    "poetry": {"run", "shell"}, "pdm": {"run"}, "hatch": {"run", "shell", "test"}, "uv": {"run"}, "pip": {"install"},
}
SEPARATORS = {";", "|", "||", "&&", "&", "(", ")", "{", "}", "|&"}
WILD = "**"


def classify(host: str, command: str) -> list[str]:
    """Return the ordered, de-duplicated list of required patterns for `command` on `host`."""
    base = f"ssh/{host}/exec"
    # shlex is a tokenizer, not a shell parser. Fail closed for syntax which can
    # change execution, environment, privileges, or write files outside the named command.
    if any(c in command for c in "\n\r<>$`#\\"):
        return [f"{base}/{WILD}"]
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";|&()<>{}")
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        return [f"{base}/{WILD}"]

    segments: list[list[str]] = [[]]
    for tok in tokens:
        if tok in SEPARATORS:
            if segments[-1]:
                segments.append([])
            continue
        segments[-1].append(tok)
    if not segments[-1]:
        segments.pop()

    out: list[str] = []
    for seg in segments:
        pat = _classify_segment(base, seg)
        if pat not in out:
            out.append(pat)
    if not out:
        out.append(f"{base}/{WILD}")
    if f"{base}/{WILD}" in out:
        return [f"{base}/{WILD}"]
    return out


def _classify_segment(base: str, words: list[str]) -> str:
    if not words:
        return f"{base}/{WILD}"
    executable = words[0]
    if "=" in executable or executable.rsplit("/", 1)[-1] in WRAPPERS_WITH_ARGS:
        return f"{base}/{WILD}"
    # Absolute system paths are useful; any other path could be an agent's own executable.
    if "/" in executable and executable not in ("/usr/bin/" + executable.rsplit("/", 1)[-1],
                                                "/bin/" + executable.rsplit("/", 1)[-1],
                                                "/usr/sbin/" + executable.rsplit("/", 1)[-1],
                                                "/sbin/" + executable.rsplit("/", 1)[-1]):
        return f"{base}/{WILD}"
    bin_ = executable.rsplit("/", 1)[-1]
    if bin_ in SHELLS or bin_ in {"if", "then", "for", "while", "until", "case", "function", "!"} or re.fullmatch(r"(?:python|pypy|node|perl|ruby|lua)[0-9.]*", bin_):
        return f"{base}/{WILD}"
    if bin_ == "find" and any(w in ("-exec", "-execdir", "-delete", "-ok", "-okdir") for w in words):
        return f"{base}/{WILD}"
    if bin_ in {"awk", "gawk", "mawk", "sed", "make", "gmake", "less", "more", "vi", "vim", "nvim"}:
        return f"{base}/{WILD}"
    # Test runners and build tools execute whatever the project contains; `exec/pytest` would read
    # as narrow in a prompt while meaning anything at all.
    if bin_ in RUNNERS or (bin_ in RUNNER_SUBCOMMANDS and any(w in RUNNER_SUBCOMMANDS[bin_] for w in words[1:2])):
        return f"{base}/{WILD}"
    if bin_ == "git" and any(w == "-c" or w.startswith(("-c", "--config-env", "--exec-path")) for w in words[1:]):
        return f"{base}/{WILD}"
    if not _is_word(bin_):
        return f"{base}/{WILD}"
    parts = [bin_]
    if bin_ in SUBCOMMAND_BINS:
        args = words[1:]
        if bin_ == "git" and len(args) >= 3 and args[0] == "-C":
            args = args[2:]
        if not args or args[0].startswith("-"):
            return f"{base}/{WILD}"
        sub = args[0] if _is_word(args[0]) else None
        if sub:
            parts.append(sub)
            if (bin_, sub) in TWO_LEVEL:
                rest = _skip_flags(args[1:], *LEVEL_FLAGS.get((bin_, sub), (set(), set())))
                if rest is None or not rest or not _is_word(rest[0]):
                    return f"{base}/{WILD}"
                parts.append(rest[0])
    return f"{base}/" + "/".join(parts)


def _skip_flags(args: list[str], value_flags: set[str], bool_flags: set[str]) -> list[str] | None:
    """Drop leading known flags (and their values); None when an unknown flag is in the way."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        flag, eq, _ = args[i].partition("=")
        if flag in value_flags:
            i += 1 if eq else 2  # --file=x is one token; -f x is two
        elif flag in bool_flags and not eq:
            i += 1
        else:
            return None
    return args[i:]


def _is_word(w: str) -> bool:
    return bool(w) and all(c.isalnum() or c in "_.-+:" for c in w)


def classify_mcp(server: str, tool: str, arguments: dict[str, Any] | None, keys: list[str] | None) -> list[str]:
    """Permission paths for one upstream MCP call.

    `keys` are dotted paths into the arguments the resource owner cares about (`service`,
    `data.entity_id`). Each key present in the call adds `mcp/<server>/tools/<tool>/<key>=<value>`;
    a list value adds one path per element. Every path must be allowed, so a tool-level grant
    (literal prefix) covers everything and a deny on one qualifier blocks just that value.
    With no keys configured, or none present in the call, the bare tool path is required.
    """
    base = f"mcp/{server}/tools/{tool}"
    paths: list[str] = []
    for key in keys or []:
        value = _lookup(arguments or {}, key)
        if value is None:
            continue
        values = value if isinstance(value, list) else [value]
        for v in values:
            if isinstance(v, (dict, list)):
                continue
            q = f"{base}/{qualifier(key, v)}"
            if q not in paths:
                paths.append(q)
    return paths or [base]


def _lookup(arguments: dict[str, Any], key: str) -> Any:
    cur: Any = arguments
    for part in key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur
