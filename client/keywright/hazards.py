"""Destructive-operation tripwire.

Classification says WHAT a command is (`rm`, `docker/compose/down`); this says whether a human
must look at it fresh. It runs on every SSH operation before policy is consulted, so a standing
rule or a one-hour grant never lets `rm -rf /home` through unseen.

Severities:
  critical  refused. Keywright never runs it; the human can do it by hand over real SSH.
  high      always a fresh prompt, approved once and exactly, whatever grants or rules exist.
  medium    runs under existing access; the prompt, the result and the audit row carry the flag.

Two passes over a command line. The structured pass tokenizes it, strips `sudo`/`env`/`timeout`
wrappers, follows `bash -c`, `ssh host ...`, `xargs` and `find -delete`, and tracks `cd` so
`cd /home/x && rm -rf .` is seen for what it is. The lexical pass scans the raw text for shapes
the structured pass cannot reach: `python -c "shutil.rmtree('/')"`, heredocs, quoted scripts.

This is a tripwire, not a sandbox. It reads the command line, not what runs. Code executed by a
test runner or interpreter is invisible to it, which is why Keywright keeps credentials off the
agent's machine in the first place.

Stdlib only, no package imports: the file runs standalone as a Claude Code PreToolUse hook
(`python3 hazards.py --hook`) on a machine that has no Keywright installed.
"""

from __future__ import annotations

import fnmatch
import json
import posixpath
import re
import shlex
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

SEVERITIES = ("medium", "high", "critical")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Hazard:
    severity: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {"severity": self.severity, "reason": self.reason}


def worst(hazards: Iterable[Hazard | dict[str, Any]] | None) -> str | None:
    """The highest severity present, or None."""
    top: str | None = None
    for h in hazards or ():
        s = h.severity if isinstance(h, Hazard) else str(h.get("severity", ""))
        if s in _RANK and (top is None or _RANK[s] > _RANK[top]):
            top = s
    return top


def blocks(level: str | None) -> bool:
    """Whether this level overrides standing access (needs a fresh once-only approval or is refused)."""
    return level in ("high", "critical")


def describe(hazards: Iterable[Hazard | dict[str, Any]] | None) -> str:
    parts = []
    for h in hazards or ():
        d = h.as_dict() if isinstance(h, Hazard) else h
        parts.append(f"{d.get('severity')}: {d.get('reason')}")
    return "; ".join(parts)


# ---- operation entry point ----------------------------------------------------------------------
def scan(operation: dict[str, Any]) -> list[Hazard]:
    """Hazards for one SSH operation dict as Keywright builds it (run, put, get, capture)."""
    out = _Sink()
    if operation.get("command"):
        for h in scan_command(str(operation["command"])):
            out.add(h.severity, h.reason)
    if operation.get("to_path"):
        for h in scan_path(str(operation["to_path"]), "write"):
            out.add(h.severity, h.reason)
    elif "sha256" in operation and operation.get("path"):
        for h in scan_path(str(operation["path"]), "write"):
            out.add(h.severity, h.reason)
    elif operation.get("path"):
        for h in scan_path(str(operation["path"]), "read"):
            out.add(h.severity, h.reason)
    return out.items


# ---- brokered MCP tools -------------------------------------------------------------------------
# A tool's name is the only thing Keywright can read about what it does; the owner's catalog is the
# rest. Names say medium at most: only the owner knows whether `reset` means a counter or a device.
_DESTRUCTIVE_WORDS = frozenset((
    "delete", "remove", "destroy", "purge", "wipe", "erase", "reset", "restart", "reboot", "shutdown",
    "poweroff", "format", "uninstall", "revoke", "drop", "kill", "terminate", "factory",
))
_WORD_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


def scan_mcp(tool: str, paths: Iterable[str], catalog: dict[str, list[str]] | None = None) -> list[Hazard]:
    """Hazards for one brokered MCP call. `paths` are the call's classified paths relative to the
    resource (`tools/<tool>[/<key>=<value>]`, so qualifiers appear only for configured argument
    keys); `catalog` is the owner's {severity: [entry, ...]} in bundle syntax, an entry matching a
    path when its segments glob-match the path's leading segments."""
    out = _Sink()
    hits = sorted({w.lower() for w in _WORD_SPLIT.split(tool) if w} & _DESTRUCTIVE_WORDS)
    if hits:
        out.add("medium", f"tool name suggests a destructive action ({', '.join(hits)})")
    paths = [p.strip("/") for p in paths]
    for severity, entries in (catalog or {}).items():
        if severity not in _RANK:
            continue
        for entry in entries:
            if any(_entry_matches(entry, p) for p in paths):
                out.add(severity, f"listed as {severity} for this server ({entry})")
    return out.items


def _entry_matches(entry: str, path: str) -> bool:
    e, p = entry.strip("/").split("/"), path.split("/")
    return len(e) <= len(p) and all(fnmatch.fnmatchcase(pp, ee) for ee, pp in zip(e, p))


def as_dicts(hazards: Iterable[Hazard]) -> list[dict[str, str]]:
    return [h.as_dict() for h in hazards]


class _Sink:
    def __init__(self, cap: str | None = None):
        self.items: list[Hazard] = []
        self.cap = cap

    def add(self, severity: str, reason: str) -> None:
        if self.cap and _RANK[severity] > _RANK[self.cap]:
            severity = self.cap
        h = Hazard(severity, reason)
        if h not in self.items:
            self.items.append(h)

    def add_weak(self, severity: str, reason: str) -> None:
        """A lexical finding: dropped when the structured pass already reported the same thing,
        possibly with more context ("(inside ssh) ...", "... (from .)")."""
        if any(reason in h.reason for h in self.items):
            return
        self.add(severity, reason)


# ---- paths --------------------------------------------------------------------------------------
# (globs, reason) per group. fnmatch's `*` crosses `/`, so `*/.ssh/*` matches any depth.
_KEY_MATERIAL = (["*/.ssh", "*/.ssh/*", "*/.gnupg", "*/.gnupg/*", "/etc/ssh/ssh_host_*"],
                 "SSH/GPG key material")
_ACCOUNTS = (["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/subuid", "/etc/subgid"],
             "the account database")
_PRIVILEGE = (["/etc/sudoers", "/etc/sudoers.d/*", "/etc/pam.d/*", "/etc/nsswitch.conf", "/etc/ld.so.preload"],
              "login and privilege configuration")
_BOOT = (["/etc/fstab", "/etc/crypttab", "/boot/*", "/etc/default/grub", "/etc/grub.d/*"], "boot configuration")
_SSHD = (["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*"], "the SSH server configuration")
_STARTUP = (["/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/zsh/*", "*/.bashrc", "*/.bash_profile",
             "*/.profile", "*/.zshrc", "*/.zprofile", "*/.config/fish/config.fish", "/etc/crontab", "/etc/cron.d/*",
             "/etc/cron.hourly/*", "/etc/cron.daily/*", "/var/spool/cron/*", "/etc/rc.local", "/etc/environment"],
            "code that runs at login or on a schedule")
_SECRETS_READ = (["/etc/shadow", "/etc/gshadow", "*/.ssh/id_*", "*/.gnupg/*", "/etc/ssh/ssh_host_*_key",
                  "*/.aws/credentials", "*/.netrc", "*/.docker/config.json", "*/.kube/config"],
                 "private key material or password hashes")
_PUBLIC_KEY = re.compile(r"\.pub$")

_TOP_DIRS = {"bin", "boot", "dev", "etc", "home", "lib", "lib32", "lib64", "libx32", "opt", "proc", "root",
             "sbin", "srv", "sys", "usr", "var", "snap", "nix"}
_CRITICAL_GLOB_PARENTS = {"etc", "usr", "var", "boot", "bin", "sbin", "lib", "lib32", "lib64", "root", "dev", "proc",
                          "sys"}
_HIGH_GLOB_PARENTS = {"opt", "srv", "tmp", "mnt", "media", "run", "snap", "var/lib", "var/log", "usr/local",
                      "var/backups", "var/mail", "var/www"}
_HOME = re.compile(r"^(~[A-Za-z0-9_.-]*|\$HOME|\$\{HOME\}|%h)(?=/|$)")
_GLOB = re.compile(r"[*?\[]")
_DEVICE = re.compile(r"^/dev/(sd|nvme|vd|hd|xvd|md|mapper/|dm-|zvol/|disk/|mmcblk|loop\d|nbd|rbd|drbd|sr\d)")


def _norm(raw: str, cwd: str | None) -> str | None:
    """Normalize a path token. `~`, `$HOME` and friends become `~`. Relative paths resolve against
    `cwd` when a `cd` earlier in the line set it; otherwise None (unknown)."""
    p = raw.strip()
    if not p:
        return None
    p = _HOME.sub("~", p)
    if p.startswith("~"):
        rest = posixpath.normpath(p[1:] or "/")
        return "~" if rest in ("/", ".") else "~" + rest
    if p.startswith("/"):
        return re.sub(r"^/+", "/", posixpath.normpath(p))
    if cwd is None:
        return None
    if cwd.startswith("~"):
        joined = posixpath.normpath(posixpath.join(cwd[1:] or "/", p))
        if joined.startswith("/.."):
            return "/home"  # above the home directory: the parent of all homes
        return "~" if joined in ("/", ".") else "~" + joined
    return re.sub(r"^/+", "/", posixpath.normpath(posixpath.join(cwd, p)))


def _matches(path: str, globs: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, g) for g in globs)


def _system_scope(p: str) -> str | None:
    """'critical' for the filesystem root, any top-level directory, a home directory or their
    wildcard contents; 'high' for the contents of shared directories like /opt or /var/lib."""
    if p in ("/", "/*", "/.*", "/.", "/..", "~", "~/*", "~/.*", "~/."):
        return "critical"
    if p.startswith("~"):
        parts = p[2:].split("/") if len(p) > 2 else []
        return "critical" if len(parts) == 1 and _GLOB.search(parts[0]) else None
    parts = p.strip("/").split("/")
    if len(parts) == 1:
        # /etc, /ho*, /*; a top-level directory the distribution did not create is high
        return "critical" if parts[0] in _TOP_DIRS or _GLOB.search(parts[0]) else "high"
    if parts[0] == "home":
        if len(parts) == 2 or (len(parts) == 3 and _GLOB.search(parts[2])):
            return "critical"
        return None
    if len(parts) == 2 and _GLOB.search(parts[1]):
        if parts[0] in _CRITICAL_GLOB_PARENTS:
            return "critical"
        if parts[0] in _HIGH_GLOB_PARENTS:
            return "high"
    if len(parts) == 2 and "/".join(parts) in _HIGH_GLOB_PARENTS:
        return "high"
    # wiping the contents of a shared directory a few levels down (/var/lib/docker/*, /opt/app/*)
    if 3 <= len(parts) <= 4 and _GLOB.search(parts[-1]) and (
            "/".join(parts[:2]) in _HIGH_GLOB_PARENTS or parts[0] in _HIGH_GLOB_PARENTS - {"tmp", "run"}):
        return "high"
    return None


def _perm_scope(p: str) -> str | None:
    """Recursive chmod/chown: critical on the root or a system directory, high on a home directory
    or shared contents (chown -R on a home is a routine fix that still deserves a fresh look)."""
    scope = _system_scope(p)
    if scope != "critical":
        return scope
    parts = p.strip("/").split("/")
    if p.startswith("~") or parts[0] == "home" and len(parts) > 1 or parts[0] == "root":
        return "high"
    return "critical"


def scan_path(path: str, mode: str) -> list[Hazard]:
    """Hazards of writing to, reading or deleting one path. mode: write | read | delete."""
    out = _Sink()
    p = _norm(path, None) or path
    if mode == "read":
        if _matches(p, _SECRETS_READ[0]) and not _PUBLIC_KEY.search(p):
            out.add("high", f"reads {_SECRETS_READ[1]} ({p})")
        return out.items
    verb = "deletes" if mode == "delete" else "overwrites"
    for globs, what in (_KEY_MATERIAL, _ACCOUNTS, _PRIVILEGE, _BOOT, _SSHD):
        if _matches(p, globs):
            out.add("critical" if mode == "delete" else "high", f"{verb} {what} ({p})")
    if _matches(p, _STARTUP[0]):
        out.add("high", f"{verb} {_STARTUP[1]} ({p})")
    if mode == "write" and _DEVICE.match(p):
        out.add("high", f"writes raw bytes to block device {p}")
    return out.items


def _delete_target(raw: str, cwd: str | None, recursive: bool, how: str, out: _Sink, weak: bool = False) -> None:
    """`how` reads like "recursive delete of" or "find -delete under"."""
    add = out.add_weak if weak else out.add
    if not raw or raw in ("+", ";", "{}", "$", "\\;"):
        return
    p = _norm(raw, cwd)
    if p is not None:
        specific = scan_path(p, "delete")
        for h in specific:
            add(h.severity, h.reason)
        if specific:
            return
    if not recursive:
        return
    if p is None:
        if raw in (".", "..", "*", "./", "./*", "../*", ".*", "./.*"):
            add("high", f"{how} the working directory ({raw}), location unknown")
        else:
            add("medium", f"{how} {raw}")
        return
    scope = _system_scope(p)
    if scope:
        add(scope, f"{how} {p}" + (f" (from {raw})" if p != raw else ""))
    else:
        add("medium", f"{how} {p}")


# ---- commands -----------------------------------------------------------------------------------
_SEPARATORS = {";", "|", "||", "&&", "&", "(", ")", "{", "}", "|&"}
_PUNCT = ";|&()<>"
_KEYWORDS = {"{", "}", "(", ")", "!", "if", "then", "else", "elif", "fi", "while", "until", "do", "done", "case",
             "esac", "in", "function", "time"}
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
_WRAPPERS = {"sudo", "doas", "busybox", "env", "nice", "ionice", "nohup", "time", "command", "builtin", "stdbuf", "timeout",
             "exec", "nocorrect", "noglob"}
_SUDO_VALUE_FLAGS = {"-u", "-g", "-h", "-p", "-r", "-t", "-U", "-C", "-D", "-R", "-T", "--user", "--group", "--host",
                     "--prompt", "--role", "--type", "--other-user", "--close-from", "--chdir", "--chroot"}
_WRAPPER_VALUE_FLAGS = {"-n", "-c", "-k", "-s", "-u", "-o", "-e", "-i", "-p", "-C", "-S", "--kill-after", "--signal",
                        "--adjustment", "--class", "--classdata", "--output", "--error", "--input", "--chdir",
                        "--split-string"}
_REMOTE = {"ssh", "pct", "docker", "podman", "qm", "kubectl", "lxc", "machinectl", "incus", "nsenter", "chroot"}
_FIND_DELETE = {"-delete"}
_FIND_EXEC = {"-exec", "-execdir", "-ok", "-okdir"}
_DELETERS = {"rm", "rmdir", "unlink", "shred", "srm"}
_FORMATTERS = re.compile(r"^(mkfs(\.\w+)?|mke2fs|mkswap|mkfs_\w+|wipefs|blkdiscard|sgdisk|sfdisk|fdisk|cfdisk|parted|"
                         r"gdisk|zerofree|nvme|hdparm|badblocks)$")
_POWER = {"reboot", "poweroff", "halt", "shutdown", "telinit"}
_FLUSHERS = {"flushall", "flushdb"}


def scan_command(command: str) -> list[Hazard]:
    out = _Sink()
    _structured(command, out, depth=0)
    _lexical(command, out)
    return out.items


def _tokens(command: str) -> list[str] | None:
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=_PUNCT)
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        return None


def _segments(tokens: list[str]) -> list[list[str]]:
    segs: list[list[str]] = [[]]
    for tok in tokens:
        if tok in _SEPARATORS:
            if segs[-1]:
                segs.append([])
            continue
        if tok.startswith(("<", ">")) and set(tok) <= set("<>&|"):
            # a redirection operator; the target that follows is data for the lexical pass
            segs[-1].append(tok)
            continue
        segs[-1].append(tok)
    return [s for s in segs if s]


def _structured(command: str, out: _Sink, depth: int, cwd: str | None = None) -> None:
    if depth > 4:
        return
    tokens = _tokens(command)
    if not tokens:
        return
    for seg in _segments(tokens):
        words = _strip_redirections(seg)
        while words and words[0] in _KEYWORDS:
            words = words[1:]
        words = _unwrap(words)
        if not words:
            continue
        bin_ = words[0].rsplit("/", 1)[-1]
        args = words[1:]
        if bin_ in ("cd", "pushd"):
            cwd = _norm(args[0], cwd) if args and not args[0].startswith("-") else "~"
            continue
        _check(bin_, args, cwd, out, depth)


def _strip_redirections(words: list[str]) -> list[str]:
    kept: list[str] = []
    skip = False
    for w in words:
        if skip:
            skip = False
            continue
        if w and set(w) <= set("<>&|") and ("<" in w or ">" in w):
            skip = True  # drop the operator and its target (tokenized as separate words)
            continue
        kept.append(w)
    return kept


def _unwrap(words: list[str]) -> list[str]:
    """Strip privilege and environment wrappers so `sudo -u root rm -rf /` is seen as `rm`."""
    while words:
        head = words[0].rsplit("/", 1)[-1]
        if "=" in words[0] and not words[0].startswith("-"):
            words = words[1:]
            continue
        if head not in _WRAPPERS:
            return words
        rest = words[1:]
        value_flags = _SUDO_VALUE_FLAGS if head in ("sudo", "doas") else _WRAPPER_VALUE_FLAGS
        while rest and rest[0].startswith("-") and rest[0] != "--":
            flag = rest[0]
            rest = rest[1:]
            if flag in value_flags and rest:
                rest = rest[1:]
        if rest and rest[0] == "--":
            rest = rest[1:]
        if head == "timeout" and rest:
            rest = rest[1:]  # the duration
        if head == "env":
            while rest and "=" in rest[0]:
                rest = rest[1:]
        words = rest
    return words


def _flags_and_targets(args: list[str]) -> tuple[list[str], list[str]]:
    flags, targets = [], []
    end_of_flags = False
    for a in args:
        if end_of_flags:
            targets.append(a)
        elif a == "--":
            end_of_flags = True
        elif a.startswith("-") and len(a) > 1:
            flags.append(a)
        else:
            targets.append(a)
    return flags, targets


def _short_has(flags: list[str], letters: str, long: tuple[str, ...] = ()) -> bool:
    for f in flags:
        if f in long:
            return True
        if f.startswith("-") and not f.startswith("--") and any(c in letters for c in f[1:]):
            return True
    return False


def _check(bin_: str, args: list[str], cwd: str | None, out: _Sink, depth: int) -> None:
    # --- things that run another command line ---
    if bin_ in _SHELLS:
        for i, a in enumerate(args):
            if a in ("-c", "-lc", "-ec", "-xc") and i + 1 < len(args):
                _structured(args[i + 1], out, depth + 1, cwd)
                return
            if a.startswith("-") and "c" in a and not a.startswith("--") and i + 1 < len(args):
                _structured(args[i + 1], out, depth + 1, cwd)
                return
        return
    if bin_ == "su":
        for i, a in enumerate(args):
            if a in ("-c", "--command") and i + 1 < len(args):
                _structured(args[i + 1], out, depth + 1, None)
        return
    if bin_ == "eval":
        _structured(" ".join(args), out, depth + 1, cwd)
        return
    if bin_ == "xargs":
        rest = list(args)
        while rest and rest[0].startswith("-"):
            flag = rest[0]
            rest = rest[1:]
            if flag in ("-n", "-P", "-d", "-I", "-L", "-s", "-a", "-E", "--max-args", "--max-procs", "--delimiter",
                        "--replace", "--max-lines", "--max-chars", "--arg-file", "--eof") and rest:
                rest = rest[1:]
        cmd = _unwrap(rest)
        if cmd:
            inner = _Sink()
            _check(cmd[0].rsplit("/", 1)[-1], cmd[1:], None, inner, depth + 1)
            for h in inner.items:
                out.add(h.severity, h.reason)
            head = cmd[0].rsplit("/", 1)[-1]
            if head in _DELETERS:
                recursive = _short_has([a for a in cmd[1:] if a.startswith("-")], "rR", ("--recursive",))
                out.add("high" if recursive else "medium",
                        f"xargs {head}{' -r' if recursive else ''}: deletes whatever the input names")
        return
    if bin_ in _REMOTE:
        _remote(bin_, args, out, depth)
        # fall through: the outer command itself may also be hazardous (docker rm, pct destroy)
    # --- deletion ---
    if bin_ in ("rm", "srm"):
        flags, targets = _flags_and_targets(args)
        recursive = _short_has(flags, "rR", ("--recursive",))
        if "--no-preserve-root" in flags:
            out.add("critical", "rm --no-preserve-root")
        for t in targets:
            _delete_target(t, cwd, recursive, "recursive delete of" if recursive else "delete of", out)
        return
    if bin_ in ("unlink", "rmdir"):
        for t in _flags_and_targets(args)[1]:
            _delete_target(t, cwd, False, "delete of", out)
        return
    if bin_ == "shred":
        for t in _flags_and_targets(args)[1]:
            p = _norm(t, cwd) or t
            out.add("high" if _DEVICE.match(p) else "medium", f"shreds {p}")
            _delete_target(t, cwd, False, "shreds", out)
        return
    if bin_ == "find":
        _find(args, cwd, out)
        return
    if bin_ in ("chmod", "chown", "chgrp"):
        flags, targets = _flags_and_targets(args)
        if _short_has(flags, "R", ("--recursive",)):
            for t in targets[1:]:
                p = _norm(t, cwd)
                scope = _perm_scope(p) if p else None
                if scope:
                    out.add(scope, f"recursive {bin_} of {p}")
        return
    if bin_ == "mv":
        flags, targets = _flags_and_targets(args)
        for t in targets[:-1]:
            p = _norm(t, cwd)
            scope = _system_scope(p) if p else None
            if scope:
                out.add(scope, f"moves {p} away")
            if p:
                for h in scan_path(p, "delete"):
                    out.add(h.severity, h.reason.replace("deletes", "moves"))
        if targets:
            _write_target(targets[-1], cwd, out)
        return
    if bin_ in ("tee", "install", "truncate", "ln"):
        flags, targets = _flags_and_targets(args)
        if bin_ == "tee" or bin_ == "truncate":
            for t in targets:
                _write_target(t, cwd, out)
        elif targets:
            _write_target(targets[-1], cwd, out)
        return
    if bin_ == "dd":
        for a in args:
            if a.startswith("of="):
                _write_target(a[3:], cwd, out)
            elif a.startswith("if="):
                _read_target(a[3:], cwd, out)
        return
    if bin_ in ("cat", "head", "tail", "less", "more", "base64", "xxd", "od", "strings", "grep", "cp", "scp", "rsync",
                "tar", "zip", "gzip", "curl", "wget", "nc", "ncat"):
        for t in _flags_and_targets(args)[1]:
            _read_target(t.split(":", 1)[-1] if bin_ in ("scp", "rsync") and ":" in t else t, cwd, out)
        flags, targets = _flags_and_targets(args)
        if bin_ in ("cp", "scp", "rsync") and targets:
            _write_target(targets[-1], cwd, out)
        if bin_ == "rsync" and any(f.startswith("--delete") for f in flags) and targets:
            p = _norm(targets[-1], cwd)
            scope = _system_scope(p) if p else None
            out.add(scope or "medium", f"rsync --delete into {p or targets[-1]}")
        return
    if _FORMATTERS.match(bin_):
        flags, targets = _flags_and_targets(args)
        listing = any(f in ("-l", "--list", "-p", "--print", "-s", "-i") for f in flags) or "print" in targets
        if bin_ in ("nvme", "hdparm"):
            if any(t in ("format", "sanitize") for t in targets) or "--security-erase" in flags:
                out.add("high", f"{bin_} erases {targets[-1] if targets else 'a device'}")
            return
        if bin_ == "badblocks" and not _short_has(flags, "w"):
            return
        if listing and bin_ in ("fdisk", "sfdisk", "sgdisk", "parted", "gdisk", "cfdisk", "wipefs"):
            return
        # A formatter's device is the last positional, or whichever positional names a device or a
        # variable; label values like `-L ncdata` must not be reported as victims.
        victims = [t for t in targets if _DEVICE.match(_norm(t, cwd) or t) or t.startswith("$")]
        if not victims and targets and bin_.startswith("mk"):
            victims = [targets[-1]]
        for t in victims:
            out.add("high", f"{bin_} destroys the contents of {t}")
        return
    if bin_ == "cryptsetup":
        if any(a in ("luksFormat", "erase", "luksErase", "reencrypt") for a in args):
            out.add("high", f"cryptsetup {next(a for a in args if not a.startswith('-'))} on {args[-1]}")
        return
    # --- virtualization, storage, containers ---
    sub = next((a for a in args if not a.startswith("-")), None)
    sub2 = next((a for a in args[args.index(sub) + 1:] if not a.startswith("-")), None) if sub else None
    if bin_ in ("qm", "pct"):
        if sub == "destroy":
            out.add("high", f"{bin_} destroy {sub2 or ''}: deletes a guest and its disks".strip())
        elif sub in ("delsnapshot", "disk") and (sub != "disk" or sub2 == "unlink"):
            out.add("medium", f"{bin_} {sub} {' '.join(args[1:3])}".strip())
        elif sub in ("stop", "reset") and bin_ == "qm":
            out.add("medium", f"{bin_} {sub} {sub2 or ''}: hard power-off".strip())
        return
    if bin_ == "pvesm" and sub in ("free", "remove"):
        out.add("high", f"pvesm {sub} {sub2 or ''}".strip())
        return
    if bin_ == "vzdump":
        return
    if bin_ == "zpool" and sub in ("destroy", "labelclear"):
        out.add("high", f"zpool {sub} {sub2 or ''}: destroys a whole pool".strip())
        return
    if bin_ == "zfs" and sub in ("destroy",):
        flags, targets = _flags_and_targets(args[1:])
        what = targets[0] if targets else ""
        children = " and every child dataset/snapshot" if _short_has(flags, "rR") else ""
        out.add("high", f"zfs destroy {what}{children}".strip())
        return
    if bin_ in ("lvremove", "vgremove", "pvremove") or (bin_ == "lvm" and sub in ("lvremove", "vgremove", "pvremove")):
        out.add("high", f"{bin_} {' '.join(a for a in args if not a.startswith('-'))}".strip())
        return
    if bin_ == "rbd" and sub in ("rm", "remove", "trash") or bin_ == "rados" and sub in ("rmpool", "purge"):
        out.add("high", f"{bin_} {sub} {sub2 or ''}".strip())
        return
    if bin_ == "ceph" and sub in ("osd", "fs", "mon", "mgr") and sub2 in ("purge", "destroy", "rm", "remove", "pool"):
        if sub2 == "pool" and not any(a in ("delete", "rm") for a in args):
            return
        out.add("high", f"ceph {sub} {sub2} {' '.join(args[2:5])}".strip())
        return
    if bin_ == "virsh" and sub == "undefine":
        out.add("high" if any("storage" in a for a in args) else "medium", f"virsh undefine {sub2 or ''}".strip())
        return
    if bin_ in ("docker", "podman", "nerdctl"):
        _docker(bin_, args, out)
        return
    if bin_ == "kubectl" and sub == "delete":
        out.add("high" if any(a in ("--all", "-A", "--all-namespaces") or a.startswith("ns") or a == "namespace"
                              for a in args) else "medium", f"kubectl delete {' '.join(args[1:4])}".strip())
        return
    if bin_ == "git":
        _git(args, out)
        return
    # --- databases ---
    if bin_ in ("dropdb", "dropuser"):
        out.add("high", f"{bin_} {' '.join(a for a in args if not a.startswith('-'))}".strip())
        return
    if bin_ == "redis-cli" and any(a.lower() in _FLUSHERS for a in args):
        out.add("high", "redis flushes every key")
        return
    # --- host ---
    if bin_ in _POWER:
        if bin_ == "shutdown" and ("-c" in args or "--cancel" in args):
            return
        out.add("high", f"{bin_}: reboots or powers off the host")
        return
    if bin_ == "init" and args and args[0] in ("0", "6"):
        out.add("high", "init 0/6: reboots or powers off the host")
        return
    if bin_ == "systemctl":
        if sub in ("reboot", "poweroff", "halt", "kexec", "emergency", "rescue", "suspend", "hibernate"):
            out.add("high", f"systemctl {sub}: takes the host down")
        elif sub in ("stop", "disable", "mask") and any(re.match(r"^(ssh|sshd|networking|NetworkManager|systemd-networkd|"
                                                                 r"tailscaled|pve-cluster|pvedaemon|pveproxy)(\.service)?$", a)
                                                        for a in args[1:]):
            out.add("high", f"systemctl {sub} {' '.join(args[1:3])}: cuts remote access".strip())
        return
    if bin_ in ("kill", "pkill", "killall", "killall5"):
        if bin_ == "killall5" or "-1" in args or any(a in ("-r", "--regexp") for a in args) and "." in args:
            out.add("high", f"{bin_}: kills every process")
        elif bin_ in ("pkill", "killall") and any(re.match(r"^(sshd|ssh|init|systemd|pve\w*)$", a) for a in args):
            out.add("high", f"{bin_} {' '.join(a for a in args if not a.startswith('-'))}: cuts remote access")
        return
    if bin_ in ("iptables", "ip6tables", "nft", "ufw", "firewall-cmd"):
        if _short_has([a for a in args if a.startswith("-")], "FX", ("--flush", "--delete-chain")) and bin_.endswith("tables") \
                or bin_ == "nft" and "flush" in args and "ruleset" in args \
                or bin_ == "ufw" and sub in ("reset", "disable") \
                or bin_ == "firewall-cmd" and any(a in ("--panic-on", "--complete-reload") for a in args):
            out.add("high", f"{bin_} {' '.join(args[:2])}: drops the firewall".strip())
        return
    if bin_ in ("ip", "ifdown", "ifconfig", "nmcli"):
        if bin_ == "ifdown" or (bin_ == "ip" and sub in ("link", "addr", "address") and any(
                a in ("down", "flush", "del", "delete") for a in args)) \
                or (bin_ == "ifconfig" and "down" in args) or (bin_ == "nmcli" and any(a in ("down", "delete") for a in args)):
            out.add("high", f"{bin_} {' '.join(args[:4])}: may drop the network".strip())
        return
    if bin_ in ("userdel", "deluser", "groupdel"):
        rm = _short_has([a for a in args if a.startswith("-")], "r", ("--remove", "--remove-home", "--remove-all-files"))
        out.add("high" if rm else "medium", f"{bin_} {' '.join(a for a in args if not a.startswith('-'))}"
                + (" and their files" if rm else ""))
        return
    if bin_ == "passwd" and args and (args[0] in ("-d", "-l", "--delete", "--lock") or "root" in args):
        out.add("high", f"passwd {' '.join(args)}: changes a login")
        return
    if bin_ == "crontab" and "-r" in args:
        out.add("high", "crontab -r: deletes every scheduled job")
        return
    if bin_ in ("apt", "apt-get", "dnf", "yum", "pacman", "apk", "zypper") and sub in ("remove", "purge", "autoremove",
                                                                                          "erase", "del", "-R", "-Rs", "-Rns"):
        if any(re.match(r"^(openssh|ssh|sudo|systemd|linux-image|grub|pve-|proxmox|qemu-server|libc6|bash|coreutils)", a)
               for a in args[1:]):
            out.add("high", f"{bin_} {sub} {' '.join(a for a in args[1:] if not a.startswith('-'))}: removes a package "
                            "the host needs to stay reachable")
        return
    if bin_ == "history" and "-c" in args:
        out.add("medium", "history -c")
        return


def _read_target(raw: str, cwd: str | None, out: _Sink) -> None:
    p = _norm(raw, cwd)
    if p is None:
        return
    for h in scan_path(p, "read"):
        out.add(h.severity, h.reason)


def _write_target(raw: str, cwd: str | None, out: _Sink) -> None:
    p = _norm(raw, cwd)
    if p is None:
        return
    for h in scan_path(p, "write"):
        out.add(h.severity, h.reason)


def _find(args: list[str], cwd: str | None, out: _Sink) -> None:
    starts: list[str] = []
    i = 0
    while i < len(args) and args[i] in ("-H", "-L", "-P", "-O0", "-O1", "-O2", "-O3"):
        i += 1
    if i < len(args) and args[i] == "-D":
        i += 2
    while i < len(args) and not args[i].startswith(("-", "(", "!")):
        starts.append(args[i])
        i += 1
    deleting = any(a in _FIND_DELETE for a in args)
    recursive_rm = False
    for j, a in enumerate(args):
        if a in _FIND_EXEC and j + 1 < len(args):
            cmd = _unwrap(args[j + 1:])
            if cmd and cmd[0].rsplit("/", 1)[-1] in _DELETERS:
                deleting = True
                recursive_rm = recursive_rm or _short_has([x for x in cmd[1:] if x.startswith("-")], "rR",
                                                          ("--recursive",))
    if not deleting:
        return
    for s in starts or ["."]:
        _delete_target(s, cwd, True, "find -delete under", out)


def _remote(bin_: str, args: list[str], out: _Sink, depth: int) -> None:
    """A command line run somewhere else: inside a container, guest or another host. Reported at
    full severity with a prefix: a wiped guest is still a wiped machine."""
    inner = _Sink()
    if bin_ == "ssh":
        # skip options and the host
        i = 0
        while i < len(args) and args[i].startswith("-"):
            i += 2 if args[i] in ("-i", "-l", "-p", "-o", "-F", "-J", "-L", "-R", "-D", "-W", "-b", "-c", "-E",
                                  "-I", "-m", "-O", "-Q", "-S", "-w", "-B") else 1
        i += 1
        if i < len(args):
            _structured(" ".join(args[i:]), inner, depth + 1)
    elif bin_ in ("pct", "docker", "podman", "lxc", "incus", "machinectl", "kubectl", "nsenter", "chroot", "qm"):
        if "--" in args:
            _structured(" ".join(args[args.index("--") + 1:]), inner, depth + 1)
        elif bin_ in ("nsenter", "chroot"):
            rest = [a for a in args if not a.startswith("-")]
            if bin_ == "chroot":
                rest = rest[1:]
            if rest:
                _structured(" ".join(rest), inner, depth + 1)
        elif args and args[0] in ("exec", "shell", "run") and bin_ != "qm":
            rest = args[1:]
            while rest and rest[0].startswith("-"):
                rest = rest[2:] if rest[0] in ("-u", "-w", "-e", "--user", "--workdir", "--env", "-n", "--namespace") else rest[1:]
            if len(rest) > 1:
                _structured(" ".join(rest[1:]), inner, depth + 1)
    for h in inner.items:
        out.add(h.severity, f"(inside {bin_}) {h.reason}")


def _docker(bin_: str, args: list[str], out: _Sink) -> None:
    words = [a for a in args if not a.startswith("-")]
    flags = [a for a in args if a.startswith("-")]
    if not words:
        return
    sub = words[0]
    sub2 = words[1] if len(words) > 1 else ""
    if sub == "system" and sub2 == "prune":
        out.add("high", f"{bin_} system prune" + (" including volumes" if "--volumes" in flags else ""))
    elif sub == "volume" and sub2 in ("rm", "remove", "prune"):
        out.add("high", f"{bin_} volume {sub2} {' '.join(words[2:5])}: deletes persistent data".strip())
    elif sub == "compose" and "down" in words and (_short_has(flags, "v", ("--volumes",))):
        out.add("high", f"{bin_} compose down -v: deletes the stack's volumes")
    elif sub in ("rm", "container") and (sub == "rm" or sub2 in ("rm", "prune")):
        forced = _short_has(flags, "f", ("--force",))
        out.add("medium", f"{bin_} {sub} {sub2 if sub == 'container' else ''} {' '.join(flags)}".replace("  ", " ").strip()
                + (": removes running containers" if forced else ""))
    elif sub in ("rmi", "image") and (sub == "rmi" or sub2 in ("rm", "prune")):
        if _short_has(flags, "a", ("--all",)) or _short_has(flags, "f", ("--force",)):
            out.add("medium", f"{bin_} {sub} {sub2 if sub == 'image' else ''} {' '.join(flags)}".replace("  ", " ").strip())
    elif sub == "network" and sub2 == "prune":
        out.add("medium", f"{bin_} network prune")
    elif sub == "swarm" and sub2 == "leave" and _short_has(flags, "f", ("--force",)):
        out.add("high", f"{bin_} swarm leave --force")
    elif sub == "stack" and sub2 in ("rm", "remove"):
        out.add("medium", f"{bin_} stack rm {' '.join(words[2:4])}".strip())


def _git(args: list[str], out: _Sink) -> None:
    words = [a for a in args if not a.startswith("-")]
    flags = [a for a in args if a.startswith("-")]
    if words and words[0] == "-C":
        words = words[2:]
    if not words:
        return
    sub = words[0]
    if sub == "push":
        if "--force" in flags or _short_has(flags, "f") or any(w.startswith("+") for w in words[1:]):
            out.add("high", "git push --force")
        elif any(f.startswith("--force-with-lease") for f in flags) or "--delete" in flags or _short_has(flags, "d"):
            out.add("medium", "git push " + " ".join(flags))
    elif sub == "reset" and "--hard" in flags:
        out.add("high", "git reset --hard")
    elif sub == "clean":
        if _short_has(flags, "f", ("--force",)) and _short_has(flags, "x"):
            out.add("high", f"git clean {' '.join(flags)}: deletes ignored and untracked files")
        elif _short_has(flags, "f", ("--force",)):
            out.add("medium", "git clean -f")
    elif sub == "branch" and _short_has(flags, "D", ("--delete", "--force")):
        out.add("medium", f"git branch -D {' '.join(words[1:3])}".strip())
    elif sub in ("checkout", "restore") and ("." in words[1:] or "--" in args and args[-1] in (".", "*")):
        out.add("medium", f"git {sub} .: discards working changes")
    elif sub == "stash" and words[1:2] and words[1] in ("drop", "clear"):
        out.add("medium", f"git stash {words[1]}")
    elif sub in ("filter-branch", "filter-repo"):
        out.add("high", f"git {sub}: rewrites history")
    elif sub == "gc" and "--prune=now" in flags:
        out.add("medium", "git gc --prune=now")


# ---- lexical pass -------------------------------------------------------------------------------
_RM_RE = re.compile(r"(?<![\w.-])(?:\S*/)?rm\s+((?:-[\w-]+\s+)*)([^;&|<>\n'\"`)]+)")
_CD_RM_RE = re.compile(r"\bcd\s+(\S+)\s*(?:&&|;)\s*(?:\S*/)?rm\s+((?:-[\w-]+\s+)*)([^;&|<>\n'\"`)]+)")
_RMTREE_RE = re.compile(r"\b(?:shutil\.)?rmtree\(\s*(?:(['\"])(?P<lit>[^'\"]*)\1|(?P<expr>[^)]*))")
_RIMRAF_RE = re.compile(r"\b(?:rimraf|rm\.-rf)\s+([^\s;&|'\"`]+)")
_FSRM_RE = re.compile(r"\.rm(?:Sync)?\(\s*(['\"])([^'\"]*)\1[^)]*recursive")
_FIND_RE = re.compile(r"\bfind\s+([~./][^\s;&|]*(?:\s+[~./][^\s;&|]*)*)[^;&|\n]*?(?:-delete\b|-exec\w*\s+rm\b)")
_FORMAT_RE = re.compile(r"(?<![\w./-])(mkfs(?:\.\w+)?|wipefs|blkdiscard)[ \t]+([^\n;|&]*)")
_DEVICE_WRITE_RE = re.compile(r"(?:\bof=|>\s*)(/dev/(?:sd|nvme|vd|hd|xvd|md|mapper/|dm-|zvol/|mmcblk|nbd|rbd)\S*)")
_REDIRECT_RE = re.compile(r"(?<!\d)(?<![<>])>>?\s*((?:/|~/|\$HOME/|\$\{HOME\}/)[^\s;&|'\"`)]*)")
_SQL_RE = re.compile(r"\b(DROP\s+(?:DATABASE|SCHEMA|TABLE|USER|ROLE)\b[^;'\"]{0,60}|TRUNCATE(?:\s+TABLE)?\s+\w[^;'\"]{0,60})",
                     re.IGNORECASE)
_MONGO_RE = re.compile(r"\bdropDatabase\s*\(|\bdrop\s*\(\s*\)")
_FLUSH_RE = re.compile(r"\b(FLUSHALL|FLUSHDB)\b", re.IGNORECASE)
_FORK_BOMB_RE = re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")
_CHMOD_RE = re.compile(r"\b(chmod|chown|chgrp)\s+(?:-\S+\s+)*-R\S*\s+\S+\s+(/(?:\*|\s|$|[a-z]+/?(?:\*|\s|$)))")


def _lexical(command: str, out: _Sink) -> None:
    if "--no-preserve-root" in command:
        out.add("critical", "rm --no-preserve-root")
    if _FORK_BOMB_RE.search(command):
        out.add("critical", "fork bomb")
    for m in _RM_RE.finditer(command):
        flags = m.group(1).split()
        if not _short_has(flags, "rR", ("--recursive",)):
            continue
        for raw in m.group(2).split():
            # relative targets are the structured pass's job; here they are mostly `{}` and `+`
            if raw.startswith("-") or not _HOME.match(raw) and not raw.startswith("/"):
                continue
            _delete_target(raw.rstrip("\\"), None, True, "recursive delete of", out, weak=True)
    for m in _CD_RM_RE.finditer(command):
        flags = m.group(2).split()
        if not _short_has(flags, "rR", ("--recursive",)):
            continue
        for raw in m.group(3).split():
            if not raw.startswith("-"):
                _delete_target(raw, _norm(m.group(1), None), True, "recursive delete of", out, weak=True)
    for m in _RMTREE_RE.finditer(command):
        lit = m.group("lit")
        if lit is not None:
            _delete_target(lit, None, True, "shutil.rmtree of", out, weak=True)
        else:
            out.add_weak("medium", f"shutil.rmtree({(m.group('expr') or '').strip()[:40]})")
    for m in _RIMRAF_RE.finditer(command):
        _delete_target(m.group(1), None, True, "rimraf of", out, weak=True)
    for m in _FSRM_RE.finditer(command):
        _delete_target(m.group(2), None, True, "fs.rm recursive of", out, weak=True)
    for m in _FIND_RE.finditer(command):
        for s in m.group(1).split():
            _delete_target(s, None, True, "find -delete under", out, weak=True)
    for m in _FORMAT_RE.finditer(command):
        words = [w.strip("'\"") for w in m.group(2).split() if not w.startswith("-")]
        victims = [w for w in words if _DEVICE.match(w) or w.startswith("$")] or words[-1:]
        for w in victims:
            out.add_weak("high", f"{m.group(1)} destroys the contents of {w}")
    for m in _DEVICE_WRITE_RE.finditer(command):
        out.add_weak("high", f"writes raw bytes to block device {m.group(1)}")
    for m in _REDIRECT_RE.finditer(command):
        p = _norm(m.group(1), None)
        for h in scan_path(p, "write") if p else ():
            out.add_weak(h.severity, h.reason)
    for m in _SQL_RE.finditer(command):
        out.add_weak("high", f"SQL {' '.join(m.group(1).split())[:60]}")
    if _MONGO_RE.search(command):
        out.add_weak("high", "drops a MongoDB database or collection")
    if _FLUSH_RE.search(command) and "redis" in command.lower():
        out.add_weak("high", "redis flushes every key")
    for m in _CHMOD_RE.finditer(command):
        p = _norm(m.group(2).strip(), None)
        scope = _perm_scope(p) if p else None
        if scope:
            out.add_weak(scope, f"recursive {m.group(1)} of {p}")


# ---- standalone: CLI and Claude Code hook -------------------------------------------------------
def hook_response(command: str) -> dict[str, Any] | None:
    """Claude Code PreToolUse output for a Bash command. None when nothing is flagged.
    critical -> deny, high -> ask (even where an allow rule would have let it through),
    medium -> allowed, with a note the user sees."""
    hz = scan_command(command)
    level = worst(hz)
    if level is None:
        return None
    text = "Keywright hazard check: " + describe(hz)
    if level == "medium":
        return {"systemMessage": text}
    decision = "deny" if level == "critical" else "ask"
    reason = text + (". Refused: if this must happen, the user runs it by hand." if level == "critical"
                     else ". Flagged as destructive; an existing allow rule does not cover it.")
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                   "permissionDecisionReason": reason},
            "systemMessage": text}


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="keywright hazards",
                                description="Flag destructive shell commands. Exit 0 none, 1 medium, 2 high, 3 critical.")
    p.add_argument("command", nargs="?", help="command line to check (omit to read stdin)")
    p.add_argument("--hook", action="store_true",
                   help="Claude Code PreToolUse mode: read the hook JSON on stdin, print a decision")
    p.add_argument("--json", action="store_true", help="print hazards as JSON")
    a = p.parse_args(argv)
    if a.hook:
        try:
            payload = json.load(sys.stdin)
        except ValueError:
            return 0
        if payload.get("tool_name") != "Bash":
            return 0
        command = (payload.get("tool_input") or {}).get("command") or ""
        resp = hook_response(command)
        if resp:
            print(json.dumps(resp))
        return 0
    command = a.command if a.command is not None else sys.stdin.read()
    hz = scan_command(command)
    level = worst(hz)
    if a.json:
        print(json.dumps({"level": level, "hazards": as_dicts(hz)}))
    else:
        for h in hz:
            print(f"{h.severity}: {h.reason}")
    return {None: 0, "medium": 1, "high": 2, "critical": 3}[level]


if __name__ == "__main__":
    sys.exit(main())
