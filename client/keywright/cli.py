"""`kw` / `keywright`: the command agents use.

Subcommands import lazily so the hook path (`kw hazards --hook`, run before every Bash call)
stays stdlib-only and fast. Exit codes are unambiguous by default:

  0 ok  1 remote command nonzero  2 usage  3 approval pending  4 denied/refused/locked/rate-limited
  5 unknown resource/tool/request  6 transport, auth, no config, or outcome unknown
  7 the broker could not run it (ssh_failed, put_failed, get_failed, capture_failed, upstream_failed)

A gated call is three phases: one call with wait_seconds=0 (which executes at once when access
already exists), a poll on the request id while the human decides, then one execute call. A
transport failure on either executing call leaves the outcome unknown; it is reported as such
and never retried here.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
import time
from pathlib import Path
from typing import Any

EXIT_OK, EXIT_REMOTE, EXIT_USAGE, EXIT_PENDING, EXIT_DENIED, EXIT_UNKNOWN, EXIT_TRANSPORT, EXIT_FAILED = range(8)
ERROR_EXIT = {
    "approval_required": EXIT_PENDING, "pending": EXIT_PENDING, "expired": EXIT_PENDING,
    "denied": EXIT_DENIED, "refused": EXIT_DENIED, "locked": EXIT_DENIED, "rate_limited": EXIT_DENIED,
    "unknown_resource": EXIT_UNKNOWN, "not_found": EXIT_UNKNOWN, "unknown_tool": EXIT_UNKNOWN,
    "unauthorized": EXIT_TRANSPORT, "invalid_arguments": EXIT_USAGE,
    "ssh_failed": EXIT_FAILED, "put_failed": EXIT_FAILED, "get_failed": EXIT_FAILED, "capture_failed": EXIT_FAILED,
    "upstream_failed": EXIT_FAILED, "internal": EXIT_FAILED,
    "forbidden": EXIT_DENIED, "invalid_assignee": EXIT_USAGE, "invalid_transition": EXIT_USAGE,
    "stale_version": EXIT_FAILED, "conflict": EXIT_FAILED,
}
# Approvals arrive on a phone; 300 s produced timeouts in normal use (F3 in the 2026-09-20 field
# report). KW_WAIT sets the default per machine or per profile without repeating --wait everywhere.
DEFAULT_WAIT = int(os.environ.get("KW_WAIT") or 900)
POLL_CHUNK = 60
PROXY_SEP = "__"  # `<server>__<tool>` names a tool on a brokered MCP server
# Tools that only ask or look: after an approval there is nothing to run again. Everything else,
# including every proxied `<server>__<tool>`, executes, so the default is "execute" and this set
# names the exceptions; a name the client has never seen still behaves correctly.
NON_EXECUTING_TOOLS = {"access_request", "access_status", "access_list_resources", "request_attention"}


def err(text: str) -> None:
    sys.stderr.write(f"kw: {text}\n")
    sys.stderr.flush()


# ---- parser -------------------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kw", description="Keywright client: brokered hosts and tools from any shell.")
    p.add_argument("--profile", "-p", help="profile name from the config file (default: KW_PROFILE or 'default')")
    p.add_argument("--version", action="store_true", help="print the client version and exit")
    sub = p.add_subparsers(dest="cmd")

    def gated(sp: argparse.ArgumentParser, reason: bool = True) -> None:
        if reason:
            sp.add_argument("-r", "--reason", default="", help="why; the human reads this on their phone")
        sp.add_argument("--wait", type=int, default=DEFAULT_WAIT, help=f"seconds to wait for approval (default {DEFAULT_WAIT})")
        sp.add_argument("--no-wait", action="store_true", help="return at once with the request id when approval is needed")
        sp.add_argument("--json", action="store_true", help="print the server's payload as one JSON object")
        sp.add_argument("-q", "--quiet", action="store_true", help="no kw: handle line on stderr")

    sp = sub.add_parser("resources", help="brokered resources and your standing on each")
    sp.add_argument("--json", action="store_true")

    sp = sub.add_parser("work", help="native task boards: boards, list, get, create, update, comment")
    sp.add_argument("action", choices=("boards", "list", "get", "create", "update", "comment"))
    sp.add_argument("task_id", nargs="?")
    sp.add_argument("--data", default="{}", help="JSON fields or filters; updates require expected_version")
    sp.add_argument("--json", action="store_true")

    sp = sub.add_parser("shop", help="DoorDash shopping session, cached guide, status or reviewed checkout")
    sp.add_argument("host")
    sp.add_argument("action", choices=("guide", "start", "status", "checkout"))
    sp.add_argument("--cart-uuid")
    sp.add_argument("--card-id")
    sp.add_argument("--tip-cents", type=int)
    sp.add_argument("--scheduled-time")
    sp.add_argument("--priority", action="store_true")
    sp.add_argument("--no-apply-credits", action="store_true")
    sp.add_argument("--intent", help="DoorDash workflow purpose; exclude private account/delivery information")
    gated(sp)

    sp = sub.add_parser("run", help="run a command on a brokered host: kw run <host> [opts] -- <cmd...>")
    sp.add_argument("host")
    sp.add_argument("-c", "--command", help="a verbatim shell line (pipes, loops); otherwise use -- <cmd...>")
    sp.add_argument("-u", "--user", help="remote account (subject to policy)")
    sp.add_argument("-t", "--timeout", type=int, default=300, help="remote command timeout in seconds")
    sp.add_argument("--exit-passthrough", action="store_true", help="exit with the remote command's own code")
    gated(sp)

    sp = sub.add_parser("put", help="write a file on a brokered host (content from --file or stdin)")
    sp.add_argument("host")
    sp.add_argument("path")
    sp.add_argument("-f", "--file", help="local file to send (default: stdin)")
    sp.add_argument("--mode", default="0644")
    sp.add_argument("-u", "--user")
    gated(sp)

    sp = sub.add_parser("get", help="read a file from a brokered host")
    sp.add_argument("host")
    sp.add_argument("path")
    sp.add_argument("-o", "--output", help="save to this local file instead of stdout")
    sp.add_argument("--allow-truncated", action="store_true", help="save even when the server truncated the content")
    sp.add_argument("-u", "--user")
    gated(sp)

    sp = sub.add_parser("capture", help="run a command on one host, deliver its output to a file on another")
    sp.add_argument("host")
    sp.add_argument("--to", required=True, metavar="HOST:PATH")
    sp.add_argument("-c", "--command")
    sp.add_argument("--append", action="store_true")
    sp.add_argument("--mode", default="0600")
    sp.add_argument("-t", "--timeout", type=int, default=300)
    sp.add_argument("-u", "--user")
    sp.add_argument("--to-user")
    gated(sp)

    sp = sub.add_parser("request", help="ask for access ahead of time: patterns, or exact operations from a file")
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--pattern", action="append", help="permission pattern; repeatable")
    g.add_argument("--ops", help="JSON file (or - for stdin) holding a list of exact operations")
    gated(sp)

    sp = sub.add_parser("status", help="approval state of a request (never resumes a command)")
    sp.add_argument("request_id")
    sp.add_argument("--wait", type=int, default=0)
    sp.add_argument("--json", action="store_true")

    sp = sub.add_parser("ping", help="ask the human to come back to the conversation (their phone, and the dashboard)")
    sp.add_argument("message", nargs="+", help="what you need from them, in a sentence or two")
    sp.add_argument("--where", default="", help="where the conversation is (default: this host and directory)")
    sp.add_argument("--json", action="store_true")

    sp = sub.add_parser("llm", help="print the environment that routes LLM calls through a Keywright gateway")
    sp.add_argument("gateway", help="the llm resource name (see kw resources)")
    sp.add_argument("--shell", choices=["sh", "fish"], default="sh")
    sp = sub.add_parser("tools", help="brokered MCP tools available to you (names)")
    sp.add_argument("--json", action="store_true")

    sp = sub.add_parser("tool", help="call a brokered MCP tool: kw tool <server> <tool> [k=v ...|--args '{}']")
    sp.add_argument("server")
    sp.add_argument("tool", nargs="?")
    sp.add_argument("--list", action="store_true", help="show this server's tools and schemas")
    sp.add_argument("--args", "-a", dest="args_json", help="arguments as a JSON object")
    sp.add_argument("kv", nargs="*", help="arguments as key=value (JSON values accepted)")
    sp.add_argument("--raw", action="store_true", help="print the raw result JSON")
    gated(sp)

    sp = sub.add_parser("issue", help="preview or submit a public Keywright bug report or connector request")
    sp.add_argument("kind", choices=("bug", "connector"))
    sp.add_argument("--title", required=True)
    report = sp.add_mutually_exclusive_group(required=True)
    report.add_argument("--body", help="report text; include reproduction steps or requested connector operations")
    report.add_argument("--body-file", help="UTF-8 report file, or - for stdin")
    action = sp.add_mutually_exclusive_group()
    action.add_argument("--submit", action="store_true", help="publish using your existing GitHub CLI login")
    action.add_argument("--dry-run", action="store_true", help="preview only (the default); no network access")
    sp.add_argument("--json", action="store_true")

    sp = sub.add_parser("hazards", help="flag destructive shell commands (also the Claude Code PreToolUse hook)")
    sp.add_argument("command", nargs="?")
    sp.add_argument("--hook", action="store_true")
    sp.add_argument("--json", action="store_true")

    sp = sub.add_parser("session-start", help="Claude Code SessionStart hook: records the conversation id")
    sp.add_argument("--hook", action="store_true")

    sub.add_parser("guide", aliases=["guides"], help="print the agent guide")
    sub.add_parser("session", help="print the session id kw sends and where it came from")
    sub.add_parser("version", help="print the client version")

    sp = sub.add_parser("login", help="store the server URL and an agent token")
    sp.add_argument("url")
    sp.add_argument("--token", help="the token (prefer --paste to keep it out of shell history)")
    sp.add_argument("--paste", action="store_true", help="read the token from stdin")
    sp.add_argument("--name", default="default", help="profile name")
    sp = sub.add_parser("logout", help="forget a stored profile")
    sp.add_argument("--name", default="default")

    sp = sub.add_parser("setup", help="configure this machine: claude-code | codex | check | uninstall")
    ss = sp.add_subparsers(dest="target", required=True)
    cc = ss.add_parser("claude-code")
    cc.add_argument("--mcp", choices=("keep", "user", "remove"), default="keep")
    cc.add_argument("--no-bash-timeout", action="store_true", help="do not set BASH_DEFAULT_TIMEOUT_MS")
    cc.add_argument("--dry-run", action="store_true")
    cx = ss.add_parser("codex")
    cx.add_argument("--mcp", choices=("none", "keep"), default="none")
    cx.add_argument("--dry-run", action="store_true")
    ss.add_parser("check")
    un = ss.add_parser("uninstall")
    un.add_argument("--keep-config", action="store_true")
    un.add_argument("--dry-run", action="store_true")
    return p


# ---- gated calls --------------------------------------------------------------------------------
class Gate:
    """Runs one tool call through approval, execution and recovery, with the exit-code contract."""

    def __init__(self, args: argparse.Namespace):
        from . import config, session

        try:
            self.profile = config.load(getattr(args, "profile", None))
        except config.ConfigError as e:
            raise SystemExit(_fail(str(e), EXIT_TRANSPORT)) from e
        self.session, _ = session.resolve()
        self.wait = 0 if getattr(args, "no_wait", False) else int(getattr(args, "wait", 0) or 0)
        self.quiet = bool(getattr(args, "quiet", False))
        self.as_json = bool(getattr(args, "json", False))

    def call(self, tool: str, arguments: dict[str, Any], read_timeout: float = 60.0):
        from .transport import call

        started = time.monotonic()
        result = call(self.profile, self.session, tool, arguments, read_timeout=read_timeout)
        if tool in ("ssh_run", "doordash_shop") and isinstance(getattr(result, "structured_content", None), dict):
            result.structured_content.setdefault("timing", {})["client_exchange_ms"] = int((time.monotonic() - started) * 1000)
        return result

    def gated(self, tool: str, arguments: dict[str, Any], remote_timeout: int = 60) -> tuple[dict[str, Any], int]:
        """(payload, exit code). Exit 0 means the payload is a success result."""
        from .transport import AuthError, TransportError, payload

        # Proxied tools carry the control key underscored so it cannot collide with an upstream
        # parameter; the server strips it before forwarding (F1 in the 2026-09-20 field report).
        args = {**arguments, ("_wait_seconds" if PROXY_SEP in tool else "wait_seconds"): 0}
        try:
            first = self.call(tool, args, read_timeout=remote_timeout + 30)
        except AuthError as e:
            return _fail(f"token rejected ({e}); run `kw login`", EXIT_TRANSPORT)
        except TransportError as e:
            if tool not in NON_EXECUTING_TOOLS:
                return _fail(f"outcome unknown: the call may have run before the connection failed ({e}); "
                             "check with the user before repeating it", EXIT_TRANSPORT)
            return _fail(f"could not reach the broker ({e})", EXIT_TRANSPORT)
        data = payload(first)
        pending_request = tool == "access_request" and data.get("status") == "pending"
        if not first.is_error and not pending_request:
            return data, EXIT_OK
        kind = "approval_required" if pending_request else str(data.get("error") or "error")
        if kind != "approval_required":
            return self._error(data)
        rid = str(data.get("request_id") or "")
        _say_pending(data, self.quiet)
        if self.wait <= 0 or not rid:
            return data, EXIT_PENDING
        decided, status = self._poll(rid, data.get("notified"))
        if not decided:
            return status, EXIT_PENDING
        if status.get("status") != "approved":
            return self._error({**status, "error": "denied" if status.get("status") == "denied" else "expired"})
        if tool in NON_EXECUTING_TOOLS:
            return status, EXIT_OK
        try:
            second = self.call(tool, args, read_timeout=remote_timeout + 30)
        except TransportError as e:
            return _fail(f"approved, but the outcome is unknown: the connection failed during execution ({e}); "
                         "check with the user before repeating it", EXIT_TRANSPORT)
        data = payload(second)
        return (data, EXIT_OK) if not second.is_error else self._error(data)

    def _poll(self, rid: str, notified: Any) -> tuple[bool, dict[str, Any]]:
        from .transport import TransportError, payload

        deadline = time.monotonic() + self.wait
        last: dict[str, Any] = {"status": "pending", "request_id": rid}
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False, last
            chunk = int(min(POLL_CHUNK, remaining))
            try:
                res = self.call("access_status", {"request_id": rid, "wait_seconds": chunk}, read_timeout=chunk + 30)
            except TransportError as e:
                err(f"waiting {rid}: broker unreachable ({e}); retrying")
                time.sleep(min(5, max(1, remaining)))
                continue
            last = payload(res)
            if last.get("status") != "pending":
                return True, last
            waited = int(self.wait - (deadline - time.monotonic()))
            if not self.quiet:
                err(f"waiting for approval {rid} {waited}/{self.wait}s notified={notified or 'unknown'}")

    def _error(self, data: dict[str, Any]) -> tuple[dict[str, Any], int]:
        kind = str(data.get("error") or data.get("status") or "error")
        code = ERROR_EXIT.get(kind, EXIT_FAILED)
        bits = [kind]
        for k in ("request_id", "stage", "hazard", "retry_after", "deny_reason", "reason"):
            if data.get(k):
                bits.append(f"{k}={data[k]}")
        if data.get("hazards"):
            bits.append("flagged: " + "; ".join(f"{h.get('severity')}: {h.get('reason')}" for h in data["hazards"]))
        if data.get("hint"):
            bits.append(str(data["hint"]))
        err(" | ".join(bits))
        return data, code


def _reissue_hint(data: dict[str, Any]) -> str:
    """What the approved request was for, so whoever reads the terminal knows which command to repeat."""
    op = data.get("operation") or {}
    if op.get("command") and op.get("host"):
        return f"kw run {op['host']} -- {op['command']}"
    if op.get("path") and op.get("host"):
        return f"kw put/get {op['host']} {op['path']}"
    if op.get("tool") and op.get("server"):
        return f"kw tool {op['server']} {op['tool']} ..."
    if data.get("operations"):
        return f"the {data['operations']} operations of the batch"
    return "patterns " + ", ".join(data.get("patterns") or []) if data.get("patterns") else "see the admin UI"


def _fail(text: str, code: int) -> tuple[dict[str, Any], int]:
    err(text)
    return {"error": "transport", "message": text}, code


def _say_pending(data: dict[str, Any], quiet: bool) -> None:
    bits = [f"approval requested {data.get('request_id')} notified={data.get('notified', 'unknown')}"]
    if data.get("hazard"):
        bits.append(f"flagged {data['hazard']}")
    if data.get("patterns"):
        bits.append("patterns " + ", ".join(data["patterns"]))
    err(" | ".join(bits))
    if any(str(p).endswith("/exec/**") for p in data.get("patterns") or []):
        err("kw: host-wide ** because this line has shell syntax the classifier cannot split; it is approved "
            "exactly, one line at a time. Several plain steps in one prompt: kw request --ops ops.json (kw guide)")


def handle_line(data: dict[str, Any], extra: str = "") -> str:
    h = data.get("keywright") or {}
    parts = [f"audit={h.get('audit_id', '?')}"]
    if extra:
        parts.append(extra)
    for pat, src in (h.get("matched") or {}).items():
        bound = (h.get("bound") or {}).get(pat)
        parts.append(f"{pat}<-{src}" + (f" ({bound})" if bound else ""))
    if h.get("consumed_grants"):
        parts.append(f"consumed={len(h['consumed_grants'])}")
    if h.get("hazard"):
        parts.append(f"flagged={h['hazard']}")
    return " ".join(parts)


def emit(data: dict[str, Any], code: int, as_json: bool) -> int:
    if as_json:
        sys.stdout.write(json.dumps(data, indent=1) + "\n")
    return code


# ---- commands -----------------------------------------------------------------------------------
def cmd_run(args: argparse.Namespace, rest: list[str]) -> int:
    if args.command and rest:
        return _usage("give -c or -- <cmd...>, not both")
    command = args.command or (shlex.join(rest) if rest else "")
    if not command:
        return _usage("nothing to run: kw run <host> -- <cmd...>  or  -c '<line>'")
    gate = Gate(args)
    payload_args = {"host": args.host, "command": command, "reason": args.reason, "timeout": args.timeout}
    if args.user:
        payload_args["user"] = args.user
    data, code = gate.gated("ssh_run", payload_args, remote_timeout=args.timeout)
    if code != EXIT_OK:
        return emit(data, code, gate.as_json)
    if gate.as_json:
        return emit(data, EXIT_OK if data.get("exit_code") == 0 or args.exit_passthrough else EXIT_REMOTE, True)
    sys.stdout.write(data.get("stdout") or "")
    sys.stdout.flush()
    if data.get("stderr"):
        sys.stderr.write(data["stderr"])
    rc = int(data.get("exit_code") or 0)
    if not gate.quiet:
        err(handle_line(data, f"exit={rc} truncated={'yes' if data.get('truncated') else 'no'}"))
    if args.exit_passthrough:
        return rc
    return EXIT_OK if rc == 0 else EXIT_REMOTE


def cmd_put(args: argparse.Namespace) -> int:
    content = Path(args.file).read_text() if args.file else sys.stdin.read()
    gate = Gate(args)
    payload_args = {"host": args.host, "path": args.path, "content": content, "mode": args.mode, "reason": args.reason}
    if args.user:
        payload_args["user"] = args.user
    data, code = gate.gated("ssh_put", payload_args, remote_timeout=120)
    if code != EXIT_OK:
        return emit(data, code, gate.as_json)
    if gate.as_json:
        return emit(data, EXIT_OK, True)
    if not gate.quiet:
        err(handle_line(data, f"wrote {data.get('bytes')} bytes to {data.get('written')}"))
    return EXIT_OK


def cmd_get(args: argparse.Namespace) -> int:
    gate = Gate(args)
    payload_args = {"host": args.host, "path": args.path, "reason": args.reason}
    if args.user:
        payload_args["user"] = args.user
    data, code = gate.gated("ssh_get", payload_args, remote_timeout=120)
    if code != EXIT_OK:
        return emit(data, code, gate.as_json)
    if gate.as_json:
        return emit(data, EXIT_OK, True)
    truncated = bool(data.get("truncated"))
    if args.output:
        if truncated and not args.allow_truncated:
            err(f"refusing to write {args.output}: the server truncated the content at 1 MiB "
                "(pass --allow-truncated to keep the partial file)")
            return EXIT_FAILED
        Path(args.output).write_text(data.get("content") or "")
        if not gate.quiet:
            err(handle_line(data, f"saved {args.output} truncated={'yes' if truncated else 'no'}"))
        return EXIT_OK
    sys.stdout.write(data.get("content") or "")
    sys.stdout.flush()
    if not gate.quiet:
        err(handle_line(data, f"truncated={'yes' if truncated else 'no'}"))
    return EXIT_OK


def cmd_capture(args: argparse.Namespace, rest: list[str]) -> int:
    if args.command and rest:
        return _usage("give -c or -- <cmd...>, not both")
    command = args.command or (shlex.join(rest) if rest else "")
    if not command or ":" not in args.to:
        return _usage("kw capture <host> --to <host2>:<path> -- <cmd...>")
    to_host, to_path = args.to.split(":", 1)
    gate = Gate(args)
    payload_args = {"host": args.host, "command": command, "to_host": to_host, "to_path": to_path,
                    "append": args.append, "mode": args.mode, "reason": args.reason, "timeout": args.timeout}
    if args.user:
        payload_args["user"] = args.user
    if args.to_user:
        payload_args["to_user"] = args.to_user
    data, code = gate.gated("ssh_capture", payload_args, remote_timeout=args.timeout)
    if code != EXIT_OK:
        return emit(data, code, gate.as_json)
    if gate.as_json:
        return emit(data, EXIT_OK, True)
    if not gate.quiet:
        err(handle_line(data, f"{'appended' if data.get('append') else 'wrote'} {data.get('bytes')} bytes to "
                              f"{data.get('to_host')}:{data.get('written')}"))
    return EXIT_OK


def cmd_request(args: argparse.Namespace) -> int:
    gate = Gate(args)
    if args.ops:
        text = sys.stdin.read() if args.ops == "-" else Path(args.ops).read_text()
        try:
            ops = json.loads(text)
        except ValueError as e:
            return _usage(f"--ops is not JSON: {e}")
        if not isinstance(ops, list):
            return _usage("--ops must hold a JSON list of operations")
        payload_args: dict[str, Any] = {"operations": ops, "reason": args.reason}
    else:
        payload_args = {"patterns": args.pattern, "reason": args.reason}
    data, code = gate.gated("access_request", payload_args)
    if code == EXIT_OK and not gate.quiet:
        err(f"{data.get('status', 'approved')} {data.get('request_id', '')}".strip())
    return emit(data, code, gate.as_json)


def cmd_ping(args: argparse.Namespace) -> int:
    """Ask for the human. Nothing comes back but an acknowledgement: their answer belongs in the
    conversation, so the only sane thing to do afterwards is ask there and stop."""
    from .transport import TransportError, payload

    gate = Gate(args)
    message = " ".join(args.message).strip()
    if not message:
        return _usage("say what you need: kw ping 'which of these two should I do?'")
    try:
        res = gate.call("request_attention", {"message": message, "context": args.where or _where()},
                        read_timeout=30)
    except TransportError as e:
        return _fail(f"could not reach the broker ({e})", EXIT_TRANSPORT)[1]
    data = payload(res)
    if res.is_error:
        return emit(*gate._error(data), args.json)
    if not args.json:
        err(f"{data.get('status', 'sent')} {data.get('nudge_id', '')} notified={data.get('notified', 'unknown')}")
    return emit(data, EXIT_OK, args.json)


def _where() -> str:
    """Where this conversation is, as a human would name it: host and directory, home as ~."""
    import os
    import socket

    cwd = os.getcwd()
    home = os.path.expanduser("~")
    if cwd == home or cwd.startswith(home + os.sep):
        cwd = "~" + cwd[len(home):]
    return f"{socket.gethostname()}:{cwd}"[:200]


def cmd_status(args: argparse.Namespace) -> int:
    from .transport import TransportError, payload

    gate = Gate(args)
    try:
        data = payload(gate.call("access_status", {"request_id": args.request_id, "wait_seconds": 0}, read_timeout=30))
    except TransportError as e:
        return _fail(f"could not reach the broker ({e})", EXIT_TRANSPORT)[1]
    if data.get("status") == "pending" and args.wait > 0:
        gate.wait = args.wait
        _, data = gate._poll(args.request_id, data.get("notified"))
    status = str(data.get("status") or data.get("error") or "unknown")
    if not args.json:
        err(f"{args.request_id} {status}" + (f" ({data['deny_reason']})" if data.get("deny_reason") else ""))
        if status == "approved":
            err(f"approved, not run: re-issue the same command to execute it ({_reissue_hint(data)})")
    code = {"approved": EXIT_OK, "pending": EXIT_PENDING, "expired": EXIT_PENDING, "denied": EXIT_DENIED,
            "not_found": EXIT_UNKNOWN}.get(status, EXIT_FAILED)
    return emit(data, code, args.json)


def cmd_resources(args: argparse.Namespace) -> int:
    from .transport import TransportError, payload

    gate = Gate(args)
    try:
        data = payload(gate.call("access_list_resources", {}, read_timeout=30))
    except TransportError as e:
        return _fail(f"could not reach the broker ({e})", EXIT_TRANSPORT)[1]
    if args.json:
        return emit(data, EXIT_OK, True)
    sys.stdout.write(f"agent {data.get('agent')}  session {data.get('session') or 'none'}\n")
    for r in data.get("resources", []):
        grants = len(r.get("grants") or [])
        rules = len(r.get("allow_rules") or []) + len(r.get("constrained_rules") or [])
        sys.stdout.write(f"  {r['resource']:<24} {r['kind']:<4} {r['default']:<9} "
                         f"grants={grants} rules={rules}"
                         + (f" denies={len(r['deny_rules'])}" if r.get("deny_rules") else "")
                         + (f"  {r['description']}" if r.get("description") else "") + "\n")
        if r.get("kind") == "llm":
            limits = r.get("limits_per_lease") or {}
            sys.stdout.write(f"{'':26}models: {', '.join(r.get('models') or {}) or 'none listed'}\n"
                             f"{'':26}per lease: ${limits.get('max_budget')} · budgets "
                             f"{'enforced' if r.get('budgets_enforced') else 'NOT enforced (no database)'}\n")
    if data.get("session_note"):
        sys.stdout.write(f"  note: {data['session_note']}\n")
    return EXIT_OK


def cmd_work(args: argparse.Namespace) -> int:
    from .transport import AuthError, TransportError, payload

    try:
        fields = json.loads(args.data)
        if not isinstance(fields, dict):
            raise ValueError
    except ValueError:
        return _usage("--data must be a JSON object")
    if args.action in ("get", "update", "comment"):
        if not args.task_id:
            return _usage("this work action requires a task ID")
        fields["task_id"] = args.task_id
    elif args.task_id:
        return _usage("this work action does not take a task ID")
    names = {"boards": "work_list_boards", "list": "work_list_tasks", "get": "work_get_task",
             "create": "work_create_task", "update": "work_update_task", "comment": "work_comment_task"}
    gate = Gate(args)
    try:
        result = gate.call(names[args.action], fields)
    except (AuthError, TransportError):
        return _fail("Work call failed; inspect current state before retrying a mutation.", EXIT_TRANSPORT)[1]
    data = payload(result)
    code = ERROR_EXIT.get(data.get("error"), EXIT_FAILED) if result.is_error else EXIT_OK
    if not args.json:
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
    return emit(data, code, args.json)


def cmd_shop(args: argparse.Namespace) -> int:
    gate = Gate(args)
    arguments = {key: getattr(args, key) for key in ("host", "action", "cart_uuid", "card_id", "tip_cents",
                 "scheduled_time", "priority", "no_apply_credits", "intent", "reason")
                 if getattr(args, key) is not None}
    data, code = gate.gated("doordash_shop", arguments, remote_timeout=180)
    if code == EXIT_OK and "exit_code" in data and data["exit_code"] != 0:
        code = EXIT_REMOTE
    if not gate.as_json:
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
    return emit(data, code, gate.as_json)


CORE_TOOLS = {"access_list_resources", "access_request", "access_status", "request_attention", "doordash_shop",
              "ssh_run", "ssh_put", "ssh_get", "ssh_capture"}


def cmd_llm(args: argparse.Namespace) -> int:
    """The four lines that make an SDK or an agent call models through Keywright: the gateway URL
    as the base URL and the agent token as the API key. No provider key is involved."""
    from .config import ConfigError, load

    try:
        profile = load(getattr(args, "profile", None))
    except ConfigError as e:
        return _fail(str(e), EXIT_USAGE)[1]
    base = profile.url.rstrip("/")
    base = base.removesuffix("/mcp")
    gw = args.gateway.strip("/")
    pairs = [("ANTHROPIC_BASE_URL", f"{base}/llm/{gw}"), ("ANTHROPIC_AUTH_TOKEN", profile.token),
             ("OPENAI_BASE_URL", f"{base}/llm/{gw}/v1"), ("OPENAI_API_KEY", profile.token)]
    for name, value in pairs:
        if args.shell == "fish":
            sys.stdout.write(f"set -gx {name} {shlex.quote(value)}\n")
        else:
            sys.stdout.write(f"export {name}={shlex.quote(value)}\n")
    sys.stdout.write("# unset the real ANTHROPIC_API_KEY / OPENAI_API_KEY here; a model is what you get approved for\n")
    return EXIT_OK


def cmd_tools(args: argparse.Namespace) -> int:
    from .transport import TransportError, list_tools

    gate = Gate(args)
    try:
        tools = list_tools(gate.profile, gate.session)
    except TransportError as e:
        return _fail(f"could not reach the broker ({e})", EXIT_TRANSPORT)[1]
    proxied = [t for t in tools if t.name not in CORE_TOOLS]
    if args.json:
        return emit({"tools": [{"name": t.name, "description": t.description} for t in proxied]}, EXIT_OK, True)
    for t in proxied:
        sys.stdout.write(f"{t.name}  {(t.description or '').splitlines()[0][:100]}\n")
    return EXIT_OK


def cmd_tool(args: argparse.Namespace) -> int:
    from .transport import TransportError, list_tools

    gate = Gate(args)
    prefix = f"{args.server}{PROXY_SEP}"
    if args.list or not args.tool:
        try:
            tools = [t for t in list_tools(gate.profile, gate.session) if t.name.startswith(prefix)]
        except TransportError as e:
            return _fail(f"could not reach the broker ({e})", EXIT_TRANSPORT)[1]
        if not tools:
            err(f"no tools for server {args.server!r}; see `kw tools`")
            return EXIT_UNKNOWN
        for t in tools:
            schema = getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {}
            sys.stdout.write(f"{t.name[len(prefix):]}: {t.description or ''}\n  {json.dumps(schema)}\n")
        return EXIT_OK
    arguments: dict[str, Any] = {}
    if args.args_json:
        try:
            arguments = json.loads(args.args_json)
        except ValueError as e:
            return _usage(f"--json is not JSON: {e}")
    for kv in args.kv:
        if "=" not in kv:
            return _usage(f"expected key=value, got {kv!r}")
        k, v = kv.split("=", 1)
        try:
            arguments[k] = json.loads(v)
        except ValueError:
            arguments[k] = v
    if args.reason:
        arguments["_reason"] = args.reason
    data, code = gate.gated(prefix + args.tool, arguments)
    if code != EXIT_OK:
        return emit(data, code, gate.as_json)
    if gate.as_json or args.raw:
        return emit(data, EXIT_OK, True)
    text = data.get("text")
    sys.stdout.write((text if isinstance(text, str) else json.dumps(data, indent=1)) + "\n")
    return EXIT_OK


def cmd_login(args: argparse.Namespace) -> int:
    from . import config

    token = args.token
    if args.paste or not token:
        token = sys.stdin.readline().strip() if not sys.stdin.isatty() else input("agent token: ").strip()
    if not token:
        return _usage("no token given")
    path = config.save(args.name, args.url, token)
    err(f"stored profile {args.name!r} in {path}")
    return EXIT_OK


def cmd_logout(args: argparse.Namespace) -> int:
    from . import config

    err(f"{'removed' if config.remove(args.name) else 'no such'} profile {args.name!r}")
    return EXIT_OK


def cmd_setup(args: argparse.Namespace) -> int:
    from .setup import check, claude_code, codex

    if args.target == "check":
        return check.run(profile_name=args.profile)
    if args.target == "claude-code":
        url = token = None
        if args.mcp == "user":
            from . import config

            prof = config.load(args.profile)
            url, token = prof.mcp_url, prof.token
        return claude_code.apply(mcp=args.mcp, url=url, token=token, dry_run=args.dry_run,
                                 bash_timeout=not args.no_bash_timeout)
    if args.target == "codex":
        url = None
        if args.mcp == "keep":
            from . import config

            url = config.load(args.profile).mcp_url
        return codex.apply(mcp=args.mcp, url=url, dry_run=args.dry_run)
    if args.target == "uninstall":
        claude_code.uninstall(keep_config=args.keep_config, dry_run=args.dry_run)
        codex.uninstall(dry_run=args.dry_run)
        if not args.keep_config and not args.dry_run:
            from . import config

            config.remove("default")
        return EXIT_OK
    return EXIT_USAGE


def _usage(text: str) -> int:
    err(text)
    return EXIT_USAGE


# ---- entry --------------------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    rest: list[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, rest = argv[:i], argv[i + 1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version or args.cmd == "version":
        from . import __version__

        print(f"keywright {__version__}")
        return EXIT_OK
    if args.cmd == "hazards":
        if args.hook:
            from .hook import run_pre_tool_use

            out = run_pre_tool_use(sys.stdin.read())
            if out:
                print(out)
            return EXIT_OK
        from .hazards import main as hazards_main

        return hazards_main([*(["--json"] if args.json else []), *([args.command] if args.command is not None else [])])
    if args.cmd == "session-start":
        from .session import session_start_hook

        try:
            payload = json.load(sys.stdin)
        except ValueError:
            return EXIT_OK
        session_start_hook(payload if isinstance(payload, dict) else {})
        return EXIT_OK
    if args.cmd in {"guide", "guides"}:
        print((Path(__file__).resolve().parent / "skill" / "SKILL.md").read_text())
        return EXIT_OK
    if args.cmd == "session":
        from .session import resolve

        value, source = resolve()
        print(f"{value or 'none'}  ({source})")
        return EXIT_OK
    if args.cmd == "login":
        return cmd_login(args)
    if args.cmd == "logout":
        return cmd_logout(args)
    if args.cmd == "setup":
        return cmd_setup(args)
    if rest and args.cmd not in ("run", "capture"):
        return _usage("`--` is only meaningful for run and capture")
    if args.cmd == "issue":
        from .issues import run

        return run(args)
    try:
        if args.cmd == "work":
            return cmd_work(args)
        if args.cmd == "run":
            return cmd_run(args, rest)
        if args.cmd == "shop":
            return cmd_shop(args)
        if args.cmd == "put":
            return cmd_put(args)
        if args.cmd == "get":
            return cmd_get(args)
        if args.cmd == "capture":
            return cmd_capture(args, rest)
        if args.cmd == "request":
            return cmd_request(args)
        if args.cmd == "status":
            return cmd_status(args)
        if args.cmd == "ping":
            return cmd_ping(args)
        if args.cmd == "resources":
            return cmd_resources(args)
        if args.cmd == "llm":
            return cmd_llm(args)
        if args.cmd == "tools":
            return cmd_tools(args)
        if args.cmd == "tool":
            return cmd_tool(args)
    except SystemExit as e:  # Gate() raised with an exit code tuple
        code = e.code
        return code[1] if isinstance(code, tuple) else int(code or 0)
    parser.print_help()
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
