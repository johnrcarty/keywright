# keywright

The client half of [Keywright](https://github.com/johnrcarty/keywright), a just-in-time credential broker for AI agents.

- `kw run|put|get|capture|request|status|tool` reach brokered SSH hosts and MCP tools from any shell.
- `kw hazards --hook` is the destructive-command tripwire, usable as a Claude Code PreToolUse hook.
- `kw setup claude-code|codex|check` configures the agent machine.

Install the published v0.0.1 client with Python 3.12 or newer and pipx:

```bash
pipx install keywright==0.0.1
kw login https://keywright.example.org/mcp --paste
kw setup claude-code
kw setup check
```

The client requires Python 3.12 or newer. On a Raspberry Pi or other machine with
an older system Python, [uv](https://docs.astral.sh/uv/guides/tools/) can install a
separate runtime for the client:

```bash
uv tool install --python 3.13 keywright==0.0.1
```

Run agent setup as the user who runs the agents. `kw setup check` validates the
integrations present on that machine; a Codex-only installation does not require
Claude Code hooks.

For development, run `pipx install ./client` from the repository root instead.

## Codex sandbox and approvals

`kw guide` (also `kw guides`) explains the agent workflow. Codex execution permission controls
whether the local command can reach the broker; Keywright separately controls each brokered
operation and its phone approval. For blocked network access, request a narrow execution prefix
such as `["kw", "resources"]` or `["kw", "run", "dev-host"]` through Codex's approval interface.
Review those prefixes before saving them; do not blanket-allow `kw` or disable the sandbox.
See the [official Codex rules documentation](https://learn.chatgpt.com/docs/agent-configuration/rules).
Setup installs agent instructions; it does not change Codex execution rules.

Network calls have a 15-second startup/handshake deadline and a separate response deadline of
the requested operation timeout plus 30 seconds. Worker cleanup adds at most one second before
termination. The worker inherits the sandbox and receives credentials over a private pipe.
This also bounds stalls in DNS resolution or SDK shutdown. Phone approval polling and remote
command timeouts keep their existing budgets. Transport errors exit 6 without retrying operations;
check the audit record before repeating an operation with an unknown outcome.

Session attribution uses `KW_SESSION` first, then header-safe `CODEX_THREAD_ID` metadata when
present, then Linux process ancestry. The metadata path was observed in Codex desktop; hosts
that do not supply it retain the fallback. Compare `kw session` inside and outside the sandbox
to check attribution. Process fallback is per process, not necessarily per conversation.
Switching from process to thread identity requires fresh session-scoped approvals.

## Bug reports and connector requests

Available in the source checkout, ahead of the next published package. `kw issue`
works without a configured or reachable broker. Preview a public report first:

```bash
kw issue bug --title "Describe the failure" --body-file report.txt
kw issue connector --title "Add a service connector" --body-file request.txt --json
```

For bugs, include reproduction steps, expected/actual behavior and relevant versions.
For connectors, include upstream API/MCP/CLI documentation, authentication details
(without credentials), versions and the operations you want. Search existing
[issues](https://github.com/johnrcarty/keywright/issues) before submitting.

To publish, install [GitHub CLI](https://cli.github.com/), sign in with
`gh auth login --hostname github.com`, and repeat the command with `--submit`.
It creates an issue in `johnrcarty/keywright` using that login. `--body-file -` reads
stdin; `--body` accepts inline text. `--dry-run` explicitly selects the default
preview behavior. `--json` gives machine-readable results. Publishing uses
[`gh issue create`](https://cli.github.com/manual/gh_issue_create).

Only your supplied title, body and client version are included. The command does
not collect logs, config files, broker credentials or conversation history, and
does not automatically sanitize your text. Review the preview for private data.
Security vulnerabilities belong in the repository's private security reporting
process, not a public bug report. Agents should publish only when authorized to
file a public report.

Exit codes: 0 previewed/submitted, 2 invalid input, 6 submission failed or outcome
unknown. Submission is never retried automatically; after a timeout or uncertain
failure, check GitHub before retrying to avoid duplicate issues. Broker-side MCP
does not acquire a GitHub credential; shell-capable agents use this client command.

## License

Keywright is licensed under [Apache-2.0](LICENSE). Copyright 2026 Keywright
contributors. See [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_NOTICES).
Commercial use and proprietary extensions are permitted under the license's terms.
Unless explicitly stated otherwise, contributions intentionally submitted for
inclusion in Keywright are provided under Apache-2.0.

### DoorDash shopping

Use `kw shop DoorDash guide` for the reviewed CLI contract, then `kw shop DoorDash start`
for a 20-minute browsing/cart session. `kw shop DoorDash status` reports the remaining time.
Checkout uses `kw shop DoorDash checkout --cart-uuid ID --card-id ID --tip-cents CENTS`: a live
priced approval, rechecked before submission. See [DoorDash setup and ordering](../docs/DOORDASH.md).
