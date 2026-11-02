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

## License

Keywright is licensed under [Apache-2.0](LICENSE). Copyright 2026 Keywright
contributors. See [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_NOTICES).
Commercial use and proprietary extensions are permitted under the license's terms.
Unless explicitly stated otherwise, contributions intentionally submitted for
inclusion in Keywright are provided under Apache-2.0.
