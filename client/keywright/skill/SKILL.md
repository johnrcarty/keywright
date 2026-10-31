---
name: keywright
description: Use `kw` to run commands and move files on brokered SSH hosts, and to call brokered MCP tools, through Keywright. Every call is checked against the human's rules; some prompt the human on their phone. Read this before the first `kw` call in a session.
keywright-version: 0.0.1
---

# Keywright: reaching hosts and tools through `kw`

Keywright brokers access to SSH hosts and MCP servers. The credentials live on the broker, never on
this machine. `kw` is the command you use; the human approves what needs approving.

## First call

`kw guide` prints this guide; `kw guides` is an alias.

```bash
kw resources            # every brokered host and MCP server, and your standing on each
kw session              # which conversation your calls are attributed to
```

Under Codex, there can be two approval layers. The local sandbox must permit `kw` to reach the
broker before Keywright can request approval on the phone. If sandbox network access is blocked,
request execution permission through the agent's normal approval mechanism, scoped to the needed
subcommand or resource (for example `kw resources` or `kw run dev-host`). Do not disable the sandbox
or grant blanket shell access. A local execution approval does not grant access on the broker.

Broker connection/handshake attempts stop after 15 seconds, plus up to one second for worker cleanup.
After connecting, each response gets its operation timeout plus 30 seconds; approval polling and
remote commands retain their longer waits. A timeout does not prove a sandbox problem: check the
broker URL, DNS, proxy and network reachability. Do not blindly retry a command whose outcome is unknown.

`kw session` prefers `KW_SESSION`, then a valid `CODEX_THREAD_ID` when Codex supplies it, then a
per-process identity. Thread metadata keeps identity stable across sandbox boundaries. Availability
depends on the Codex host; process identity may span conversations, and hidden ancestry without
metadata yields `none` (no session-scoped approvals). Existing process-scoped approvals do not carry
over when a conversation starts using a thread identity.

## Running commands

```bash
kw run <host> -r "why" -- journalctl -u myapp -n 50
kw run <host> -r "why" -c 'docker ps | grep api'      # a pipeline or loop; approved one line at a time
kw put <host> /etc/app/app.env --file app.env -r "why"   # or content on stdin
kw get <host> /etc/app/app.env                            # content on stdout; -o FILE to save
kw capture <host> --to <host2>:/root/.env -- cat /run/secret   # output goes host to host, never to you
```

- Remote stdout is your stdout, remote stderr your stderr, so `kw run h -- cat f | grep x` works.
- One `kw:` line on stderr afterwards names the audit row, what allowed the call, and whether output
  was truncated (output is capped at 1 MiB and decoded as UTF-8).
- Prefer the `--` form: a plain command classifies narrowly (`ssh/<host>/exec/journalctl`). `-c` and
  anything with pipes, substitution or loops needs the host-wide `**` pattern and is approved exactly,
  one command line at a time.
- Prefer `kw put`/`kw get` over shell redirection: they classify by path and never put file contents
  in the human's prompt.
- Quoting through `kw run -c` → ssh → `pct exec`/`docker exec` → a shell mangles inner quotes. For
  anything non-trivial `kw put` a script to the host and run it by path.
- Always pass `-r`: it is what the human reads on their phone.

## Approvals

When a call needs approval, `kw` asks the human and waits (default 900 s; `KW_WAIT` changes it), printing a heartbeat on
stderr with whether the notification was delivered. Give the Bash tool a timeout of at least the
wait plus the command's own runtime. Under Claude Code the setup sets `KW_WAIT=540` because a Bash call
is capped at 10 minutes; a longer wait would push the call into the background and out of your control.
When a call exits 3, `kw status <id> --wait 540` keeps waiting and names the command to re-issue.

Exit codes tell you what happened:

| exit | meaning |
|---|---|
| 0 | ran; remote command exited 0 |
| 1 | ran; remote command exited nonzero (code in the `kw:` line, or `--json`) |
| 3 | approval still pending: the request id is printed; `kw status <id> --wait 900` later; when it reports approved it names the command to re-issue. `--no-wait` returns this at once |
| 4 | denied, refused, locked, recently denied, or rate-limited. Do not retry without new instructions from the user |
| 5 | unknown host, tool or request |
| 6 | could not reach the broker, bad token, or the call's outcome is unknown: check with the user before repeating anything |
| 7 | the broker could not run it (SSH failed, write refused): the `kw:` line names the stage |

Approval is once and exact by default: the same command line, once. Ask for several exact steps in
one prompt when you know them: `kw request -r "why" --ops ops.json` where the file is a JSON list of
`{"host","command"}`, `{"host","put","content"}`, `{"host","get"}` or capture objects. Patterns
(`kw request --pattern ssh/nvr/exec/journalctl`) ask for standing scope instead.

Destructive operations are flagged whatever access exists: recursive deletes of system or home
directories, disk formatting, destroying guests, volumes or pools, force pushes, powering off, and
touching key material or login configuration. The worst are refused outright (exit 4); the rest
always prompt and are approved once. Never reword a command to get around a flag; tell the user.

`kw status <id>` reports approval only; it never resumes a command. If a call returned 6 after the
human approved it, the command may or may not have run: ask the user, or check the audit log through
them, before running it again.

## When you need the human, not a host

```bash
kw ping "Traefik cert: ACME DNS-01 or the existing wildcard? Both work, you have a preference."
```

This reaches the same phone as an approval prompt and stays on the Keywright dashboard until they
clear it. It does **not** bring back an answer and does not wait. So: send it, ask the question in
the conversation, and stop. They come to you.

Use it when you would otherwise sit idle while they are away from the keyboard: a choice only they
can make, a question you cannot answer from the repo, or work finished and waiting on their eyes.

Do not use it to narrate progress, and do not use it to chase a pending approval - that request is
already on their phone. One ping per thing you need: sending the same message twice folds into the
one already waiting, and a second different ping inside a minute exits 4. `--where` overrides the
host and directory it reports; by default it sends both so they know which conversation to open.

## Brokered MCP tools

```bash
kw tools                          # names, e.g. ha__ha_get_state
kw tool ha --list                 # schemas for one server, on demand
kw tool ha ha_get_state entity_id=light.kitchen -r "why"
kw tool ha call_service --args '{"service":"light.turn_on","entity_id":"light.kitchen"}' -r "why"
```

## Models through Keywright

A gateway of kind `llm` in `kw resources` brokers model calls: the provider keys stay on the broker.
`kw llm <gateway>` prints the `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` lines that route an SDK
through it with your Keywright token. A call names a model; a model you have no lease on asks the
human and waits (`X-Keywright-Wait` seconds, `X-Keywright-Reason` for the prompt), then answers
`403 approval_required` with a request id if they have not decided yet. Every lease has a spend
ceiling; a 4xx from the gateway saying budget exceeded means the ceiling, not a bug. Ask with
`kw request --pattern llm/<gateway>/model/<model>` ahead of time when you know what you need.

## What `kw` will not do for you

`kw setup`, `kw login` and `kw logout` change this machine's own gate and are for the human. If the
setup looks wrong, say so instead of fixing it.
