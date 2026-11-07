# keywright-router

Version **0.0.2** is [published](https://github.com/johnrcarty/keywright/releases/tag/v0.0.2).

Acts on mail that reaches the agents' mailbox. It is an ordinary Keywright agent (`mail-router`):

```
Mail provider ⇄ email-mcp ⇄ Keywright ⇄ router ──(label / draft only)──> Keywright /llm ⇄ LiteLLM
                                     └──(actions)──> Keywright ⇄ email-mcp / ha-mcp / ...
```

- **No secrets.** The mailbox password is only in `email-mcp`, the provider keys are only in LiteLLM.
  The router holds a Keywright token, so revoking `mail-router` stops it completely.
- **Routing is boolean.** Rules in `rules.yaml` test sender, recipients, subject, body and attachments.
  The model is asked only when a rule reaches a `label:` test (one call per message, answer
  restricted to the configured labels) or an action drafts text with `llm:`.
- **Mail never chooses where things go.** `send`/`forward` addresses and `mcp` tool names are
  literals in the rules. Message text reaches a call only through `{{placeholders}}` in free
  text. The one exception is `reply`, which answers the sender, and Keywright's recipient rules
  gate that like any other send. The router never replies to bounces or robots.
- **Every action is a Keywright call.** A call the agent may not make without asking puts a
  prompt on the phone. The message's job waits (checked with `access_status`, never re-sent),
  resumes with the identical call once approved, and gives up after `pending_hours`.
- **Leaves your mail alone unless a rule claims it.** Handled mail is marked read and filed in
  `done_folder`, or in the folder a rule's `move` names. Mail no rule claimed stays unread in the
  inbox. Only mail that arrives after the router's first start is considered.

Rules reference: see [rules.example.yaml](rules.example.yaml). Commands:

```
keywright-router check      # validate the rules file
keywright-router dry-run    # route today's unread mail and print the calls, making none
keywright-router run        # the container's command
```

## Setting it up (once)

1. **Mailbox.** Fill in a protected `email.env` file on the broker host (0600; template
   `deploy/stack/email.env.example`): address, IMAP/SMTP hosts, password, recipient allowlist.
2. **Keywright resource `email`** (Resources → add MCP server):
   URL `http://email-mcp:9557/mcp`, default **approval**,
   argument keys `account_name, recipients, cc, bcc, attachments, include_attachments`.
   Each key present in a call adds a path (`.../send_email/recipients=a@b.c`) and every one
   must be allowed, so a recipient that is not allowed asks even when the rest of the call is.
   Standing rules for every agent:
   - deny `mcp/email/tools/delete_emails`, `mcp/email/tools/download_attachment`, `mcp/email/tools/set_email_tags`
   - deny `mcp/email/tools/send_email/attachments=*` and `mcp/email/tools/forward_email/include_attachments=True`
     unless an agent needs them
3. **Agent `mail-router`** (Agents → add). Put its token in `router.env` as `KW_TOKEN=kw_...`.
   No rules by hand: on its first start the router works out what its rules need (the mailbox
   reads, each fixed `mcp` call, each `forward`/`send` recipient), qualified exactly the way
   Keywright qualifies the calls, and asks for all of it in **one** request. Open it under
   Requests and choose **Always allow**. It does not poll while that request waits. Replies,
   values a rule fills from the message, and model access are left out on purpose and ask per
   call (a model needs a rule in the UI: `llm/<gateway>/model/<model>`). Preview the list with
   `keywright-router access`; after editing the rules, restart the router and it asks only for
   what is new.
4. **Rules.** Edit `./rules.yaml` (seeded from the example).
   Set `llm.gateway` to the name of the LLM gateway resource.
5. **Start.** Deploy your chosen email MCP service separately. With Python 3.12 or newer,
   install the published router with `pipx install keywright-router==0.0.2`, then run
   `keywright-router dry-run --config ./rules.yaml` before enabling
   `keywright-router run --config ./rules.yaml`. Supply `KW_URL` and `KW_TOKEN` through
   the environment. This optional integration is not part of the minimal Compose stack.

`email-mcp` also enforces its own recipient floor (`MCP_EMAIL_SERVER_ALLOWED_RECIPIENTS` in
`email.env`). Nothing leaves for an address outside it, whoever approved it.

## Web inbox and PDF delivery

Keywright's **Mail** screen (`/ui/mail`) adds a searchable inbox, reading pane, PDF downloads,
email rules, and local processing tags: Unprocessed, Queued, Processing, Waiting for approval,
Completed, and Failed. Tags are stored in Keywright, independently of the mailbox's read flag;
opening a message does not mark it read. All indexed mail retains delivery history after a
message leaves the watched folder. The cache indexes up to 10,000 messages in the selected
mailbox and renders message bodies as escaped text, without loading remote email images.

This worker runs inside Keywright and is disabled until configured in **Mail → Connection**.
Select the existing email resource, account `agents`, mailbox `INBOX`, and an enabled agent
(normally `mail-router`). Mailbox reads, attachment reads, and mutations go through that agent's
existing broker permissions and audit log. Pending approvals park a delivery; a denial or
failure produces a Failed tag and a manual Retry action. Run a single Keywright server worker,
as in the shipped stack; its in-process lock serializes mailbox sync and delivery operations.

The UI rules are separate from the existing YAML rules. Pause overlapping YAML rules (or stop
the legacy router container once its jobs have finished) before enabling the new worker. The
first sync only indexes existing mail. Subsequently discovered mail can run automatically;
existing messages require **Run rules**. Editing a rule does not re-run old messages. Rules use
sender address patterns and subject substrings, with the first enabled match winning in priority
order. Actions currently include PDF delivery to Budget, marking read, and moving to a folder.

For PDF delivery:

1. Deploy the budget app's document intake feature and create a **document delivery token** under
   **Settings → Document inbox**. This is separate from its Home Assistant summary token.
2. In **Mail → Connection**, enter the budget app's direct server URL and delivery token. The
   endpoint is fixed to `/api/integrations/documents`. Do not use a Home Assistant ingress URL.
3. On email-mcp 1.9.1, set `MCP_EMAIL_SERVER_ENABLE_ATTACHMENT_CONTENT=true` in `email.env` and
   recreate that service. For managed email-server configurations, enable the corresponding
   attachment-content policy instead. This does not enable filesystem attachment downloads.
4. Allow `get_attachment_content` for the chosen agent/account, along with metadata/body reads and
   marking read. A deny on `download_attachment` can remain: the UI uses embedded binary resources.
5. Add an electric-bill rule with **Send PDFs to Budget**. Test it on one existing message before
   enabling automatic processing.

Each PDF is transferred byte-for-byte, without parsing or changing budget amounts. The worker
accepts PDFs up to 5 MiB each (within email-mcp's 8 MiB serialized-result ceiling). Budget confirms
the SHA-256 checksum, and Keywright stores the receipt before continuing. Partial delivery retries
skip confirmed files; Budget also deduplicates a delivery if the response was lost. Mail is marked
read only after all PDFs are confirmed. Completed mail stays in the inbox. Destination changes do
not silently redirect an existing job: restore its original destination before retrying it.

The budget token stays in Keywright's protected settings database and is never rendered back
into the form or included in audit details. Back up that database as a credential-bearing file.

## License

Keywright is licensed under [Apache-2.0](LICENSE). Copyright 2026 Keywright
contributors. See [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_NOTICES).
Commercial use and proprietary extensions are permitted under the license's terms.
Unless explicitly stated otherwise, contributions intentionally submitted for
inclusion in Keywright are provided under Apache-2.0.
