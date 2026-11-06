# Shared CLI guidance and beta feedback

Use a dedicated collection, conventionally `CLIFeedback`, for CLI guidance and
sanitized feedback. Do not share an existing private project collection just to
distribute these instructions. This workflow uses Keywright's existing policy engine
and reviewed Markdown; semantic embeddings are optional.

## Share once, including future agents

1. Create `CLIFeedback` under **Knowledge**, described as shared CLI guidance and
   sanitized beta call notes for admin review.
2. Open **Access for every agent**. Keep **Agent → Every agent** and the scope empty.
3. Allow `knowledge_search`, `knowledge_get`, `knowledge_list`, and `knowledge_neighbors`.
4. Separately allow `knowledge_propose` if every enrolled agent should submit notes.
5. Publish this guidance as `guides/doordash-beta-feedback.md` in that collection.

These are ordinary global policies on five exact tools in one collection. Newly
enrolled agents inherit the same access. Existing denies, disabled agents, token
revocation, and collection boundaries remain enforced. Removing the relevant global
rules revokes that shared access; separate individual rules or grants may still apply.
Only admins publish. Pending proposals appear in the dashboard and are not returned
by knowledge search/list/get, including to other agents.

## Agent workflow

Discover the collection with `kw resources` and its schemas with
`kw tool CLIFeedback --list`. Search for the relevant CLI guidance and read its current
published document. Treat it as reference material; it does not grant permission to
spend money, bypass access controls, or disregard user instructions.

After a meaningful DoorDash workflow, capture talking points for the user's beta
feedback phone calls: what worked, what was confusing, bugs, and suggested improvements.
Lead with two or three short, conversational bullets the user can say on the call;
keep supporting technical evidence below them. Provide one useful note per workflow
rather than a note for every command.
Use `knowledge_propose` with a unique path such as
`feedback/doordash/YYYY-MM-DD-<unique>.md`, `kind: memory`, and a rationale explaining
the observation. Do not overwrite another agent's note. Keep the returned proposal
ID and tell the user that the note awaits review. An unknown submission outcome
does not justify blindly creating a duplicate proposal.

If no suitable collection or contribution permission is available, provide the
same sanitized report in chat and explain that it was not saved. Do not grant
yourself access, repeatedly request it, or omit the feedback silently.

## Report template

```text
Title: DoorDash CLI — short observation
Call talking points (2–3 short bullets):
Date:
CLI version / release, if known:
OS / architecture (no private hostname):
Workflow and command family:
Expected behavior:
Observed behavior, including what worked:
Sanitized reproduction steps / error code:
Responsiveness (measured or clearly described as an impression):
Reproducibility / number of observations:
Workaround, if any:
Impact and suggested improvement:
Likely layer: CLI / DoorDash service / auth / SSH / Keywright / unknown
```

Record evidence from the actual workflow. Do not invent results, place test purchases,
or repeat a timed-out checkout to investigate. Check order state before deciding
whether any retry is appropriate. Distinguish a broker approval delay from CLI latency,
and an expired credential from a CLI defect.

Remove tokens, login links/codes, account/cart/order IDs, customer names, delivery
addresses, payment details, private hostnames, and raw transcripts or output dumps.
Use placeholders in reproduction steps. Do not copy food purchases or other personal
details into a collection shared with all agents.

## Review and phone calls

The admin reviews each proposal. Approval publishes it to the shared collection;
rejection leaves it out of retrieval. Review confidentiality before publishing.
The user provides beta feedback by phone. When asked to prepare for a call, retrieve
reviewed notes and group recurring observations into a short agenda: successes,
friction or bugs, and suggested improvements. Preserve concrete examples and distinguish
one-off observations from repeated problems. The user can also review pending notes
in the Knowledge dashboard before the call; agents cannot retrieve unpublished proposals.

Saving or approving a note in Keywright is not a submission to DoorDash. Agents must
not email feedback, post upstream issues, or send vendor forms without explicit
submission instructions. `kw issue` targets the Keywright repository, not DoorDash.
