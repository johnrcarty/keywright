# Keywright

Give AI agents temporary access to your infrastructure without giving them your credentials.
Self-hosted SSH and MCP access through one endpoint, with approval from your phone.
Choose **what** to authorize independently of **how long**: once, 15 minutes, 30 minutes,
1 hour, or this session. Permanent allow and deny rules are available in the admin UI.
Keywright keeps its SSH keys and upstream authentication tokens on the broker.

```
Claude Code / Codex / your agent ──(one MCP URL + agent token)──▶ Keywright ──ssh──▶ hosts
                                                                     │  └──http──▶ upstream MCP servers
                                                        phone ◀──────┘  notification driver
                                                        (Home Assistant, webhook/ntfy, or the admin UI)
```

## What it does

- **Agent-facing MCP server** (streamable HTTP at `/mcp`). Every agent sees four tools:
  `access_list_resources`, `access_request`, `access_status`, `request_attention`. Gated tools appear
  as access allows:
  `ssh_run(host, command)`, `ssh_put(host, path, content)`, `ssh_get(host, path)`,
  `ssh_capture(host, command, to_host, to_path)` and every upstream MCP tool re-exported as
  `<server>__<tool>`.
  Only tools are proxied: upstream MCP resources and prompts are not reachable through Keywright.
  A proxied call may carry `_reason` and `_wait_seconds` next to the tool's own arguments; both are
  stripped before the call goes upstream, so the upstream, the prompt and the audit row see the same arguments.
- **LLM gateways.** Provider API keys are the credential most able to cost you money, so they
  never live where an agent runs. An `llm` resource points at a [LiteLLM](https://docs.litellm.ai)
  proxy that Keywright alone can reach; the real OpenAI/Anthropic/Gemini keys sit in that proxy's
  environment on the broker host. An approval on `llm/<gateway>/model/<model>` becomes a LiteLLM
  virtual key with exactly the approved models, the lease's lifetime as its expiry, and the gateway's
  per-lease ceiling (max spend in USD, requests and tokens per minute, concurrent requests). The
  agent is a LiteLLM internal user carrying a second, per-agent window ($10 a day, say), and
  `litellm_settings.max_budget` in `deploy/litellm.yaml` is the global ceiling behind both. Revoking
  the grant, the approval, the agent or the resource deletes the key upstream. A lease is always
  timed: "Allow once" and "Always allow" are not offered for LLM paths. Budgets are enforced against
  spend LiteLLM reads from its database, so **no key is minted unless the gateway reports its
  database connected**; the resource card says so in red, and a phone tap that could not mint leaves
  the request pending instead of pretending. The resource page lists active leases with what each has
  spent and the **exposure remaining**: what every active lease could still burn if it all went wrong now.
  **Usage** (`/ui/usage`) reports requests and observed tokens by gateway, model, agent, and
  virtual key, with inclusive UTC date filters, provider/model/key drill-downs, daily totals,
  and links to recent audit events. Models can be aggregated across gateways while keeping
  each gateway's contribution separate. Expired/revoked keys retain their recorded history.
  This covers calls through Keywright, not direct provider calls or provider billing costs;
  adding a provider still requires a supported gateway integration. Provider here means the
  configured gateway, not a vendor inferred from the model name or LiteLLM's internal route.
  Token coverage explicitly distinguishes missing and partial reports. Old streamed calls
  cannot be backfilled from audit data. New streams capture reported usage from
  [Anthropic events](https://platform.claude.com/docs/en/build-with-claude/streaming) and
  [OpenAI usage chunks](https://developers.openai.com/api/reference/resources/chat/subresources/completions/streaming-events)
  without changing response bytes; OpenAI chat clients should request
  `stream_options: {"include_usage": true}`. Compressed responses are counted as requests
  but their usage is not parsed. Key labels and IDs are shown, never key secrets.
  Agents use a lease through **the proxy at `/llm/<gateway>/…`** with the Keywright token they
  already have: `ANTHROPIC_BASE_URL=https://keywright.example/llm/anthropic` plus
  `ANTHROPIC_AUTH_TOKEN=kw_…` (or `OPENAI_BASE_URL=…/llm/openai/v1`, `OPENAI_API_KEY=kw_…`; `kw llm
  <gateway>` prints the lines). Every call names a model, and the model is the permission path, so
  a call nobody has approved asks the human and waits up to `KW_LLM_WAIT` seconds (default 60;
  `X-Keywright-Wait` per call, `X-Keywright-Reason` for the prompt) before answering
  `403 approval_required` with the request id, exactly like `ssh_run`. Bodies and streams pass
  through untouched; only the credential changes hands. Standing access (an allow rule or an open
  default) runs on a key minted on first use with the same per-lease ceiling, renewed hourly, so
  "always allow" never means "unlimited". Every call is an audit row with the model, status,
  duration and token counts; spend itself is LiteLLM's to know and the resource page reads it back.
- **Permission paths**, hierarchical and glob-matched:
  `ssh/<host>/exec/<command>[/<subcommand>]`, `mcp/<server>/tools/<tool>`, `llm/<gateway>/model/<model>`.
  A shell command is classified into the paths it needs (`docker ps` → `ssh/nvr/exec/docker/ps`);
  anything with command substitution, `eval`, `bash -c`, `xargs`… needs `ssh/<host>/exec/**`.
  File transfers classify by path, `ssh/<host>/put/srv/apps/web/compose.yaml`, so a rule can
  allow a directory (`ssh/<host>/put/srv/apps/**`). The prompt shows the path, size and
  sha256, never the contents; an exact approval covers those contents at that path. Writes are atomic
  (temp file, mode, rename).
  **Secrets that only need to reach another machine** go by `ssh_capture`: a command's stdout on one
  host is delivered to a file on another (or the same) host and never returned to the agent. The
  prompt shows the command and the destination, the agent and the audit log get exit codes, byte count
  and sha256, and nothing is written unless the command exits 0. An approval to capture is bound to
  that destination, so it never lets the same command return its output.
  An MCP resource can name **argument keys** (e.g. `service, entity_id`); each key present in a call
  adds `mcp/<server>/tools/<tool>/<key>=<value>`, so one approval of a tool no longer covers every
  argument. A tool-level rule still covers all calls; a deny on `.../service=automation.turn_off` blocks
  just that value, and a value may end in `*` (`entity_id=light.*`).
  An MCP resource can also define **bundles** (`read-only: tools/ha_get_*, tools/ha_search`); an agent
  requests `mcp/<server>/bundle/read-only` and the human sees the request grouped by bundle. "Suggest
  bundles" on the resource page drafts them from the upstream tool names by verb.
  An MCP resource can keep a **hazard catalog** (`high: tools/ha_manage_app`, `critical:
  tools/ha_call_service/service=homeassistant.stop`, qualifiers need the matching argument key), which
  puts brokered tools under the same tripwire as shell commands; a tool whose name says delete, restart,
  reset… is flagged medium on its own.
- **Decision order** per path: deny rule → active grant (once-grants consumed atomically) → allow rule
  → resource default (`open` / `approval` / `locked`).
- **Gated calls ask automatically.** `ssh_run` on something not yet allowed creates a request, notifies
  you, and waits up to `wait_seconds` (default 90 s). Approve on the phone and the same call completes.
  An agent that knows its next steps can ask for them together:
  `access_request(operations=[{host, command}, {host, put, content}, {host, get}])` is one prompt
  listing every command line, and one exact grant per operation, so exact binding does not have to
  mean one prompt per step.
- **Pluggable notifications.** `Notifier` interface with drivers for Home Assistant (actionable push via
  the companion app, taps come back over HA's websocket, no automation needed), generic webhook / ntfy,
  and log-only. Every driver also gets signed decision links that work from any channel.
- **"The agent needs you"**, the other direction: `request_attention(message)` / `kw ping "..."` is
  an agent asking for *you*, in the conversation, because it has hit a question only you can settle.
  It authorizes nothing, is never gated by policy, and brings back no answer - it reaches the same
  phone as an approval and leaves a card on the dashboard until you clear it, so you know to go back
  to the chat once the approvals are done. Limits are on your attention, not on access: one ping per
  agent per minute, at most five outstanding, and a repeat of the same message folds into the one
  already waiting rather than buzzing again.
- **Access overview** at `/ui`: what is waiting on you, live over a websocket. Pending requests are
  tiles - agent, age, the command line, the expiry clock, and the answers most likely to be right -
  that expand to the full detail and every scope. New requests appear as they are made and decided
  ones resolve in place, including when the decision came from your phone, so a dashboard left open
  on a second screen is never stale. The page is server-rendered and fully usable with the socket
  closed or JavaScript off; the socket only ever reads. Below that: temporary approvals grouped by
  request with time remaining, standing allows and denies, target defaults, and agent suspension. An
  empty grant list never implies that permanent access is absent. Detailed grants, rules, targets,
  and settings remain available in the admin UI.
- **Audit log** of every decision and every executed command (who, what, where, exit code, duration).
  Every allowed call returns a handle (`_meta.keywright`, a trailing `[keywright] audit #…` line, and
  `keywright` in `ssh_run`'s JSON) naming the audit row, what allowed each path, and the approval
  requests behind grants and newly created permanent allow rules, so an agent can cite the approval
  in its report. Each request also has an activity timeline built from those recorded references.
  Per-MCP-resource opt-out.

### Preview a standing rule

In **Rules**, enter a pattern, effect and agent scope, then choose **Preview recent activity**
before adding the rule. The preview compares up to 200 brokered call records from the last 30 days
against current access settings, with and without the draft rule. It reuses the live policy
decision logic and current SSH/MCP classification and hazard checks. The draft is saved only
when you choose **Add rule**.

Each record is evaluated independently with current active grants; previews never spend grants,
create approval requests or run tools. Counts are audit records, not unique operations, and do
not reconstruct historical policy. Missing, redacted or truncated operation evidence, changed
target identities and LLM lease/budget checks are marked inconclusive. Upstream availability,
approval cooldowns and semantic decisions are outside this preview. No matching history is not
evidence that a proposed rule is safe.

### Approval friction

Open **Approval friction** from Requests, Audit or Rules to review a UTC date range (up to
90 days), optionally filtered by agent. Request counts use distinct request IDs; repeated
polling and lifecycle audit records do not inflate them. The report separates human approvals,
denials, pending/expired requests, decision wait times, policy blocks and failed tool results.
Missing timings and unreported results are shown explicitly. Commands, arguments, request
reasons and error output stay out of the report; examples link to their existing detail pages.

Three matching human approvals can produce an **exact-operation suggestion** for that agent
and target. Review the original operation and the policy preview, then explicitly save to add
standing rules that retain the exact command/arguments, account, target and file digest where
applicable. Repetition does not establish safety. Denials, failures, hazards, wildcard scopes,
incomplete evidence and already-covered operations exclude suggestions; no rules are applied
automatically. Evidence and access settings are checked again on save, and reviews expire after
10 minutes. The report caps each of its request and call samples at 2,000 rows and disables
suggestions when either sample is incomplete. Estimated coverage counts historical approval
requests, not guaranteed future savings.

## Quick start

```bash
uv venv && uv pip install -e ./client -e ".[dev]" -e ./router   # two packages: client/ (keywright) and the server
KW_DATA_DIR=./data keywright-server serve         # http://localhost:8700/ui
```

1. Open `/ui`, set the admin password.
2. **Resources → + SSH host**: name, host, user, paste a private key (stored 0600 in the data dir), pick
   the default mode. **Test connection** pins the host key.
3. **Agents → Create**: copy the token once. On the agent's machine:
   ```bash
   pipx install ./client
   kw login http://keywright.lan:8700 --paste     # paste the token on its own line
   kw setup claude-code                            # hook, permission rules, skill; or: kw setup codex
   kw setup check
   ```
   Any MCP client can instead point at `/mcp` with `Authorization: Bearer kw_…` (the admin UI shows
   the `claude mcp add` and `codex mcp add` forms).
4. **Settings → Notifications**: pick Home Assistant, paste a long-lived token, **Probe**, tick the
   phones, choose the three buttons, **Save**. Set the public URL so links in notifications resolve.
5. Ask the agent to do something. Your phone buzzes.

## Infrastructure inventory and topology

Under **Resources**, use **Inventory**, **Topology**, and **IP allocations** to maintain
device and workload records alongside your access connections:

1. Add hosts, workloads, network equipment, and smart-home devices in **Inventory**.
   The device-type picker includes lighting, plugs, vents, climate controls, sensors, security,
   appliances, media, energy, and pet devices. Type to filter the choices on new/edit records
   and discovery imports; select a result or press Enter to use it. Existing types remain valid,
   and an unfinished search cannot silently save the previous type.
   Set **Hosted on** for workloads, plus site, tags, and notes. **Topology** shows a
   collapsible hosting tree.
2. Add wired, Wi-Fi, or virtual interfaces to each record. Optionally record the MAC,
   connected switch/AP/host, and port, SSID, or bridge.
3. Add IPv4 or IPv6 subnets in **IP allocations**, including VLAN, gateway, and DHCP pool.
   Record assigned addresses against interfaces, or labelled reserved, planned, and
   excluded addresses. Separate address spaces support isolated networks with overlapping IPs.
4. Link existing resources from the inventory record, or choose **Add to inventory** in
   a resource's menu. Resources can be sorted numerically by IP and grouped by inventory
   host or network; inventory also supports grouping by parent host, connection type,
   site, and device type.

These are manual records: they do not configure devices, grant access, import DHCP leases,
or monitor reachability. Unrecorded address ranges exclude the recorded gateway, DHCP pool,
and allocations, but are **not verified free**. Duplicate allocations and hosting cycles
are rejected; linked records must be released or reassigned before deletion. Inventory
changes are audited. Startup adds the inventory tables without changing existing resources.

### Shared knowledge and RAG

**Knowledge** (`/ui/knowledge`) is Keywright's collection-scoped knowledge gateway. Keywright
owns source Markdown, revisions, provenance, publication and access control; retrieval indexes
are replaceable. The existing broker database stays on SQLite by default. PostgreSQL/pgvector
is an optional, separate search index, not a migration of broker state or LiteLLM's database.

1. Create a collection, such as `KeywrightKnowledge`. It starts **locked**: no agent access
   until you configure explicit rules under **Manage agent access**.
2. Publish Markdown, or import a committed `.md` file from a local Git checkout configured
   with `KW_KNOWLEDGE_GIT_ROOT`. Imports record the exact commit and do not read uncommitted
   files or follow symlinks. Reimport from the document page after changing the source repository.
3. Grant selected agents the collection's `read-only` bundle. Grant `contribute` separately
   if they may propose memory. Existing deny rules, grants, revocation and audit apply.
4. Review agent proposals in Knowledge. The UI shows the current-to-proposed Markdown diff,
   attribution, rationale and claimed source. Approval publishes; rejection never indexes the
   proposal. Stale proposals must be submitted again against the current revision.

The MCP tools are exported using Keywright's existing naming convention:

| Tool | Behavior |
| --- | --- |
| `KeywrightKnowledge__knowledge_search` | Search reviewed chunks; return source, revision, hash, line range and citation |
| `KeywrightKnowledge__knowledge_get` | Read a current published document by `document_id` |
| `KeywrightKnowledge__knowledge_list` | List this collection's reviewed documents with pagination |
| `KeywrightKnowledge__knowledge_propose` | Submit Markdown for human review; cannot publish or change access |

Search accepts `query`, `limit` (1–30, default 10), optional `path_prefix`, and optional
`diagnostics` (default false). A prefix such as `projects/example/` restricts both text and vector
candidates **before** their limits, within the authorized collection. Prefixes are literal,
case-sensitive relative paths; `%` and `_` are ordinary characters. Use a trailing slash for a
directory boundary. Omitting the prefix preserves cross-project discovery.

```json
{"query":"How do I publish a release?","limit":5,"path_prefix":"projects/example/","diagnostics":true}
```

Every search reports `index_status`: `disabled`, `empty` (no current chunks in the requested
scope), `missing`, `partial`, `incompatible`, `unavailable`, or `current`. Missing/partial
coverage, incompatible embeddings and outages produce a warning. Status checks the actual
indexed current chunk IDs against the configured embedding model and query vector dimensions;
it does not infer freshness from the last-rebuild time. `mode=hybrid` means at least one current
vector candidate survived authoritative validation and participated in ranking. It does not
mean the whole scope is indexed or that the results are relevant.

With diagnostics enabled, results include local/external text ranks, vector ranks/distances and
fusion scores, and the response includes scoped coverage counts, candidate counts and stage
timings. Coverage counts are `null` when the backend is disabled or unavailable. Scores are
ranking signals, not confidence probabilities. Timings cover broker work, including embedding,
index connection/queries, merging and validation; they exclude CLI/transport overhead and final
wire serialization. Diagnostics expose no connection URLs, credentials or raw provider errors.

Newly published documents use section-aware chunks (`chunk_version=sections-v2`). ATX and Setext
headings supply a separate `section_path` breadcrumb, including on split sections; headings inside
fenced code are ignored. Excerpts remain contiguous, exact source lines. Chunks target 2,400
characters, with at most 240 characters of whole-line overlap within a split section. An oversized
line or heading block attached to its first content line can exceed the target; the existing 256 KB
document limit remains the hard ceiling. Citation text never contains synthetic heading prefixes.

For existing publications, an administrator can open **Knowledge → Update existing search passages**.
This explicit, transactional migration preserves canonical Markdown, revision IDs, hashes and review
history. It only rebuilds derived chunks for current, published, unexpired documents in that collection.
Repeating it is a no-op when the chunks already match. A corrupt/missing source aborts the entire
migration. Versioned chunk IDs prevent old semantic entries from referring to changed boundaries.
Run **Rebuild semantic index** afterward if semantic search is configured. Startup adds the nullable
breadcrumb column to existing databases but does not automatically migrate their chunks.

Example proposal arguments:

```json
{
  "path": "decisions/retrieval.md",
  "title": "Keep retrieval indexes separate from broker state",
  "kind": "decision",
  "body": "# Decision\n\nKeywright owns access and provenance. Retrieval indexes are rebuildable.\n",
  "source": "Project implementation session",
  "rationale": "Preserve the architectural reason for future agents."
}
```

To update a document, include `expected_revision` from `knowledge_get`. The other supported
types are `documentation`, `memory` and `operational`. Operational records expire from retrieval
after `retention_days` (default 30; 1–365). Expiry and archival remove access, not historical
storage: old Markdown, provenance and audit remain for backup and review. Session summaries can
use `knowledge_propose`; automatic session capture, Notion synchronization and PDF parsing are
not implemented. Nothing from an agent session is silently promoted into shared memory.

Canonical UTF-8 Markdown is stored as immutable content-addressed `.md` files under
`$KW_DATA_DIR/knowledge/markdown/<hash-prefix>/<sha256>.md`; the database maps collection paths
to revisions and holds the derived chunks. A document can be downloaded as Markdown. **Back up
the broker database and the entire knowledge directory together.** Failed transactions may leave
unreferenced immutable blobs; these are never searchable. The search index can always be rebuilt
from published records. Source credentials and arbitrary server paths are not exposed by the tools.

Every chunk inherits its collection's resource identity. Both local and external retrieval filter
by that identity, then Keywright checks the authoritative current revision, publication and expiry
before delivering content. An index hit cannot supply authoritative content or grant access.
Retrieved material is labeled reference data; reviewed content is still not an instruction or an
authorization rule. Markdown is displayed as escaped text in the admin UI.

#### Optional PostgreSQL/pgvector and LiteLLM embeddings

Without extra services, SQLite FTS5 provides ranked text retrieval. For hybrid retrieval:

1. Install the optional driver (`pip install '.[knowledge]'`) and provision a dedicated
   PostgreSQL database with pgvector. Apply `deploy/knowledge-schema.sql` as its owner.
   The runtime database role needs only SELECT, INSERT and DELETE on `knowledge_search_chunks`.
2. Add an embedding model alias to your LiteLLM configuration. Issue a dedicated virtual key
   restricted to that model, with an explicit budget. Set the variables from
   `deploy/knowledge.env.example`. The API base ends in `/v1`; Keywright calls `/embeddings`.
   The embedding model and provider are administrator choices; there is no default paid call.
3. Restart Keywright, then select **Rebuild semantic index** for each collection. This sends
   its published chunks to your configured embedding provider. Repeat after publishing or
   reimporting content, and whenever the embedding model or endpoint changes.

For the existing Compose deployment, copy `knowledge.env.example` to `knowledge.env`, set its
credentials and embedding settings, set `KNOWLEDGE_PG_PASSWORD` in `.env`, then run from `deploy`:

```bash
docker compose -f docker-compose.yml -f knowledge.compose.yml up -d --build
```

The overlay adds a private pgvector service and installs the driver in Keywright's image. It
does not publish the database port or alter LiteLLM's PostgreSQL volume. If using Git import in
Docker, bind-mount the chosen checkout read-only at the configured Git root. Initialize the SQL
schema explicitly when using an existing database volume.

The adapter combines PostgreSQL full-text and exact cosine-vector rankings using reciprocal
rank fusion. Keywright also merges local text hits, so newly published documents remain searchable
before their next semantic rebuild. A failed embedding/index request falls back to local text
results with an explicit warning. Reindexing replaces a collection atomically after all embeddings
succeed. Changed model fingerprints cannot reuse old vectors. Exact vector search is intended for
small-to-medium collections; large deployments should measure latency before adding ANN indexes.
The first release uses manual semantic rebuilds, not an ingestion queue or background scheduler.
Search coverage diagnostics and path filtering use the existing index schema; no schema migration
or semantic rebuild is required to enable them. Publishing new content still requires a rebuild
to make that content semantically discoverable.

Run `pytest tests/test_knowledge.py tests/test_knowledge_index.py`. To exercise real PostgreSQL,
set `KNOWLEDGE_TEST_PG_URL` to an **isolated disposable** pgvector database: the integration test
initializes the schema and truncates only its `knowledge_search_chunks` table. Embedding HTTP
responses are mocked in tests; provider credentials and paid requests are not needed.

Backend references: [LiteLLM embeddings](https://docs.litellm.ai/docs/embedding/supported_embedding),
[pgvector hybrid search](https://github.com/pgvector/pgvector#hybrid-search),
[SQLite FTS5](https://www.sqlite.org/fts5.html).

### Network map

**Resources → Network map** shows a deterministic infrastructure hierarchy with client fans
around their reported AP or switch. Phones start with infrastructure and connected-client counts.
Select a switch or AP to expand and center its clients; **Overview** returns to the backbone.
Busy clusters use pages of eight clients on phones and ten on desktop. Desktop expands clusters
by default when they fit at a readable scale. **Fit view** never shrinks labels below their designed
size; larger networks remain pannable. **Reset** restores the responsive defaults.

Search by name, IP, MAC, or SSID to focus a device (including a client on another page).
The selected device's upstream path is highlighted and unrelated branches are dimmed. Use
pinch zoom, drag, +/−, or keyboard arrows. Details appear in a bottom sheet on mobile and a
panel on desktop, with full names, addresses, connection provenance and observation times.
The accessible device list includes every matching record. Status buttons highlight devices
without moving them; purple review markers are independent of connectivity status.

The map refreshes the selected controller every 60 seconds while the page is visible and
**Refresh every minute while open** is checked. Turn it off for a saved snapshot, or use
**Refresh now**. No background polling runs after closing the page. Refreshes reuse discovery's
read-only collection, audit log, complete-snapshot handling, and per-source concurrency guard;
map refreshes also enforce a 60-second minimum interval across tabs. Omada's own reporting
cadence is separate from this interval. There are no direct device pings.

Green means the client explicitly reported active in a current snapshot. Amber means inactive
or absent from the latest successful snapshot; red means an absent record was last collected
more than 24 hours ago. Unknown states and snapshots older than three minutes are gray, as are
snapshots after a failed refresh or changed source configuration. The last successful refresh
is always shown. Device numeric status codes are not treated as client active flags.

Wi-Fi links are dashed, wired links solid, and unspecified connections muted/dotted. Missing devices retain their last recorded connection. AP details supply the current wireless mesh parent. Wired infrastructure uplinks can be recorded
in inventory, including upstream port labels and PoE. Unmanaged inventory parents such as WAN/Internet
appear as unmonitored nodes. Thick backbone links distinguish wired and mesh connections, and
**Overview** collapses clients to inspect only the backbone.
Unreported connections remain unplaced. The purple dot means **not reviewed in inventory**,
not a missing DHCP reservation. This view does not monitor traffic, battery state, reservations,
or send offline alerts. Discovery retains the latest observation and previous change, not a
complete connection history. Site and search filters cover the full snapshot.

The existing SVG renderer has separate normalization/layout, presentation, and interaction
modules (`_topology_layout.js`, `_topology_render.js`, `_topology_controller.js`). The layout
uses reserved rectangles for infrastructure and outward client fans to prevent card/label
collisions. Refreshes retain the camera, selection, pages, and expanded clusters; geometry
changes only with topology or layout controls. Unknown attachments get a separate group
without invented edges. Cycles use a spanning forest for placement while retaining all reported
edges. Device icons use available category/model/name metadata, with a generic fallback.

Run `node tests/test_topology_layout.cjs` for deterministic layout checks at 25, 88, 160 and
350 devices. `tests/browser_network_map.py` exercises the rendered page and touch gestures
in a local Chromium browser; pass a saved graph with `--actual` for private network validation.

### Discovery and reviewed imports (phase 2)

**Resources → Discovery** provides on-demand, read-only discovery from an existing Omada
controller resource or a Proxmox SSH resource with a pinned host key. Omada reads all accessible
sites, devices, and clients, including reported MACs, addresses, and switch/AP attachments.
Proxmox reads cluster nodes, VMs, containers, and their hosting relationships through a fixed
`pvesh get /cluster/resources --output-format json` command; guest IPs are not collected yet.

Observations retain their source, refresh time, and latest field changes. MAC, name, and IP
matches are suggestions only, including when just one candidate exists. Missing records are
labelled as not seen in the latest successful refresh; observations older than 24 hours are
marked stale. Failed or incomplete refreshes retain the previous snapshot. Refreshes are
admin-only, audited, and bounded by pagination and timeout limits.

Select **Review** to create an inventory record or explicitly link an existing one. The selector
also offers existing Resources: selecting one reuses its inventory record or creates and links
a new record when you save. For existing records, choose individual fields to apply; unchecked
fields retain their manual values. Import
or link a parent host or connected switch/AP first, then select its hosting or interface connection
on the child's review. Multiple discovery sources can link to the same inventory record.

Interfaces and IP allocations are optional. To record an observed IP, choose its subnet/address
space and confirm the assignment, including DHCP reservations where applicable. Existing allocations
cannot be taken from another interface, and old addresses are never released by a discovery review.
Records remain allocated when a device disappears or a source fails.

Source links and review times appear on the inventory record. The discovery list distinguishes new,
reviewed, and changed observations; future refreshes never automatically apply changes. A stale
review form is rejected if its source or inventory has changed. Unlinking an observation retains
inventory, interfaces, and addresses. Imports and selected changes commit atomically with an audit
record and never grant agent access or configure the source device. Background polling is not enabled; the Network map can refresh while its browser tab is visible.

### OAuth for upstream MCP servers (including Notion)

**Resources → Add resource** opens a searchable integration catalog. Notion, TP-Link Omada,
and Keywright inventory have guided setup and connection defaults. Generic SSH hosts, MCP servers,
and LLM gateways are listed under **Custom connections**. The catalog lives in
`keywright_server/integrations.py`; presets reuse the existing adapters and OAuth implementation.

HTTP MCP resources support browser-based OAuth as well as static headers. OAuth is generic:
Keywright discovers the server's authorization provider, registers a client automatically when
supported, and uses authorization code + PKCE (S256). Providers without dynamic registration can
use a pre-registered client ID with `none`, `client_secret_basic`, or `client_secret_post` authentication.

To connect Notion, including a Free-plan workspace:

1. Set `KW_PUBLIC_URL` to Keywright's public HTTPS origin and open the admin UI at that URL.
2. Choose **Notion** from **Add resource**. Its server URL and OAuth method are already configured.
3. Keep **Agent access** on **Ask for approval** and select **Continue to Notion**. Complete Notion's sign-in
   and workspace consent in your browser. No Notion API token or client registration is needed.
4. Use **Test connection**, then review the discovered tools and access bundles. Agents use the
   same Keywright MCP endpoint or CLI as before; each operation still passes the approval gate.

The fixed callback is `<KW_PUBLIC_URL>/ui/mcp-oauth/callback`. Advanced OAuth settings accept
explicit scopes, pre-registered client credentials, and additional trusted HTTPS origins when the
authorization provider runs separately from the MCP server. Discovery sends no configured headers
and does not follow redirects. Unknown OAuth origins are rejected until the administrator adds them.
OAuth requires protected-resource metadata, authorization-server or OIDC discovery, and S256 PKCE.
This flow does not implement device-code grants or automatic client-ID metadata document hosting.

Each resource owns one shared provider connection. Keywright keeps client secrets and access/refresh
tokens encrypted in separate database records, using a key derived from `KW_SECRET_KEY` or the
persisted `secret.key`. Back up that key with the database. Changing it requires saving and
reconnecting OAuth resources (and re-entering any pre-registered client secret).
Tokens refresh on demand, with a database lease to serialize refresh-token rotation across workers.
An upstream 401 expires the cached token for the next attempt; Keywright never automatically replays
a potentially mutating MCP call. Expired/revoked refresh grants require an administrator to reconnect.

**Disconnect** removes the local tokens and invalidates pending sign-ins. It does not revoke the
provider's authorization: remove Keywright in the provider's connection settings for that as well.
Changing the endpoint or OAuth settings invalidates the saved connection. Existing header-based
resources, approvals, audit records, and result-inspection settings keep their existing behavior.
Only tools are proxied; upstream MCP resources/prompts and direct file-upload HTTP requests are
not added by this OAuth feature.

See [Notion's connection guide](https://developers.notion.com/guides/mcp/get-started-with-mcp)
and the [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

### Internal inventory MCP

Add **Resources → Add resource → Keywright inventory**, keep the default **approval** mode,
and save. This built-in adapter needs no URL or credentials. Using the default resource name
`Keywright`, existing agent connections to `/mcp` discover these tools:

| Tools | Purpose |
| --- | --- |
| `Keywright__list_inventory`, `Keywright__get_topology` | Find hosts/services, interfaces, resource links, hosting parents and network attachments. |
| `Keywright__list_subnets`, `Keywright__list_ips` | Inspect subnet ranges, DHCP pools, recorded IPs and their ownership. |
| `Keywright__list_discovery` | Read cached observations with their source, timestamp and inventory link. |
| `Keywright__setup_host` | Create/update a host, VM, container or service with interfaces, addresses and existing resource links atomically. |
| `Keywright__save_subnet`, `Keywright__save_ip` | Record/update subnets and explicitly reserve, plan or assign IPs. |

All calls, including reads, use the normal approval gate, deny rules, grants and audit trail.
The resource offers `read-only` and `inventory-write` bundles; creating it grants no access.
Allow selected reads on **Access** if agents should inspect inventory without a prompt.
Automatic approvals bind the exact arguments. Resource credentials are never returned, and
inventory links do not change a resource's connection or permissions.

Read inventory first and copy the returned `revision` into a write's `expected_revision`.
If anything changes before the approved operation runs, the write fails without changing
inventory; read again and review a new operation. Successful writes return the next revision,
created IDs and before/after records. Use IDs to update existing records; omitted fields are
preserved. A failed step rolls back the entire host setup, and changes commit with their audit
record. Retrying a successful write with its old revision cannot create duplicate records.

For example, after reading inventory and subnets, call `Keywright__setup_host` with:

```json
{
  "expected_revision": "<revision from the latest inventory read>",
  "asset": {"name": "API VM", "kind": "vm", "parent_id": "<physical host ID>"},
  "interfaces": [{
    "name": "eth0",
    "medium": "wired",
    "attached_to_id": "<switch ID>",
    "allocations": [{"subnet_id": "<subnet ID>", "address": "192.0.2.50", "state": "assigned"}]
  }],
  "resource_ids": ["<existing SSH resource ID>"],
  "_reason": "Record the host and confirmed address for the API deployment"
}
```

These tools record inventory. Deploy software through the existing gated SSH tools; use the
admin UI for SSH enrollment and discovery refreshes. Unrecorded ranges are candidates to
verify, and cached discovery addresses are observations, not confirmed free IPs or reservations.

## Omada routers and controllers

Keywright includes an Omada Open API connector. In **Resources → Add resource → Omada controller**,
enter the controller's **Interface Access Address**, **Omada ID**, **Client ID**, and **Client Secret**.
Create the credentials in Omada's Global View under **Settings → Platform Integration → Open API**,
using **Client / Client Credentials** mode and the role and site privileges you want to expose.
See [TP-Link's Open API setup guide](https://support.omadanetworks.com/us/document/109315/).
The router must be managed by a controller that exposes Open API; a standalone router login is
not sufficient. Availability and endpoint behavior depend on the controller model and version.

Use the HTTPS address and port shown by Omada, such as `https://omada.example:8043`, without an API
path. Certificate verification is enabled by default. For a private certificate authority, set the
CA bundle path on the Keywright server (mount it into the container if applicable). An explicit
skip-verification option is available for self-signed controllers. **Save → Test connection** checks
authentication and site access. Secrets remain on the broker; access tokens are cached only in
memory and renewed automatically.

The connector provides four read-only tools: `omada_list_sites`, `omada_list_devices`
(including router inventory and status), `omada_list_clients`, and `omada_get_ap`
(including wireless mesh uplinks). It does not yet change DHCP,
firewall, VLAN, or other router settings. Every list accepts `page` (default 1) and `page_size`
(default 100, maximum 1000); device/client lists require `site_id`. Results retain the controller's
pagination metadata; request subsequent pages as needed. Available fields depend on the controller.

For a resource named `omada`:

```bash
kw tool omada --list
kw tool omada omada_list_sites
kw tool omada omada_list_devices site_id=YOUR_SITE_ID
kw tool omada omada_list_clients site_id=YOUR_SITE_ID page=1 page_size=100
```

The connector uses the existing MCP approval and audit flow, with permission paths such as
`mcp/omada/tools/omada_list_devices` and tools exported as `omada__omada_list_devices`.
The setup form includes `site_id` as an argument qualifier, so access can be scoped by site.
No separate MCP service or client package is required. Keep the default mode on **approval**
and use **Edit access** to set standing access if desired.

## Scopes

Automatic requests default to the **exact operation** shown: the same command or the same complete
MCP argument object, regardless of duration. The admin can explicitly select **permission patterns**
to cover other matching arguments. For automatic SSH requests, both choices remain bound to the
resolved remote account and configured target identity. Choosing more time never implicitly broadens
the operation. Phone buttons and signed decision links use the default scope; broadening requires
the authenticated admin UI.

An explicit `access_request` asks for the listed patterns or expanded bundles, so it has no exact
operation to bind. Existing manually created rules likewise cover all matching arguments.

| Button | Effect |
|---|---|
| Allow once | one use per listed permission scope, consumed atomically; a compound operation consumes each applicable grant once |
| This session | bound to `Mcp-Session-Id` or the client-supplied `X-Keywright-Session`, capped at `KW_SESSION_GRANT_TTL`; unavailable without an ID. This does not track conversation closure |
| 15 minutes / 30 minutes / 1 hour | expiring grants for the selected operation scope |
| This path, 15 min | a single file write only: the host and path for 15 minutes, whatever the contents, so iterating on a script costs one prompt instead of one per revision. The one phone button that broadens beyond the exact operation; enable it under Settings → notification buttons |
| Always allow | permanent allow rule for the selected operation scope (admin UI only) |
| Deny | reject this request with your reason; equivalent requests are suppressed for 10 minutes |
| Always deny | permanent deny rule for the selected operation scope (admin UI only) |

The API validates timed access between 1 minute and 1 hour. Notification actions sign the chosen
duration; changing it invalidates the signature. Home Assistant retains Deny within its three-button
limit. Configure which allowance buttons appear in Settings.

**Revoke approval** removes all temporary grants from that request. Other grants, standing rules,
or open defaults can still allow the operation. **Suspend agent** blocks all new operations for that
identity, regardless of those permission sources. Neither action cancels an operation already running.

## Destructive-operation tripwire

Every SSH operation is scanned by `keywright/hazards.py` before policy is consulted. Classification
says what a command *is*; the tripwire says whether a human has to look at it fresh, whatever access
already exists. It reads the command line (and `ssh_put`/`ssh_get` paths), sees through `sudo`,
`env`, `timeout`, `bash -c`, `ssh host ...`, `xargs`, `find -delete` and a preceding `cd`, and makes a
second lexical pass for shapes it cannot parse: `python -c "shutil.rmtree('/')"`, heredocs, quoted
scripts.

| Level | What happens | Examples |
|---|---|---|
| **critical** | refused before anyone is asked; no approval can allow it. If the human wants it, they run it by hand | `rm -rf /`, `/*`, `/home`, `~`, `/home/<user>`, `/etc/*`; `--no-preserve-root`; deleting `.ssh`/`.gnupg`/host keys; `chmod -R` on `/`; `mv /etc`; `find / -delete`; fork bomb |
| **high** | always a fresh prompt, titled `DESTRUCTIVE`, even under a `**` hour or an always-rule. Only *Allow once* and *Deny* are offered; the grant binds the exact command line and is used up by it | `rm -rf /opt/*`, `rm -rf .` with no known directory; `mkfs`, `wipefs`, `dd of=/dev/…`; `qm`/`pct destroy`, `zfs`/`zpool destroy`, `lvremove`; `docker compose down -v`, `volume rm`, `system prune`; `git push --force`, `reset --hard`, `clean -fdx`; `DROP DATABASE`, `FLUSHALL`; `reboot`, `systemctl stop sshd`, `iptables -F`, `crontab -r`, `userdel -r`; writing `/etc/sudoers*`, `/etc/passwd`, `authorized_keys`, `fstab`, `/boot`, shell startup files; reading `/etc/shadow` or private keys |
| **medium** | runs under existing access; the prompt, the tool result and the audit row carry the flag | any other `rm -r`, `docker rm -f`, `git clean -fd`, `git branch -D`, `rsync --delete` |

Deny rules still win first. A flagged request cannot be widened to patterns or given a duration, from
the phone or the admin UI. Commands run inside a guest or another host (`pct exec`, `docker exec`,
`ssh host`) are flagged at the same level with an `(inside …)` prefix. Brokered MCP tools are flagged
from the resource's hazard catalog (owner-listed, high or critical) or, medium only, from a destructive
verb in the tool name; the same once-only and refuse rules apply.

This is a tripwire, not a sandbox: it cannot see what a test runner or interpreter does once it runs,
which is why `pytest`, `tox`, `npm test`, `cargo run` and friends classify as `**` like `make` does.
The real protection against an agent wiping its own machine is that the machine holds nothing worth
losing: the keys live here.

### The same check on the agent's own machine

`kw setup claude-code` installs `kw hazards --hook` as a Claude Code `PreToolUse` hook for Bash. High
asks even where an allow rule would have let it through; critical denies; medium shows a note. The
remote payload of a `kw run|put|get|capture` line only earns a note, because the server judges it;
everything local on that line, and `kw setup|login|logout` whatever precedes them, is enforced here.
`kw hazards "<command>"` prints the flags and exits 0/1/2/3 for none/medium/high/critical.

## The `kw` command

The client package (`client/`, published as `keywright`) gives any agent that can run a shell the
same broker without MCP, and fixes two things MCP cannot: Claude Code's stateless MCP transport names
no session, so "This session" approvals were never available to it, and MCP tool calls are
backgrounded after ~120 s while a phone approval is pending.

```bash
kw resources
kw run nvr -r "why" -- journalctl -u frigate -n 50      # narrow classification
kw run nvr -r "why" -c 'docker ps | grep api'           # verbatim line: host-wide ** pattern, exact approval
kw put nvr /etc/app/app.env --file app.env -r "why"
kw get nvr /etc/app/app.env -o app.env
kw capture nvr --to app-host:/root/.env -- cat /run/secret
kw request -r "why" --ops ops.json                      # several exact steps, one prompt
kw status req_… --wait 900                              # approved? it names the command to re-issue
kw tool ha ha_get_state entity_id=light.kitchen -r "why"
kw ping "ACME DNS-01 or the existing wildcard? I need your call."   # asks for you, not for access
kw guide                                                # the agent guide (installed as a Claude Code skill)
```

Remote stdout and stderr are the CLI's stdout and stderr, so pipes work; one `kw:` line on stderr
names the audit row and what allowed the call. Exit codes: 0 ok · 1 remote nonzero · 2 usage ·
3 approval pending · 4 denied/refused/locked/rate-limited · 5 unknown resource · 6 transport/auth/outcome unknown ·
7 the broker could not run it. A gated call is three phases: one call with `wait_seconds=0`, a poll
while the human decides (heartbeat on stderr, default 900 s, `KW_WAIT` overrides), then one execute call; a transport
failure on an executing call is reported as "outcome unknown" and never retried.

Session identity comes from `KW_SESSION` (automation can set `job:<id>`; the Claude Code
`SessionStart` hook writes `claude:<session_id>` through `CLAUDE_ENV_FILE`), else from a per-agent-
process file keyed by pid, start time and boot id. `kw session` shows what will be sent.

Config lives in `~/.config/keywright/config.toml` (0600); `KW_URL`, `KW_TOKEN` and `KW_PROFILE`
override it. `kw setup claude-code` allows the operational subcommands (`Bash(kw run *)` and friends,
never `setup`/`login`), sets `BASH_DEFAULT_TIMEOUT_MS`, installs the skill, and with `--mcp remove`
drops the MCP registration and its blanket rule. `kw setup check` is the doctor.

## Configuration (environment)

`GK_*` names from before the rename are still read, with a warning, for one release.

| Var | Default | |
|---|---|---|
| `KW_DATA_DIR` | `./data` | SQLite DB, secret key, SSH keys (mode 700) |
| `KW_HOST` / `KW_PORT` | `0.0.0.0` / `8700` | bind |
| `KW_PUBLIC_URL` | | URL used in notification links (UI setting overrides) |
| `KW_TRUSTED_PROXIES` | loopback | reverse proxy IPs/CIDRs (or `*`) whose `X-Forwarded-*` headers are honoured; required behind a TLS-terminating proxy or every browser form post fails the same-origin check |
| `KW_ADMIN_PASSWORD` | | seeds the admin password on first start |
| `KW_AUTH_MODE` | `password` | `password`, `both` (SSO with password fallback), or `oidc` (SSO only) |
| `KW_OIDC_ISSUER` | | HTTPS OIDC issuer; Authentik: `https://auth.example/application/o/keywright/` |
| `KW_OIDC_CLIENT_ID` / `KW_OIDC_CLIENT_SECRET` | | confidential OIDC client credentials |
| `KW_OIDC_ADMIN_GROUP` | | required exact group name in the signed ID token's `groups` array |
| `KW_OIDC_SESSION_TTL` | `3600` | absolute browser session lifetime, 300–86400 seconds |
| `KW_REQUEST_TIMEOUT` | `900` | seconds a pending request stays answerable |
| `KW_TYPESAFE_API_KEY` | | enables Jev's second opinion on operations that prompt the human (Settings → Jev); absent, nothing leaves the host |
| `KW_LLM_WAIT` | `60` | how long a proxied LLM call waits for the human before answering 403 |
| `KW_SESSION_GRANT_TTL` | `3600` | upper bound on "this session" grants |
| `KW_NUDGE_TTL` | `43200` | how long an unanswered "the agent needs you" ping stays up |

### Authentik browser login

Create an Authentik application with an OAuth2/OpenID provider: confidential client, per-provider
issuer, signing certificate, and the `openid`, `profile`, and `email` scope mappings. Enable claims
in the ID token; `profile` must include a `groups` array. Restrict the application to a dedicated
group such as `keywright-admins`, and set `KW_OIDC_ADMIN_GROUP` to that exact name. Register the
strict callback `https://<keywright-host>/ui/oidc/callback`.

Set the OIDC environment variables above and `KW_PUBLIC_URL=https://<keywright-host>` (the process
environment is authoritative for the callback, even if the UI's notification URL differs).
Start with `KW_AUTH_MODE=both`: `/ui/login` redirects to Authentik, while `/ui/login?local=1`
offers the existing password. After verifying SSO, `KW_AUTH_MODE=oidc` disables password login,
old password cookies, and first-run password setup. Invalid or incomplete OIDC configuration
refuses startup. A provider outage never automatically enables password login.

SSO sessions are stored server-side with opaque, HTTPS-only cookies. Signing in requires the
admin group; group removal or disabling an Authentik account takes effect at the next sign-in,
within `KW_OIDC_SESSION_TTL` (one hour by default). Keywright logout immediately revokes its own
session, including live dashboard connections, but does not sign you out of other Authentik apps.
Provider-initiated/back-channel logout is not implemented. Provider tokens are not retained or
refreshed. Changing the issuer, client credentials, required group, public URL or session lifetime
invalidates existing SSO sessions. CLI/MCP agent tokens and signed notification links keep their
existing authentication.

For recovery from SSO-only mode, an operator with host access can change `KW_AUTH_MODE=password`
and recreate the container. Reset a forgotten local password with
`keywright-server set-admin-password`, then restart the server to reload its cached password hash.

## Deploy

`deploy/` contains a Dockerfile and generic Compose configurations. Run the broker on a
separate trusted host from the agents whose access it controls.

### Compose with LiteLLM

`deploy/llm.compose.yml` runs Keywright, LiteLLM and Postgres on one private network. Only
Keywright is published. LiteLLM is reachable as `http://litellm:4000` from Keywright and from
nowhere else, and Postgres is not optional: LiteLLM keeps virtual keys and spend there, and
without it every budget is a suggestion. `deploy/litellm.yaml` fails closed when spend cannot be
verified and never sets `allow_requests_on_db_unavailable`.

```bash
cd deploy
cp .env.example .env                 # PG_PASSWORD, LITELLM_MASTER_KEY, LITELLM_SALT_KEY (set once)
cp litellm.env.example litellm.env   # the real provider keys: rotate them first, this host only
docker compose -f compose.yaml -f llm.compose.yml up -d --build
```

Then in the admin UI: **Resources → + LLM gateway**, URL `http://litellm:4000`, the master key,
the per-lease and per-agent ceilings, **Test connection** (checks the database, refreshes the model
list). Both env files are gitignored.

### Updating a running instance

Back up the broker data directory before upgrades. Install matching server/client versions,
restart one server worker, and verify the health endpoint and approval/revocation flows.
Restore the matching application and data backup together when rolling back.

## Writing a notifier

Subclass `keywright_server.notify.base.Notifier`, declare `fields` for the settings form, implement
`probe()` and `send()`, optionally `send_nudge()`/`clear_nudge()` to carry "the agent needs you"
pings and `start()`/`stop()` for a listener that turns replies into decisions (`on_decision(token)`),
and decorate with `@register`. A driver that does not implement `send_nudge()` is not an error: the
dashboard card is created either way, so the ask is never lost because a channel cannot carry it.
See `notify/homeassistant.py`.

## MCP result inspection

Each MCP resource has a **MCP result inspection** setting in its edit form:

| Mode | Delivery |
| --- | --- |
| Off (default) | Original output; no inspection. |
| Observe | Scan locally and report findings, but deliver original output even on scanner failure. Use this to assess compatibility; it does not protect secrets. |
| Redact | Replace detected credentials in text. Withhold the entire result when coverage is incomplete or the scanner fails. |

All MCP adapters, including Omada and the built-in inventory, use this boundary after execution
and before delivery. SSH output is unchanged. Detectors cover configured header credentials and
Omada client secrets, common token formats, bearer credentials, private keys and credential
fields. Text blocks, structured JSON values and keys, metadata, embedded text resources and
resource-link descriptions are inspected. Suspicious instruction patterns produce advisory
findings only; quoted examples may trigger them, and obfuscated instructions can escape them.
No output is sent to an external model.

Redact withholds images, audio, binary resources and linked content because their contents are
not inspected. It also withholds sensitive dictionary keys, non-text credential fields and
changes to structured content: replacing a structured value could violate its upstream output
schema. Text redaction preserves the MCP envelope and the upstream error flag. Withheld results
are explicit MCP errors without original content or structured data. **The tool already ran**;
withholding does not undo its effects and callers must not automatically retry.

Inspection has a 256 KiB decoded-text/configuration budget, 10,000 visited nodes, 24 traversal
levels, 10,000 credential matches and 64 distinct configured credential values. The cleaned
payload also has a 256 KiB budget before trusted notices and audit metadata. Each scan has a cooperative 100 ms work
budget and a 250 ms wait limit, using bounded input in a worker thread. These are inspection
limits, not transport body limits or a hard real-time guarantee; the MCP SDK has already received
and decoded the response. Scanner exceptions and limit breaches are reported as fixed codes.
Findings never include matched content, credentials or exception messages. For inspected
resources, upstream exception details are also suppressed from the call audit.

The audit records execution (`is_error`) separately from delivery (`result_delivery`) and shows
findings and coverage gaps. When inspection is enabled, agents receive the same summary in reserved
`_meta.keywright_result_inspection`, independently of the optional audit handle; visible notices
accompany findings and withheld results. No response body is stored in the inspection audit.
Unknown modes fail closed. Older resource configurations default to Off. Detection is limited
to local patterns and exact configured values: encoded, split or novel secrets may be missed.
Start in Observe before enabling Redact for a resource with established clients.

## Security notes

- The command classifier is a scope guard, not a sandbox. Give "always" rules only to read-only
  commands on hosts you don't mind an agent poking at; keep production hosts `locked`.
- Broker credential isolation does not prevent an authorized command from reading application
  secrets on a remote host. Keep remote account privileges appropriate for the permitted work.
- Agent tokens are hashed at rest; upstream MCP headers and the HA token are stored in the SQLite DB
  (file mode 600). Restrict access to the data dir.
- Decision links are signed and expire with the request; anyone holding a link can decide.
- Phone buttons are authenticated compact actions (`<body>.<128-bit MAC>`): knowing a request or
  nudge ID grants no authority, and a dismiss action cannot decide access.
- The dashboard websocket is read-only and needs the admin cookie plus a same-origin `Origin`
  header; every change still goes through the ordinary same-origin-checked form posts.
- Host keys are pinned on first contact and verified afterwards.

## Tests

```bash
.venv/bin/python -m pytest -q
```
