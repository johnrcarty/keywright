# Native work boards

Keywright Work tracks durable local tasks in project boards and a permanent
Keywright / General board. All tasks combines those records across projects;
Needs you shows unfinished tasks assigned to the local owner. Neither view creates
copies of tasks or changes their board membership.

## First slice

Open **Work** in the admin navigation (`/ui/work`). Create a project to get its
board automatically, or create a task on General. A project needs no repository.
The Keywright software project can have its own board, separate from General.

Tasks support title, description, local notes, acceptance criteria, labels,
priority, due date, owner/agent/unassigned assignment, comments, activity,
archive/unarchive, and six fixed statuses: Backlog, Ready, In progress, Blocked,
Review, Done. Task IDs survive owner-authorized board moves. The move control
shows the destination audience before confirmation. An assigned agent must have
read access to the destination; reassign first if necessary.

All tasks includes General. Done and archived work are hidden by default. Use the
filters to include them or select a board, assignee, priority, status, or title
search. Lists return at most 100 tasks per request; the UI shows page totals and
pagination. Column counts describe the current page, not the whole database.
Project boards retain manual card order. All tasks sorts by priority, due date
(with undated tasks last), and stable task ID. Needs you prioritizes Review and
Blocked in list view. Changing status in any view updates the original task.

Drag between columns to change status. On a single board, drop on another card
to place the task before it. Each card also has a keyboard/touch **Move to** control.
List view and stacked columns work on narrow screens. Browser filters survive
navigation. Live events offer a refresh without replacing an active edit or drag.

The owner is the stable installation principal `owner`, not an expiring admin
session. Authorized admin sessions act for that principal. Configure its display
name from Work. Creator attribution is separate from the next-action assignee.

## Agent access and CLI

Choose a board and expand **Board access** to grant individual agents Read and/or
Write. General requires its own explicit grant. An existing infrastructure rule,
open SSH resource, or assignment does not grant board access. Disabling an agent
or revoking its board grant removes access. Aggregate results and counts are
filtered by board permissions before pagination.

The initial agent interface supports listing boards/tasks, reading details,
creating Backlog/Ready tasks, updating planning fields, and adding comments. Agents
cannot reassign, archive, move between boards, or transition work into execution,
review, or completion through this initial generic update path. Atomic claims,
execution provenance, and structured human handoffs belong to slice four; no agent
is automatically launched. These restrictions keep that future claim protocol
from being bypassed by the initial tools.

```sh
kw work boards --json
kw work list --data '{"assignee":"owner"}' --json
kw work create --data '{"title":"Review the release checklist","assignee":"owner"}' --json
kw work get tsk_EXAMPLE --json
kw work update tsk_EXAMPLE --data '{"expected_version":1,"notes":"Validation plan"}' --json
kw work comment tsk_EXAMPLE --data '{"body":"Checked the examples","idempotency_key":"review-1"}' --json
```

The corresponding native MCP tools are `work_list_boards`, `work_list_tasks`,
`work_get_task`, `work_create_task`, `work_update_task`, and `work_comment_task`.
Identity comes from the token. Unknown actor fields are rejected. Creation without
board/project context targets General and still checks its write permission.

Updates require `expected_version`; conflicting updates return `stale_version`
with the current version when available. Comments use an idempotency key scoped
to task and authenticated actor and do not conflict with workflow changes. Reusing
a comment key with different content returns a conflict. Creation is not yet
idempotent: inspect current state before retrying an uncertain create response.

Admin JSON task endpoints are `GET/POST /api/work/tasks` and
`GET/PATCH /api/work/tasks/{id}`. They require the existing authenticated admin
session and same-origin protection for mutations. The browser, API, MCP, and CLI
use the same task domain service.

## Notifications and persistence

Assignment to the owner and a new Review transition for owner-assigned work create
an in-app unread event and durable notification delivery record in the task
transaction. Log, webhook/ntfy, and Home Assistant transports receive a generic
message and authenticated task link, without task titles or private bodies.
Delivery retries independently with bounded backoff; failures are shown in Work.
Marking a notification read does not alter its task. Existing Nudges are unchanged.

Internal events deduplicate by activity and recipient. External delivery is at
least once: a crash after sending but before recording success can repeat a push.
Stable event IDs allow receiver deduplication, and Home Assistant uses them as
notification tags. Marking an event read does not cancel a pending transport retry.

Startup adds `work_projects`, `work_boards`, `work_board_agent_access`, `work_tasks`,
`work_task_activity`, `work_task_comments`, and `work_task_notifications`. The
stable General board key is `kw`; startup seeds it idempotently. No existing rows
are rewritten. There are no board deletion endpoints, and General has no archive
operation. Database checks enforce valid statuses/assignment shapes and unique
project boards, comment retries, and notification events.

Use the existing supported single-worker broker topology. SQLite mutations use
short write transactions and conditional version updates. Notification delivery
runs in one managed lifespan worker. No Redis, frontend framework, or additional
service is required. Work operations execute no SSH, Git, build, or deployment
commands and grant no infrastructure access.

## Remaining delivery plan

1. **Native boards:** initial working slice implemented here. Verify migrations,
   aggregate visibility, concurrent edits, comments, notification retries,
   accessibility, and actual CLI/MCP behavior alongside existing tests.
2. **Repository context (implemented):** repository registry and owning project; multiple
   dev/test/prod locations using existing inventory and SSH identities; primary
   selection, metadata-only saves, path validation, explicit authorized read-only
   verification, and unavailable-reference behavior. Missing dev never selects prod.
3. **GitHub import (implemented):** named sealed PAT connections, selected repository discovery,
   stable provider IDs, source-owned issue snapshots, open-only initial cards with
   optional closed history, discussion pagination, and inbound-only refresh.
   Recheck GitHub API version support before implementing the dedicated client.
   Add repository/source filters once those domains exist. Preserve local board
   placement, notes, workflow, assignment, archived states, and source identity.
   Poll with a recoverable per-repository job, overlap watermark, full reconciliation,
   bounded requests, rate-limit handling, and redacted recoverable errors.
4. **Agent execution and handoffs:** conditional atomic claims with fencing tokens,
   separate execution history and assignment, progress/evidence, release/review,
   idempotent human requests, small blocker relations, and authoritative approval
   links. A task action must never approve an AccessRequest or start an agent.
5. **Release verification:** run the complete GitHub integration and task board
   acceptance scenarios, permission/claim concurrency and failure recovery checks,
   clean-install/upgraded-install migrations, and setup documentation. Complete the
   normal Python 3.12–3.14 CI and isolated PostgreSQL/pgvector gates before merging.

Claims, execution records, and structured human
handoffs are not implemented yet. It is not the complete release.

An agent with assigned tasks cannot be deleted until those tasks are reassigned;
disable it to revoke access while preserving assignment and history. The owner can
still edit a task that retains a disabled agent's assignment.


## Repository context and environment locations

Open **Work → Repositories** or the repository link on a project board. Register
local repository metadata, optionally choose its owning project, then add dev,
test, and prod locations. Several repositories can belong to one project, and a
repository can remain owner-only until a project is chosen. Changing the owning
project transfers repository context visibility to that board's readers; it does
not grant SSH access. Archive hides a repository from normal lists. Archived
projects/repositories retain their locations and must be unarchived before editing
locations.

Manual registration assigns an internal ID, not a fabricated GitHub provider ID.
Manual URLs are descriptive. The advanced repository-selection endpoint supports
attaching a provider identity to a manual repository while retaining its location IDs.
Registration and location saves never clone or fetch a working checkout.

Each location records an environment, name, existing inventory host and/or SSH
resource, absolute directory, checkout/deployment kind, optional relative app
subdirectory, expected revision, application URL, notes, and explicit primary
selection. When both host references are chosen, they must have an existing
InventoryResourceLink. Inventory-only locations and deployment directories without
`.git` are valid. Saves perform no remote operations. Paths reject traversal,
control characters, and expansion placeholders. Selectors show up to 500 existing
records; management APIs accept IDs directly for larger installations.

Selecting a primary replaces the previous primary for that environment atomically.
The database also enforces uniqueness. Context resolution only searches the requested
environment: no dev location produces `not_configured`, never a production fallback.
One location can be resolved directly; several with no primary require a location ID
(`choice_required`). A missing primary host does not silently select another host.

Deleted hosts leave locations present with their original reference IDs and an
Unavailable state. Changed inventory/SSH associations also make locations unavailable.
There is no relinking by name. Explicitly edit the location to select valid references.

**Verify location** is an owner-only, explicit read-only SSH operation using the
existing admin authorization and SSH host-key controls, like Inventory discovery.
It needs a pinned SSH host key and Python 3 on the remote host; checkout verification
also needs Git. The fixed probe checks directory and subdirectory existence, symlink
containment, and (for checkouts) origin identity, ref, and commit. It does not clone,
pull, checkout, build, deploy, or run repository scripts. Expected revision and observed
revision remain separate. A deployment directory needs no Git metadata. Repository
identity verification currently supports GitHub URLs; other or absent URLs produce
Partial verification for checkouts. Credentials in origin URLs are discarded before
storing observations. Remote failures show fixed redacted messages.

Location, repository URL, and SSH configuration changes during verification discard
its result. Concurrent verification is rejected for two minutes; an interrupted
verification becomes stale and can be retried explicitly. Checks older than one day
or with changed host configuration display Stale. Editing a location resets verification.
A verified observation describes the last check, not a continuous host health guarantee.

Agents can list/read repositories only through explicit project-board read access.
Location lists redact host identities, paths, notes, links and verification data unless
current broker policy permits `ssh/<host>/exec/git` without requesting or consuming
access. Exact-command or session-only grants are conservatively insufficient for this
context read. Inventory-only locations are owner-visible. The broker still evaluates
the actual operation independently if an agent later requests SSH; context reads grant
nothing. Disabled agents and revoked board access are rejected on every call.

```sh
kw work repositories --json
kw work repository repo_EXAMPLE --json
kw work locations repo_EXAMPLE --data '{"environment":"dev"}' --json
kw work context repo_EXAMPLE --data '{"environment":"dev"}' --json
kw work context repo_EXAMPLE --data '{"environment":"dev","location_id":"loc_EXAMPLE"}' --json
```

Native tools are `work_list_repositories`, `work_get_repository`,
`work_list_locations`, and `work_get_location_context`. Agent writes to repository
configuration and remote verification are not exposed. Owner management APIs use
`GET/POST /api/work/repositories`, `GET/PUT /api/work/repositories/{id}`,
`GET/POST /api/work/repositories/{id}/locations`,
`PUT /api/work/repositories/{id}/locations/{location_id}`, and
`POST /api/work/locations/{location_id}/verify`. Updates and verification require
`expected_version`; lists are bounded. They use the same domain service as the UI.

Startup adds `work_repositories` and `work_repository_locations`; no existing task
rows or other tables are rewritten. Foreign keys retain location rows when hosts are
deleted, while stored historical reference IDs explain their unavailable state.
Repository/location changes and verification outcomes use existing audit records
and publish Work refresh events after committing.


## GitHub setup and issue import

Open **Resources → Add resource → GitHub**, add a named connection, and enter a fine-grained personal
access token with selected repositories and **Metadata: read** / **Issues: read**.
Contents permission is not required. Fine-grained tokens have one resource owner;
use separate named connections for different owners. Test the connection, then
choose repositories from the picker. Nothing is selected automatically. The picker
shows 100 repositories per GitHub page, with page-local name/description and owner
filters; use Next to browse further. Each table row has quick Add and Ignore actions;
checkboxes and Select all apply bulk actions to the current page. Add uses the bare
repository name, leaves the local description, project and environments blank, and
keeps issue import disabled. Source identity and GitHub metadata are retained.
Use Manage or Work → Repositories to fill in settings later; create projects in Work.
Adding an already registered repository preserves its existing configuration.

Ignore persistently hides a repository from the picker, including across renames,
token replacements and other connections. Show ignored exposes hidden rows with
Restore actions. Ignoring an added repository does not archive it or affect imports,
tasks or locations. Adding an ignored repository also restores its picker visibility.
Bulk add reports partial failures; retries do not duplicate registered repositories.
Configured GitHub connections in Resources have a direct **Browse repositories** link.

Tokens use the existing Fernet sealing pattern in dedicated connection records.
They are never returned to browser responses or agent tools. Replace a token by
entering a new value; leave the field blank to retain it. Disabling a connection
pauses its repositories, without selecting another credential. A successful catalog
test confirms repository access; importing issues additionally checks Issues read
permission. Revoked/expired tokens and unavailable repositories show redacted errors.
A GitHub App provider and installation onboarding remain a future distribution step.

Each selected repository uses its stable GitHub numeric ID (strings in JSON), not
its current name or connection ID. Rediscovery from another connection opens the
existing record without changing its chosen sync connection or project. The owner
can change its selected connection explicitly in Import settings. Renames update
source metadata while preserving repository, location, source issue and task IDs.

Enable import on an active project. Multiple repositories can import into the same
project board. The complete initial scan caches all real issues, excluding pull
requests. Open issues create Backlog tasks. **Include closed history** also creates
Done tasks; normal completed-work filtering hides them. Enabling closed history
later schedules a full reconciliation. A previously unimported closed issue that
reopens creates a Backlog task.

GitHub owns source title/body, state/reason, labels, author, GitHub assignees,
milestone and source timestamps. Keywright owns notes, acceptance criteria, workflow,
priority, local labels, assignment, position, archive state and board placement.
Imported titles and descriptions cannot be edited through the generic task API.
GitHub state changes add activity and visible badges; closing/reopening does not
change local status. A human can reconcile using the normal local status control.
Local Done does not close a GitHub issue. GitHub usernames are not mapped to local
identities. Source updates do not increment the local task mutation version or send
assignment notifications. Moving an imported task preserves its source link and all
subsequent refreshes respect its chosen board. Archiving never causes re-creation.

Source bodies and discussion are displayed as escaped plain Markdown text, with no
HTML execution, embedded image requests, or automatic link traversal. Issue bodies
are bounded to 64,000 characters and show a truncation indicator. GitHub discussion
is a separate on-demand paginated cache with its own refresh timestamp; local
comments remain durable and separate. Refresh discussion explicitly to see comment
edits. At most ten discussion pages per issue are cached; older pages can be loaded
again. Agents can read cached pages with `work_get_github_discussion` or
`kw work discussion <task_id> --data '{"page":1}'`; task-board permission is checked.
Source content follows the task's destination audience, while repository configuration
and host access stay governed by their own permissions.

### Synchronization and recovery

The managed worker runs with the supported single-process/single-SQLite installation.
Manual Sync now and scheduled imports share one persistent job/checkpoint per repo.
Default polling is 300 seconds (configurable from 60 to 86,400), with a daily full
reconciliation. Requests are serialized per connection. Repository refresh and issue
requests are inbound GETs only, pinned to GitHub REST version **2026-03-10**. The
client validates pagination and redirect origins, applies timeouts and response-size
bounds, and never makes authenticated requests to URLs in issue bodies.

A run captures its start, requests changes since the previous successful watermark
minus five minutes, and advances the watermark to its captured start only when all
pages have committed successfully. Individual pages can commit before later failures;
stable issue uniqueness makes replay safe. Older source snapshots are ignored.
Restart requeues interrupted work, preserving the successful watermark and forcing
full reconciliation. Each run is bounded to 1,000 pages. Outages, missing listings,
404s and permission errors never remove source snapshots, tasks, comments or work.

ETags/Last-Modified validators are cached by connection generation, API version and
exact URL; 304 responses reuse the matching page and pagination data. Cache capacity
is 32 pages per connection with at most 1 MiB cached per page (8 MiB transport limit).
Polling interval headers apply to their exact endpoint. Retry-After and rate-limit
reset times are honored, and transient job retries use bounded exponential backoff
with jitter. 403 permission failures are distinguished from rate limiting. Credential
replacement/configuration edits fence in-flight results before they can commit.

Startup adds `work_github_connections`, `work_github_cache`, `work_github_sync`,
`work_external_issues`, `work_github_discussion_pages`, and
`work_github_ignored_repositories` (stable repository-ID picker preferences), plus additive repository
configuration columns for installations that already have manual repository records.
No existing task rows are rewritten. Job state retains the latest outcome/counts;
audits record configuration changes and sync outcomes without source bodies or tokens.

References: [API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions),
[repository discovery](https://docs.github.com/en/rest/repos/repos#list-repositories-for-the-authenticated-user),
[repository issues](https://docs.github.com/en/rest/issues/issues#list-repository-issues), and
[REST API practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api).

GitHub setup lives in the Integrations picker at **Resources → Add resource → GitHub**.
Existing connections also appear on Resources. Old `/ui/work/github` bookmarks redirect
to `/ui/integrations/github`; existing connection records and tokens are preserved.
