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
2. **Repository context:** repository registry and owning project; multiple
   dev/test/prod locations using existing inventory and SSH identities; primary
   selection, metadata-only saves, path validation, explicit authorized read-only
   verification, and unavailable-reference behavior. Missing dev never selects prod.
3. **GitHub import:** named sealed PAT connections, selected repository discovery,
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

GitHub sync, repository locations, claims, execution records, and structured human
handoffs are not implemented by this first slice. It is not the complete release.

An agent with assigned tasks cannot be deleted until those tasks are reassigned;
disable it to revoke access while preserving assignment and history. The owner can
still edit a task that retains a disabled agent's assignment.
