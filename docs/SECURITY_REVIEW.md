# Backend security review — 2026-09-16

## Scope and method

Reviewed the admin authentication and mutation routes, approval lifecycle and policy evaluation,
SSH execution and enrollment, MCP authentication and proxying, notification actions, and audit storage.
Regression tests exercise the authorization boundary using disposable databases, HTTP servers, and
SSH servers. No exploit was attempted against production resources, and no production secrets were read.
This is a source review with targeted tests, not a certification or a complete penetration test.

## Findings addressed

| Severity | Finding and consequence | Change |
| --- | --- | --- |
| High | Home Assistant accepted unsigned `KW_ONCE_<request-id>` actions. An agent able to fire HA events could approve its own known request ID. The callback also accepted `ALWAYS`, although permanent grants were described as UI-only. | Compact actions now include a 128-bit HMAC bound to request and scope. Bare request IDs are rejected. Signed links and notification callbacks allow temporary scopes and deny only; permanent rules require the authenticated UI. |
| High | One-time grants used an ORM read/decrement/write sequence. Concurrent operations could both spend the same grant. Concurrent decisions could each mint a new grant. | Database conditional updates arbitrate both operations. Grant consumption rolls back if any required grant loses a race, and each grant is decremented only once per compound operation. |
| High | Pending requests were reused based only on permission patterns. Different commands/arguments and sessions could share a prompt. An automatic “once” approval also authorized another operation with the same command pattern. | Request reuse includes session and full operation details. Automatic one-time grants match the approved command/arguments and originating session. Explicit advance access requests and longer scopes remain pattern-based. |
| High | Shell parsing discarded newlines and redirection targets, stripped privilege/environment wrappers, and reduced arbitrary executable paths to their basenames. Narrow grants could therefore authorize additional commands or file writes. | Ambiguous syntax, redirection, environment/privilege wrappers, arbitrary executable paths, and several interpreter/option cases require host-wide execution approval. A wildcard execution request cannot avoid an overlapping narrow deny rule. |
| High | Waiting calls retained an already authenticated agent object, allowing disablement or token rotation to be missed after approval. | Evaluation reloads the agent and checks the original token hash. Resources, rules and grants are refreshed too. Revocation does not retroactively terminate commands already executing. |
| High | Keywright authenticated MCP requests without providing the SDK a session owner. Another valid agent could reuse a known session ID for stream access or session deletion. | The SDK receives a principal bound to the agent and token hash. HTTP GET, POST and DELETE with another agent’s credential are regression-tested and rejected. |
| High | Password enrollment always used `known_hosts=None`, including for hosts with a stored pin. A substituted server could receive enrollment credentials. | Enrollment verifies existing pins before authentication. SSH connections use explicitly configured keys and disable inherited SSH config and ambient agent identities. Initial contact still uses trust on first use. |
| Medium | SSH output was collected without a bound and truncated only after the command finished. | Concurrent stream readers retain at most 1 MiB total and discard excess as it arrives. Real SSH tests cover output limits, timeouts and incorrect host pins. |
| Medium | Cookie-authenticated forms lacked origin validation. Login redirects accepted network-path URLs. Sensitive pages lacked anti-framing/cache/referrer headers. | Unsafe browser routes require a matching Origin or Referer, reject cross-site/sibling-site submissions, and fail closed when source headers are missing. Redirects stay local. Sensitive pages are not cached or framed; HTTPS responses use Secure cookies. |
| Medium | Login attempts were unthrottled; password hashing ran on the event loop. Existing session cookies were independent of the stored password. | Bounded per-process login throttles, off-loop verification, a password input limit, and session payloads tied to the password hash. Password resets invalidate old cookies. |
| Medium | Enrollment scripts interpolated public-key comments and outbound-address settings into shell syntax. Private key creation had a separate permission-setting step. | Shell quoting, outbound-IP validation, and exclusive private-key creation with mode 0600. Passwords echoed during enrollment are redacted from returned output. |
| Medium | Nested MCP credential arguments were not scrubbed from audit records. MCP arguments were omitted from the dashboard and signed approval pages. | Recursive credential-field redaction and explicit argument previews in approval views and notifications. Exception text containing configuration details is no longer returned to agents. |

Additional fixes: expired requests are not reused; waiter state is cleaned up and observes decisions
made by another worker; approving a pending request rechecks disabled agents, deleted/locked resources,
and deny rules; the enrollment-script route no longer uses a closed database session. The MCP minimum
version now matches the 2.x API actually used by this code (`mcp>=2.2,<3`).

## Compatibility notes

- Sign in again after this update. Old admin cookies lack the password binding.
- Old **unsigned** HA notification buttons will be rejected. Use the admin UI for existing requests.
  Legacy signed tokens remain supported for temporary scopes and deny, subject to request expiry/state.
- Commands containing `sudo`, environment assignments, redirection (including `2>&1`), or uncertain shell
  syntax now need broader approval. Review the full command before granting it. With a narrow deny rule
  on that host, an overlapping host-wide execution request is denied.
- An automatic “allow once” applies to the exact operation that was reviewed. Session, hourly and
  permanent permissions still authorize the named permission scopes and can cover different arguments.
- Native scripts that submit admin forms using cookies must send an `Origin` header matching the
  request URL. Normal browser form submissions supply it automatically. The bearer-authenticated MCP
  endpoint is separate and does not require admin cookies or these form headers.
- Reverse proxies must preserve the public Host and convey the HTTPS scheme through a trusted proxy
  configuration. Request origin checks deliberately do not trust arbitrary forwarded-host headers.

## Validation

Final validation: 104 backend tests passed; Ruff and `git diff --check` passed. Chromium
checks covered 98 page/width combinations (320–1440px), both themes, and mobile form workflows.

The original implementation failed the new concurrency, unsigned-action, scope parsing, request reuse,
and stale-identity cases. The repaired implementation is covered by `tests/test_security.py`,
`tests/test_ssh_security.py`, and the existing classifier, policy, notification, enrollment and MCP tests.
Validation includes real local SSH connections and MCP sessions, not only mocks.

A `pip-audit` scan on 2026-09-16 examined the local environment: 55 package records, with the unpublished
Keywright package excluded from advisory lookup. No known advisories were reported for the 54 external
packages. This result is version- and date-specific; it does not establish that dependencies have no bugs
or that another environment has identical versions.

## Remaining boundaries and recommendations

- **Use HTTPS on untrusted networks.** The default service still supports plain HTTP. Secure-cookie flags
  do not encrypt HTTP bearer tokens or passwords. TLS termination and the actual production network
  topology were outside this source review.
- **Scope matching is not a shell sandbox.** Longer-lived grants allow the named commands and their
  arguments. Utilities can read secrets, change state, run hooks or call other programs; no short parser
  can establish the behavior of every executable. Use least-privilege remote accounts and narrow grants;
  use a constrained command/argument allowlist if stronger isolation is required.
- **First contact still trusts the presented SSH key.** Establish pins over a trusted network and verify
  fingerprints independently for sensitive hosts. Subsequent connections now enforce those pins,
  including password enrollment.
- **The broker remains a credential trust boundary.** Upstream headers and notification credentials are
  stored in the permission-restricted database, not encrypted at rest. Protect the host, backups and
  database, and isolate them from agent access. Redaction recognizes credential field names; arbitrary
  secrets embedded in command strings or free text cannot be recognized reliably.
- **A signed decision link/action is a bearer capability.** Anyone who possesses one can use its temporary
  authority before expiration. HA administrators or clients able to read notification contents must be
  trusted. Signatures prevent fabrication from request IDs, not misuse of stolen signed actions.
- **Single-admin authentication is still basic.** There is no MFA. Logout deletes the browser cookie;
  an already stolen cookie remains usable until expiry or password reset. Login throttles are local
  to one process, and per-agent pending-request limits are not a complete resource-exhaustion defense.
- **No proof of absence of compromise.** This review did not analyze historical production audit logs or
  perform a forensic investigation.

## Reference checks

The browser defenses follow [OWASP’s origin/fetch-metadata guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
SSH pinning and process APIs were checked against the installed library and
[AsyncSSH’s API documentation](https://asyncssh.readthedocs.io/en/latest/api.html).
