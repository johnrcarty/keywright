# DoorDash CLI

Choose **DoorDash** in **Resources → Add resource** to connect an SSH host running
the official `dd-cli`. The preset is available in the source checkout, ahead of
the next release. It runs the CLI on the enrolled SSH host and adds `doordash_shop` for shopping sessions,
reviewed command guidance and priced checkout approvals.

## Guided setup on an existing host

Under **Resources → Add resource → DoorDash**, choose an existing enrolled SSH host
and continue. The next screen shows the host and SSH account before you press
**Install DoorDash CLI**. Keywright reuses that connection's account, key and pinned
host key, creates a separate DoorDash resource in **Ask for approval** mode, and
leaves the original host's settings and access rules unchanged.

Guided installation currently supports glibc Linux x86_64 with Python 3.9+, outbound
HTTPS and a writable home directory. It installs the official **v0.2.6** release,
verified against its published SHA256, under
`~/.local/share/keywright/cli/<resource-id>/`. No sudo or system-wide PATH changes
are required. Keywright adds this private installation to PATH for commands through
the DoorDash resource only. The account and host administrators can access its credentials.

1. **Install** verifies the download and tests that the executable starts.
2. **Sign in to DoorDash** starts the CLI's headless browser flow. Open the link
   on your phone or computer and sign in with your approved beta account.
3. The final browser page may show a localhost connection error. Copy its full
   address into **Return address or sign-in code** and complete sign-in within
   10 minutes. Alternatively, use the password field for an already exported token.
4. **Verify DoorDash access** checks order-history access, discarding order output.
   It does not place a purchase.

The callback travels over SSH stdin, never in command arguments or audit records.
The CLI exchanges it on the host and saves the token atomically in a mode-0600 file.
Keywright's database stores setup progress, not the token. Headless tokens last
about 72 hours; return to **Manage DoorDash sign-in** to renew one. Setup jobs run
in the background, reject duplicate steps, and can be revisited after closing the page.
Interrupted jobs require an explicit retry; they are never automatically replayed.

The SSH connection is copied at setup time. If its account or key later changes,
create a new setup for the new connection. Deleting the resource does not uninstall
the remote CLI or remove its host-side token. Shared SSH keys are retained while
another resource still references them.

## Manual installation and authentication

DoorDash currently distributes binaries for Apple Silicon macOS and glibc-based
Linux x86-64. Choose the matching archive from the official
[releases](https://github.com/doordash-oss/doordash-cli/releases), verify its published
SHA256 checksum, and follow the included `quickstart.txt`. Install `dd-cli` on the
remote account's non-interactive SSH PATH. The preset suggests the account name
`doordash`; create it or select an existing account.

Use your approved DoorDash account to authenticate:

- On a host with a browser and OS keychain, run `dd-cli login` as the same account
  Keywright will use over SSH.
- On a headless host without a keychain, securely supply `DD_CLI_ACCESS_TOKEN` to
  the process environment. Obtain it with `dd-cli export-token` on a signed-in
  machine. Transfer it directly to the host's secret store; do not paste it into
  chat, a resource description, or a `kw run` command. The environment variable
  takes precedence over keychain authentication.

The [official setup instructions](https://github.com/doordash-oss/doordash-cli)
and [authentication notes](https://github.com/doordash-oss/doordash-cli/blob/main/doordash-cli-skills/README.md)
describe these paths. Release v0.2.6 also adds two-step remote login; consult the
installed `dd-cli login --help` and `dd-cli export-token --help` for its current options.

For headless use, configure a host-side launcher or secret manager that loads the
token before executing `dd-cli`. A token exported in your interactive shell is not
automatically available to a fresh SSH command. Keep the actual token out of shell
arguments, tracing output, and version control. Manual connections require you to
configure that host environment; guided setup handles the host-side token file and
loads it for the DoorDash resource. Renew an expired token through DoorDash's sign-in flow.

## Connect and verify manually

1. Select **DoorDash → Set up a host manually**, enter the SSH host and account, and keep **Ask for approval**.
2. Save, generate or supply an SSH key, and enroll it on the host.
3. Use **Test connection** to verify SSH connectivity. This does not test DoorDash login.
4. Verify the binary and account access with approved commands:

```bash
kw run DoorDash -r "Check DoorDash CLI installation" -- dd-cli --help
kw run DoorDash -r "Verify DoorDash access" -- dd-cli order history --intent "Verify DoorDash access"
```

Use your saved resource name if different. An authenticated read must succeed
before treating the account connection as verified. Order history may contain
private purchases and delivery details; the result is returned through the normal
SSH output path. Tests for this preset use synthetic responses and no real account.

## Ordering through Keywright

```bash
kw shop DoorDash guide
kw shop DoorDash start -r "Prepare the requested meal"
kw run DoorDash -r "Inspect existing carts" -- dd-cli --json-output cart list --intent "Review the requested order"
kw shop DoorDash status
kw shop DoorDash checkout --cart-uuid CART_ID --card-id CARD_ID --tip-cents 500 -r "Place the reviewed order"
```

`start` asks once for **20 minutes of browsing and cart preparation**, bound to the
agent, client session, resource and SSH account. Expiry and revocation stop future
calls. Standing deny rules still apply to every command. The reviewed command
contract distinguishes reads, cart changes, and purchases; preview with
`--fulfillment` or `--selected-budget-id` counts as a cart change. Changing account
defaults, credentials, courier operations and business administration is outside
this contract. The same separation is available through the `doordash_shop` MCP tool.

`guide` returns a local, reviewed **v0.2.6** reference, including modifier discovery,
DoubleDash and exit-code recovery. It makes no remote help call and caches no
account output or prices. Each executed command checks the installed version in
the same SSH connection and refuses an unsupported version. Commands are parsed
as arguments and reconstructed with shell quoting. Arbitrary shell programs and
raw `order submit` are refused on DoorDash resources; maintenance uses the underlying
host's separate permissions.

`checkout` requires an explicit card and tip, previews with that card, and shows
items, preparation instructions, destination, charges, total, tip, payment and
handoff requirements in one approval. Timed grants, broad allow rules, open resource
mode and automatic semantic approval cannot authorize this purchase. Approval
binds the exact quote and expires within five minutes (sooner if the request or
DoubleDash offer expires). A fresh preview after approval must match before submit.

Checkout currently supports personal USD orders with an existing delivery/pickup
cart, optional scheduling, priority, and credit opt-out. Set fulfillment while
preparing the cart. Work-benefit submission and bundles whose primary order has
not been placed are outside this checkout flow. An incomplete or unrecognized
quote fails closed; review it in DoorDash rather than bypassing the priced gate.

A durable reservation prevents a second submit attempt for the same resource/cart,
including after a timeout, crash or restart. Check order status after submission:
CLI success can mean processing rather than store acceptance or successful payment.
There is deliberately no automatic retry or agent-accessible reset of that reservation.
DoorDash has no CLI maximum-charge/idempotency option: the final preview reduces
stale-quote risk but cannot make provider pricing and submission atomic. The provider
can still change availability or pricing between the final check and processing.

DoubleDash status/options responses expose the offer deadline and remaining seconds.
Keywright records links observed from `doubledash add`; JSON output is enforced for
these commands. Checkout refuses a known failed link, expired offer, or linkage to
an unsubmitted primary cart. Read options/status before adding so Keywright has the
offer deadline. Never guess modifier IDs or retry a partial/uncertain add blindly.

Results include client exchange, broker gate, SSH connection, and remote process
timing where available. The remote process measurement includes CLI and provider
work; it is not a provider-only measurement. Approval pages display pending stage
and expiry; session status reports the grant's remaining lifetime. SSH connections
are still opened per command; connection pooling is not part of this change.

These controls apply to the DoorDash resource. Independently granted shell access
to its underlying host remains a separate trust boundary.

## Beta feedback

`kw guide` and Keywright's MCP instructions tell agents to summarize observed DoorDash
CLI behavior after meaningful workflows and propose sanitized feedback when an accessible
feedback collection exists. [CLI feedback guidance](CLI_FEEDBACK.md) describes a shared
collection for current and future agents, talking points for beta feedback phone calls,
and human review. Notes capture successes, friction, bugs, and suggestions with supporting
evidence. The user discusses them by phone; nothing is automatically sent to DoorDash.

## Host or container?

With this SSH preset, `dd-cli` executes on the configured SSH host. It may be the
Keywright VM itself under a dedicated SSH account, or another supported host. The
broker container does not execute local commands; adding the binary to its Docker
image alone does not make this integration work.

A separate CLI runner container is also possible: install `dd-cli` in that image,
provide its token at runtime, and expose a `dd-cli` launcher on the SSH host that invokes the container. Arbitrary
`docker exec` commands belong to the underlying host resource; the DoorDash resource
accepts the reviewed `dd-cli` contract. This requires a configured runner and appropriate
Docker permissions; the preset does not provision one.
Bake only the executable into an image, never its token. Host installation under a
dedicated account is the simplest deployment for the current preset.
