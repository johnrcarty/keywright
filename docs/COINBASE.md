# Coinbase

The **Coinbase** entry in **Resources → Add resource** connects a managed SSH host
running the official Coinbase CLI. It is available in the source checkout, ahead
of the next release. Agents run Coinbase commands through Keywright's existing SSH
approval and audit flow; this preset does not expose a separate set of MCP tools.

Coinbase currently allowlists clients for its remote MCP service. Keywright is not
on the published list; successful dynamic client registration alone does not grant
access. Coinbase recommends its CLI for custom clients. See the official
[setup guide](https://docs.cdp.coinbase.com/coinbase-for-agents/skill.md) and
[supported clients](https://docs.cdp.coinbase.com/ai-agents/coinbase-for-agents/coinbase-mcp#supported-harnesses).
The preset does not register Keywright as another client or borrow another app's tokens.

## Set up the host

1. Choose a host reachable from Keywright and an SSH account for Coinbase. The form
   suggests `coinbase`; create that account on the host or use an existing account.
2. Install Node.js 22 or later and `@coinbase/coinbase-cli` on that host, following
   Coinbase's setup guide. Verify with `coinbase --version`. Make the executable
   available in the account's non-interactive SSH PATH.
3. Create a CDP API key in the [Coinbase developer portal](https://portal.cdp.coinbase.com/api-keys/secret),
   scoped to the intended accounts and operations. View access is sufficient for
   balance checks; Trade and Transfer permissions enable their respective operations.
4. Under the same SSH account, configure the CLI using
   `coinbase env live --key-file /path/to/key.json`. Keep this credential setup on
   the host, outside agent prompts and Keywright command history. On Linux, follow
   Coinbase's keyring instructions and ensure the credential store is accessible
   in a non-interactive SSH session. Installing `secret-tool` alone does not verify that.
5. In Keywright, choose **Coinbase**, enter the host and SSH account, and keep
   **Ask for approval**. Save, generate or supply an SSH key, and enroll it on the
   host using the resource page.

Keywright stores the SSH credential. The CDP key remains in the remote CLI's
credential store. Adding the resource does not install software, configure a CDP
key, grant agents access, or make a Coinbase API call.

## Verify and use

**Test connection** verifies SSH connectivity and host-key handling only. After
that succeeds, verify Coinbase itself through an approved read:

```bash
kw run Coinbase -r "Check Coinbase CLI installation" -- coinbase --version
kw run Coinbase -r "Verify Coinbase access" -- coinbase balance
kw run Coinbase -r "List Coinbase portfolios" -- coinbase portfolios list
```

Use the actual resource name if it differs from `Coinbase`. Coinbase access is
verified only when an authenticated read succeeds. Authentication and keyring
errors must be fixed under the configured SSH account on the host.

Commands use normal Keywright SSH access rules, approvals, and audit records.
The preset does not constrain the SSH account to Coinbase commands or install
standing allow rules. Limit the host account and review commands accordingly.
Trading, transfers, and paid x402 calls remain separate operations requiring the
appropriate Coinbase permissions and Keywright authorization. Capabilities depend
on the account, region, and installed CLI version. Consult current CLI help and
Coinbase's guide for argument schemas; do not retry an uncertain write blindly.

Validation uses synthetic SSH responses and an isolated database. No live account
authentication, trade, transfer, or payment is part of these tests.

## Related integrations

[Robinhood](ROBINHOOD.md) is available as a remote MCP preset with browser sign-in.
