# Robinhood

The **Robinhood** preset in **Resources → Add resource** connects to
`https://agent.robinhood.com/mcp/trading` using browser OAuth. It is included in
the 0.0.2 release candidate.

## Connect

1. Set `KW_PUBLIC_URL` to Keywright's public HTTPS origin and open the admin UI there.
2. Choose **Robinhood** from **Add resource**, name the connection, and keep
   **Agent access → Ask for approval**.
3. Select **Continue to Robinhood**, sign in, and complete Robinhood's agent
   onboarding. Trading requires a dedicated Robinhood Agentic/MCP account.
4. Return to Keywright and use **Test connection** to discover tools. Then approve
   a read operation to verify account access; tool discovery alone does not verify
   permission for every operation.

Robinhood documents reads across accounts, positions, balances, and transaction
history, while trading is confined to the agent account. Account eligibility and
available tools are controlled by Robinhood. If Robinhood rejects the client or
callback, contact its support; Keywright does not substitute another client's identity.
See Robinhood's [external-agent guide](https://robinhood.com/us/en/support/articles/agentic-trading-overview/).

## OAuth configuration

The preset trusts the MCP origin plus `https://robinhood.com` for browser consent
and `https://api.robinhood.com` for tokens. Keywright discovers the `internal` scope,
registers as **Keywright**, and uses authorization code with S256 PKCE. Leave the
advanced client and scope fields blank for automatic setup.

The public metadata checked for this integration advertises:

| Purpose | URL |
| --- | --- |
| Resource and issuer | `https://agent.robinhood.com/mcp/trading` |
| Protected-resource metadata | `https://agent.robinhood.com/.well-known/oauth-protected-resource/mcp/trading` |
| Authorization-server metadata | `https://agent.robinhood.com/.well-known/oauth-authorization-server/mcp/trading` |
| Browser consent | `https://robinhood.com/oauth` |
| Client registration | `https://agent.robinhood.com/oauth/trading/register` |
| Token exchange and refresh | `https://api.robinhood.com/oauth2/token/` |

Keywright stores tokens encrypted on the broker. Agent calls use the normal resource
access rules, approvals, and audit log. The preset creates no standing allow rules
or automatic trading permissions. **Disconnect** removes Keywright's local tokens;
revoke the provider authorization through Robinhood separately when needed.

## Discover tools

```bash
kw tool Robinhood --list
```

Use the saved resource name if it differs from `Robinhood`. Tool names and schemas
come from Robinhood at connection time; this preset does not hardcode an order API.

Tests simulate discovery, browser consent, token exchange and refresh, and approval
gating with an isolated provider. Live account sign-in and trading have not been
acceptance-tested. Adding this preset does not connect an account or place orders.
