# Deployment and VM testing

The minimal stack runs one broker container and stores its database, keys and signing
secret in the `keywright-data` volume. It does not require any external service.

```bash
docker compose -f deploy/compose.yaml config
docker compose -f deploy/compose.yaml up -d --build
curl --fail http://127.0.0.1:8700/healthz
```

Use a disposable Debian 13 or Ubuntu 24.04 VM with Docker Engine and the Compose plugin.
A starting allocation for the core broker is 2 vCPU, 2 GiB RAM and 16 GiB disk; optional
model/index services need additional resources. Use a fresh data volume and synthetic
resources. Keep real provider credentials, home infrastructure, mail and knowledge
exports out of this environment.

The port binds to loopback by default. Connect with an SSH tunnel and complete admin
setup before configuring remote access. For HTTPS behind a proxy, set `KW_PUBLIC_URL`
and the exact `KW_TRUSTED_PROXIES` addresses in a local `deploy/.env` file. Configure the
proxy and firewall deliberately before changing `KW_BIND_ADDRESS`.

## Optional LLM gateway

From `deploy/`, copy `.env.example` to `.env` and `litellm.env.example` to `litellm.env`.
Fill the database password, master key and salt with independently generated values.
Keep the salt stable. Supply provider credentials only if testing the gateway.

```bash
docker compose -f compose.yaml -f llm.compose.yml up -d --build
```

Register `http://litellm:4000` as an LLM gateway in Keywright and confirm database-backed
budgets work. PostgreSQL and LiteLLM have no published host ports.

## Optional knowledge index

Add `KNOWLEDGE_PG_PASSWORD` to `.env`, and copy `knowledge.env.example` to `knowledge.env`.
Set the index connection password and a dedicated embedding credential. Then add the
`knowledge.compose.yml` overlay to the LLM command above. Local text search does not
require this overlay. Index coverage and retrieval quality need separate verification.

The Authentik provisioning helper in `stack/authentik-keywright.py` takes all identities
and HTTPS origins from environment variables. Its credential export mode is for transfer
into a protected environment file, never interactive output.

## Acceptance checklist

- [ ] Fresh image builds and starts with an empty data volume; `/healthz` reports 0.0.1.
- [ ] Complete administrator setup through the SSH tunnel and log in again.
- [ ] Add one disposable SSH target and verify its host-key fingerprint.
- [ ] Enroll a test agent, approve one exact command, and verify its audit record.
- [ ] Repeat it and confirm one-time access was consumed.
- [ ] Verify deny, timed expiry, revocation and agent-token rotation.
- [ ] Repeat approval and revocation against a synthetic upstream MCP service.
- [ ] Restart the broker and verify resources and audit history persist.
- [ ] Stop the broker, back up the entire data volume, restore to a second empty volume,
      and verify startup, login and audit records. Treat backups as credentials.
- [ ] Verify proxy HTTPS and notifications separately if included in release claims.

Record VM identity, addresses and raw logs in a private operations record outside this
repository. Commit only sanitized results. Stop the broker before copying its SQLite
files; an inconsistent live copy is not a valid backup. Never delete a data volume as
part of a normal upgrade.
