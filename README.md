# Keywright

Give AI agents temporary access to infrastructure without handing them your credentials.
Keywright is a self-hosted broker for SSH hosts and MCP tools, with human approval,
scoped access, revocation and an audit trail.

**v0.0.1 is in preparation.** This repository is an unreleased source preview. Package
publishing and a tagged release are pending installation, security and licensing review.

## Start a local preview

Docker with the Compose plugin is required. From this checkout:

```bash
docker compose -f deploy/compose.yaml up -d --build
```

Open <http://localhost:8700/ui> and set the administrator password. The default port is
bound to loopback. For a remote VM, use an SSH tunnel first:

```bash
ssh -L 8700:127.0.0.1:8700 user@test-vm
```

Then open the same localhost URL in your browser. Configure HTTPS and trusted proxy
addresses before exposing the broker to other machines. Keep the broker separate from
agent machines and use disposable targets for initial tests.

1. Add an SSH host or upstream MCP server under **Resources**.
2. Create an agent and copy its token once.
3. Point an MCP client at `/mcp` with `Authorization: Bearer <agent-token>`, or install
   the CLI from source using the instructions below.
4. Request one operation, approve it in the UI, and inspect its audit record.
5. Revoke the access and verify the operation needs approval again.

Phone notifications through Home Assistant or a webhook are optional. The base stack
needs no cloud account, model provider, identity provider or external database.

## Develop from source

Python 3.12 or newer and [uv](https://docs.astral.sh/uv/) are required:

```bash
uv venv
uv pip install -e ./client -e '.[dev]' -e ./router
KW_HOST=127.0.0.1 KW_DATA_DIR=./data .venv/bin/keywright-server serve
```

In a separate shell, run the client as the user who operates the agent:

```bash
.venv/bin/kw login http://localhost:8700 --paste
.venv/bin/kw setup check
```

Optional agent setup: `.venv/bin/kw setup claude-code` or `.venv/bin/kw setup codex`.
See the [client guide](client/README.md) for details.

```bash
.venv/bin/python -m pytest -q
node --test tests/test_topology_layout.cjs
```

The PostgreSQL/pgvector tests require an isolated database and `KNOWLEDGE_TEST_PG_URL`.
Never point test configuration at a production database.

## Optional integrations

- [Feature and configuration reference](docs/FEATURES.md): permissions, notifications,
  LLM gateways, OIDC, inventory, shared knowledge and result inspection.
- [Deployment guide](deploy/README.md): base stack, optional LLM/knowledge services and
  a disposable VM acceptance checklist.
- [Mail router](router/README.md): optional agent that routes mail through brokered tools.
- [Release checklist](docs/RELEASE_PLAN.md): remaining work before v0.0.1.

Knowledge chunking changes are experimental pending retrieval evaluation. Optional
features are not all covered by the minimal-stack installation check.

Keywright is a credential trust boundary. Protect its host and backups. Command scope
matching is not a shell sandbox, and output inspection cannot prove arbitrary text is
secret-free. The [historical source security review](docs/SECURITY_REVIEW.md) records
prior findings; it is not a certification of this candidate.
