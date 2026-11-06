# Keywright

Give AI agents temporary access to infrastructure without handing them your credentials.
Keywright is a self-hosted broker for SSH hosts and MCP tools, with human approval,
scoped access, revocation and an audit trail.

**[v0.0.1 is available](https://github.com/johnrcarty/keywright/releases/tag/v0.0.1).**
This first experimental release includes public prebuilt images for Linux x86-64 and
ARM64, Python packages, and verified source and license materials. Keywright is Apache-2.0.

## Install the prebuilt broker

You need Docker Engine with the Compose plugin. No Git checkout, Python installation
or local image build is needed.

1. Download `keywright-install.tar.gz` and `SHA256SUMS` from the
   [v0.0.1 release](https://github.com/johnrcarty/keywright/releases/tag/v0.0.1)
   into a dedicated installation directory. The bundle pins the exact multi-platform image digest.
2. Verify the archive, extract it, verify its files, and start the broker:
   ```bash
   sha256sum --ignore-missing -c SHA256SUMS
   tar -xzf keywright-install.tar.gz
   sha256sum -c SHA256SUMS
   docker compose up -d --wait
   ```

The source copy at `deploy/compose.yaml` also works on its own; it follows
`ghcr.io/johnrcarty/keywright:0.0.1-preview` unless `KEYWRIGHT_IMAGE` selects another tag
or digest. Use the release bundle for the pinned stable installation.
Public image downloads do not require a registry login.

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
   the published CLI using the instructions below.
4. Request one operation, approve it in the UI, and inspect its audit record.
5. Revoke the access and verify the operation needs approval again.

Phone notifications through Home Assistant or a webhook are optional. The base stack
needs no cloud account, model provider, identity provider or external database.

## Install the client

With Python 3.12 or newer and pipx:

```bash
pipx install keywright==0.0.1
kw login http://localhost:8700 --paste
kw setup check
```

Paste the agent token at the prompt. Run setup as the user who runs the agent.
Optional integration commands are `kw setup claude-code` and `kw setup codex`.
See the [client guide](client/README.md) for installing a separate Python runtime.

## Develop from source

For a local Docker build, clone the repository and explicitly add the development overlay:

```bash
docker compose -f deploy/compose.yaml -f deploy/build.compose.yaml up -d --build
```

For direct Python development, Python 3.12 or newer and [uv](https://docs.astral.sh/uv/) are required:

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

- [DoorDash](docs/DOORDASH.md): guided `dd-cli` setup through a managed SSH host,
  including headless authentication (source checkout, unreleased).
- [Robinhood](docs/ROBINHOOD.md): accounts, market data, and trading through browser
  sign-in (source checkout, unreleased).
- [Coinbase](docs/COINBASE.md): guided Coinbase CLI setup through a managed SSH host
  (source checkout, unreleased).
- [CoinStats](docs/FEATURES.md#oauth-for-upstream-mcp-servers-including-notion-and-coinstats):
  crypto data and portfolios through browser sign-in (source checkout, unreleased).
- [Homelab connectors](docs/CONNECTORS.md): Proxmox VE, Pi-hole v6, Home Assistant,
  Jellyfin, Sonarr, Radarr and authentik setup and read-only tools (source checkout, unreleased).
- [Feature and configuration reference](docs/FEATURES.md): permissions, notifications,
  LLM gateways, OIDC, inventory, shared knowledge and result inspection.
- [Deployment guide](deploy/README.md): base stack, optional LLM/knowledge services and
  a disposable VM acceptance checklist.
- [Mail router](router/README.md): optional agent that routes mail through brokered tools.
- [Release checklist](docs/RELEASE_PLAN.md): release evidence and publication record.
- [Security reporting](SECURITY.md), [support scope](SUPPORT.md), and [contributing](CONTRIBUTING.md).
- [Third-party source and notice materials](third_party/README.md).

Knowledge retrieval remains experimental; the synthetic evaluation does not establish
quality for every corpus or reliable no-answer detection. Optional features are not all
covered by the minimal-stack installation check.

Keywright is a credential trust boundary. Protect its host and backups. Command scope
matching is not a shell sandbox, and output inspection cannot prove arbitrary text is
secret-free. The [historical source security review](docs/SECURITY_REVIEW.md) records
prior findings; it is not a certification of this candidate.

## License

Keywright is licensed under [Apache-2.0](LICENSE). Copyright 2026 Keywright
contributors. See [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_NOTICES).
Commercial use and proprietary extensions are permitted under the license's terms.
Unless explicitly stated otherwise, contributions intentionally submitted for
inclusion in Keywright are provided under Apache-2.0.
