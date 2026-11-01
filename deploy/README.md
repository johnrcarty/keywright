# Deployment and VM testing

The standard installation pulls a prebuilt broker image from
`ghcr.io/johnrcarty/keywright`. Docker selects Linux x86-64 or ARM64 automatically.
The database, SSH keys and signing secret live in the `keywright-data` volume.
The core broker needs no external service.

Download the **keywright-install** artifact from a successful image publishing run.
It contains `compose.yaml`, `image.txt`, `SHA256SUMS`, this guide, and the optional LLM
and knowledge overlays, schema and environment examples. The broker image is pinned to
its exact digest. Extract into a dedicated installation directory; no source checkout is needed.

```bash
# Private preview only: use a classic GitHub token with read:packages and package access.
docker login ghcr.io -u YOUR_GITHUB_USERNAME
sha256sum -c SHA256SUMS
docker compose up -d --wait
curl --fail http://127.0.0.1:8700/healthz
```

The package remains private during release preparation. A public image will allow
anonymous pulls. Credentials entered at the login prompt stay out of shell history.
See [GitHub's registry authentication guide](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-to-the-container-registry).

## Image versions and updates

- `0.0.1-preview` follows successful builds from the current development series on `main`.
- `sha-<full commit>` identifies the source revision. Pin the registry digest to select exact image bytes.
- A matching `v0.0.1` Git tag publishes image tag `0.0.1` after tests and both native image checks pass.
  The stable tag has not been published yet. The workflow does not publish a `latest` alias.

The downloadable install file pins the multi-platform digest and supports either architecture.
To update it, back up the stopped broker's full data volume, download a new successful install
artifact into the same installation directory, verify its checksums, and run
`docker compose up -d --wait` again. Keep the prior Compose file and matching data backup
for rollback. Do not run `down --volumes` during normal upgrades.

When using the source `compose.yaml` with the preview tag, fetch updates explicitly with
`docker compose pull` before `docker compose up -d --wait`. `KW_HTTP_PORT` selects the
host port (8700 by default); the container continues listening on 8700.

## Development builds

From a source checkout, explicitly opt in to building locally:

```bash
docker compose -f deploy/compose.yaml -f deploy/build.compose.yaml up -d --build
```

The normal Compose file and optional service overlays contain no build directives.
The prebuilt broker includes the optional PostgreSQL driver, so knowledge indexing does
not require rebuilding the image or installing Python packages at startup.

## Disposable VM testing

Use a disposable Debian 13 or Ubuntu 24.04 VM with Docker Engine and the Compose plugin.
A starting allocation for the core broker is 2 vCPU, 2 GiB RAM and 16 GiB disk; optional
model/index services need additional resources. Use a fresh data volume and synthetic
resources. Keep real provider credentials, home infrastructure, mail and knowledge
exports out of this environment.

The port binds to loopback by default. Connect with an SSH tunnel and complete admin
setup before configuring remote access. For HTTPS behind a proxy, set `KW_PUBLIC_URL`
and the exact `KW_TRUSTED_PROXIES` addresses in a local `.env` file beside your Compose file. Configure the
proxy and firewall deliberately before changing `KW_BIND_ADDRESS`.

## Optional LLM gateway

From `deploy/`, copy `.env.example` to `.env` and `litellm.env.example` to `litellm.env`.
Fill the database password, master key and salt with independently generated values.
Keep the salt stable. Supply provider credentials only if testing the gateway.

```bash
docker compose -f compose.yaml -f llm.compose.yml up -d
```

Register `http://litellm:4000` as an LLM gateway in Keywright and confirm database-backed
budgets work. PostgreSQL and LiteLLM have no published host ports.

## Optional knowledge index

The prebuilt image already includes the database driver. Add `KNOWLEDGE_PG_PASSWORD` to `.env`, and copy `knowledge.env.example` to `knowledge.env`.
Set the same database password in `knowledge.env` and `.env` (URL-encode it in the connection
URL if it contains reserved URL characters), plus the embedding endpoint, model and a dedicated
embedding credential. With the optional LiteLLM gateway configured above:

```bash
docker compose -f compose.yaml -f llm.compose.yml -f knowledge.compose.yml up -d --wait
```

If using an existing compatible embedding endpoint, set its `/v1` base in `knowledge.env`
and omit `llm.compose.yml`. Local text search needs neither overlay. Index coverage and
retrieval quality need separate verification. The optional Git import directory is not mounted
by default; importing a checkout requires an explicit read-only mount.

Knowledge documents remain in the broker's data volume; PostgreSQL holds a derived search
index. Semantic indexing sends document passages to the configured embedding endpoint, and
semantic queries send search text there. Choose an endpoint suitable for that data. Provider
credentials belong in the local environment file, never in documents or agent arguments.

Publishing updates text search immediately. Semantic indexing is manual: use the collection's
rebuild-index action after publishing or changing embedding models, then check that diagnostics
report current coverage. A missing, incompatible or unavailable index returns text results with
a warning. Rechunking existing documents is a separate explicit admin action, followed by reindexing.

Hybrid search ranks reference passages; it does not determine whether the collection can answer
every question. An unrelated query can still return candidates. Check the cited content before
using it as evidence; retrieval scores are not confidence in an answer.

The Authentik provisioning helper in `stack/authentik-keywright.py` takes all identities
and HTTPS origins from environment variables. Its credential export mode is for transfer
into a protected environment file, never interactive output.

## Acceptance checklist

The core and knowledge checks below passed on a clean Debian 13 AMD64 VM using candidate
`10af43c` and the downloaded, pinned prebuilt bundle. The [sanitized acceptance record](https://github.com/johnrcarty/keywright/blob/main/docs/VM_ACCEPTANCE.json)
records the image, test methods and limits. Treat this checklist as a fresh-install procedure
for subsequent releases; optional HTTPS and external notification checks were outside that run.

- [ ] Pull the published image and start it with an empty data volume; `/healthz` reports 0.0.1.
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

Knowledge acceptance, using synthetic documents and a disposable index:

- [ ] Create a collection, propose a document through MCP, review it in the UI and verify
      only published content is searchable. Check exact source-line citations.
- [ ] Configure the knowledge overlay and embedding endpoint; rebuild and verify current
      coverage plus genuinely semantic retrieval for a paraphrased question without word overlap.
- [ ] Publish a revision: verify immediate text discovery and missing/partial semantic coverage;
      rebuild and check current coverage. Repeat with a changed embedding model.
- [ ] Check collection permissions and revocation, literal path scoping, expired/archived content
      and a competing project. No unauthorized or out-of-scope excerpts may be returned.
- [ ] Stop the embedding service and then the index database separately; verify text fallback
      and a clear warning without credentials, provider error bodies or private connection details.
- [ ] Restore the stopped broker's complete volume into a fresh installation, verify documents,
      review metadata and citations, then rebuild an empty index and repeat retrieval checks.
- [ ] Record actual-model retrieval quality and cold/warm latency separately from mocked tests.

Record VM identity, addresses and raw logs in a private operations record outside this
repository. Commit only sanitized results. Stop the broker before copying its SQLite
files; an inconsistent live copy is not a valid backup. Never delete a data volume as
part of a normal upgrade.

## Publishing and verification

The workflow tests Python 3.12, 3.13 and 3.14 before building images on native AMD64 and
ARM64 runners. Each candidate is installed using only the standalone Compose file in
an empty temporary directory, with local building disabled. Checks cover health, first
administrator setup, MCP version, the optional database driver and persistence across
container replacement. After publication, fresh runners pull the manifest by digest and
repeat the install checks on each architecture. Only a successful complete run should be
used for deployment.

## License files

The installation bundle includes `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES`.
Keywright is Apache-2.0 licensed. Container images retain dependency license files
and system copyright notices; third-party components keep their own licenses.
