# Keywright v0.0.1 release checklist

Status: unreleased preparation. The repository starts with a sanitized source snapshot
and fresh history. Server, client and optional router share the planned 0.0.1 version.
The supported first-run target is the core SSH/MCP approval and revocation flow.

Completed in the initial migration:

- Selected source, tests and generic configuration without operational reports or history.
- Replaced live knowledge-corpus dependencies with synthetic fixtures.
- Added a broker-only Compose path with loopback binding and optional service overlays.
- Added test/package-build CI. No package publishing workflow is enabled yet.

Before tagging or making the repository public:

- [ ] Review a dedicated secret scan and privacy audit of the exact candidate and artifacts.
- [ ] Select a project-level license and align package metadata. The client's existing MIT
      declaration does not settle the license of the whole project.
- [ ] Pass CI on supported Python runtimes and test wheel/source/container installs.
- [ ] Complete the disposable VM checklist in `deploy/README.md`.
- [ ] Add a security reporting route and contribution guidance.
- [ ] Review shared-knowledge retrieval and experimental chunking before claiming support.
- [ ] Run real disposable PostgreSQL/pgvector tests for hybrid-retrieval support.
- [ ] Confirm package-name access and trusted publishing, then add a tested publish workflow.
- [ ] Freeze the source commit, record artifact hashes, and write release notes.

LLM gateways, OIDC, inventory, semantic advice, knowledge and mail are optional.
MCP resources/prompts and tamper-evident audit history are subsequent work.
Use synthetic demonstrations and never merge historical operational branches into this repository.
