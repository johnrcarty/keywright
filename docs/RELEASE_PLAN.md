# Keywright v0.0.1 release checklist

Status: unreleased preparation. The repository starts with a sanitized source snapshot
and fresh history. Server, client and optional router share the planned 0.0.1 version.
The supported first-run target includes the core SSH/MCP approval and revocation flow
and shared knowledge. Knowledge stays in v0.0.1; semantic search adds an optional
PostgreSQL/pgvector index and embedding endpoint.

Completed in the initial migration:

- Selected source, tests and generic configuration without operational reports or history.
- Replaced live knowledge-corpus dependencies with synthetic fixtures.
- Added a broker-only Compose path with loopback binding and optional service overlays.
- Added test/package-build CI and prebuilt broker image publishing for AMD64 and ARM64.
- Standard Compose installations pull images; local builds use an explicit development overlay.
- Image installation bundles pin the manifest digest. Python package publishing remains pending.

Before tagging or making the repository public:

- [ ] Review a dedicated secret scan and privacy audit of the exact candidate and artifacts.
- [ ] Select a project-level license and align package metadata. The client's existing MIT
      declaration does not settle the license of the whole project.
- [x] Pass CI on Python 3.12–3.14 and test wheel/source/container installs for candidate
      `10af43c`; final release changes must retain passing checks.
- [x] Complete core and knowledge acceptance on a clean AMD64 VM using the published bundle.
      See `VM_ACCEPTANCE.json`; optional proxy and external notification checks remain separate.
- [ ] Add a security reporting route and contribution guidance.
- [x] Complete the knowledge release gates below, including real PostgreSQL/pgvector tests.
- [ ] Confirm Python package-name access and trusted publishing, then add a tested PyPI workflow.
- [ ] Approve public repository/package visibility and verify anonymous image pulls.
- [ ] Freeze the source commit, record artifact hashes, and write release notes.

## Knowledge release gates

- [x] Configure every supported Python CI job to run the two existing real PostgreSQL/pgvector
      integration tests using an isolated service database and deterministic test embeddings.
      Local release validation: 1,073 tests passed with no skips on Python 3.14. The updated
      CI passed on Python 3.12–3.14, including the previously skipped database tests.
- [x] Add a public synthetic text-retrieval baseline: nine cases covering literal questions,
      paraphrases, mixed projects, historical/current guidance, absent vocabulary and empty scope.
      `tests/test_knowledge_retrieval.py` checks relevant passages, exact source-line citations
      and zero foreign-scope hits. It does not establish real-model semantic quality or general
      no-answer detection. Keep raw private evaluations out.
- [x] Evaluate current section-aware chunks with a fresh semantic index and local
      `nomic-embed-text` embeddings. All seven answerable synthetic benchmark questions found
      their relevant passage first; a separate semantic-only probe also ranked first. This
      small benchmark does not establish large-corpus quality or general no-answer detection.
- [x] Test the prebuilt knowledge installation on a clean VM, through both UI and MCP:
      proposal, review, publication, text search, reindex and hybrid search with current coverage.
- [x] Verify revisions before/after reindex, archive/expiry, collection permissions and
      revocation; unavailable embedding/database services must preserve text fallback.
- [x] Verify persistence, backup/restore and rebuilding the derived index from canonical data.
- [x] Include knowledge overlay, schema, configuration examples and instructions in the
      install-bundle builder. Explain manual rebuilds and embedding-provider data flow.
- [x] Verify the expanded downloaded CI artifact on both architectures, plus full AMD64 VM
      acceptance. A complete ARM64 VM run is not part of this evidence.

The sanitized [VM acceptance record](VM_ACCEPTANCE.json) identifies the exact image and test
methods. Hybrid search still returns ranked references for some absent topics; consumers must
check whether citations support the question. Search scores are not answer-confidence values.

## Owner todos and Python package publishing

- [ ] Choose the project-wide license; align all three package metadata files.
- [ ] Confirm the security-reporting destination and release support scope.
- [ ] Create or sign in to PyPI and TestPyPI accounts, verify email and configure required
      account security. Keep credentials and recovery codes outside the repository and knowledge.
- [ ] Confirm access to package names `keywright`, `keywright-server` and `keywright-router`.
      A missing project page does not reserve a name or guarantee it can be registered.
- [ ] After the publishing workflow is implemented, configure a Trusted Publisher for each
      package on both indexes: owner `johnrcarty`, repository `keywright`, planned workflow
      filename `publish-python.yml`, environments `pypi` and `testpypi` respectively.
      Match the final workflow filename exactly; these are planned settings, not configured ones.
      New names use pending publishers, which do not reserve the names before first publication.
- [ ] Create matching GitHub environments; restrict production publication to the reviewed
      release and configure the desired release approval protection.
- [ ] Implement a tested OIDC publishing workflow with `id-token: write` only on upload jobs.
      Build and check wheel/sdist metadata, test TestPyPI upload/install in a clean environment,
      then publish the reviewed distributions to PyPI and verify CLI/server/router entry points.
      Install ordinary dependencies from PyPI separately from the TestPyPI package artifacts.
- [ ] Confirm the final release and repository/container visibility change after acceptance;
      verify anonymous pulls and attach installation assets and checksums to the GitHub Release.

Publishing references: [PyPI pending publishers](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
and [PyPA GitHub Actions publishing guide](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/).

LLM gateways, OIDC, inventory, semantic advice and mail are optional integrations.
MCP resources/prompts and tamper-evident audit history are subsequent work.
Use synthetic demonstrations and never merge historical operational branches into this repository.
