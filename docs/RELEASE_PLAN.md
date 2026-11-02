# Keywright v0.0.1 release checklist

Status: v0.0.1 published on 2026-11-02 from frozen commit
`307b3da1773127cbe8e2bd3ab7a74f07d453353e`. The repository starts with a sanitized source
snapshot and fresh history. Server, client and optional router share version 0.0.1.
The supported first-run target includes the core SSH/MCP approval and revocation flow
and shared knowledge. Knowledge stays in v0.0.1; semantic search adds an optional
PostgreSQL/pgvector index and embedding endpoint.

Publication evidence:

- [Public release, installer, sources and checksums](https://github.com/johnrcarty/keywright/releases/tag/v0.0.1).
- [Final tag CI](https://github.com/johnrcarty/keywright/actions/runs/41540163307): passed.
- [Production PyPI publication and downloaded wheel/source installs](https://github.com/johnrcarty/keywright/actions/runs/41544947436): passed.
- Release assets `FINAL-RELEASE-REVIEW.json` and `LAUNCH-VERIFICATION.json` record the audit,
  artifact hashes, anonymous image/source checks, clean installation and preview cleanup.
- The v0.0.1 tag and published Python files remain frozen. Later documentation updates on
  `main` do not change those artifacts. Use a new shared version for the next package release.

Completed in the initial migration:

- Selected source, tests and generic configuration without operational reports or history.
- Replaced live knowledge-corpus dependencies with synthetic fixtures.
- Added a broker-only Compose path with loopback binding and optional service overlays.
- Added test/package-build CI and prebuilt broker image publishing for AMD64 and ARM64.
- Standard Compose installations pull images; local builds use an explicit development overlay.
- Image installation bundles pin the manifest digest. All three Python packages are published on PyPI.

Completed release gates:

- [x] Audit source/history, Python artifacts, installer and both image architectures for
      candidate `f3e4e5f`; no confirmed setup/family identifiers or first-party secrets found.
      See `RELEASE_AUDIT.json` for exact digests, methods and scope. Repeat for a changed candidate.
- [x] Adopt Apache-2.0 across the server, client and router; ship license and notice files
      with Python distributions, container images and installation bundles.
- [x] Implement third-party license remediation: reviewed supplemental native notices,
      immutable source lock and native hashes, pinned container dependencies, no pip cache,
      and source-material images published before application images. Source digests are
      recorded on the application image and verified after pulling both architectures.
      Version tags prepare draft release assets with source archives, notices and checksums.
      See `third_party/README.md` and `LICENSING_RELEASE.json` for passing native publication
      and source-retrieval checks at `23d1fb8`. `RELEASE_AUDIT.json` preserves the original findings.
- [x] Pass CI on Python 3.12–3.14 and test wheel/source/container installs for candidate
      `10af43c`; final release changes must retain passing checks.
- [x] Complete core and knowledge acceptance on a clean AMD64 VM using the published bundle.
      See `VM_ACCEPTANCE.json`; optional proxy and external notification checks remain separate.
- [x] Add `SECURITY.md`, `SUPPORT.md` and `CONTRIBUTING.md`, with private vulnerability
      reporting, latest-release support scope and Apache-2.0 contribution terms.
- [x] Enable GitHub private vulnerability reporting and verify its public security-page entry point.
- [x] Remove the 15 inventoried pre-remediation preview versions before making GHCR public.
      All 25 covered application/source versions present at cleanup were retained, including
      every linked source-image digest. Preserve corresponding sources for distributed images.
- [x] Complete the knowledge release gates below, including real PostgreSQL/pgvector tests.
- [x] Confirm all three Python package names through successful TestPyPI and PyPI trusted publication.
- [x] Obtain owner launch approval, make the repository/package public, and verify anonymous
      pulls for both image architectures and both matching source images.
- [x] Freeze the source commit, record artifact hashes, and publish release notes. Final review
      covered retained runtime layers/configuration, installer, source archives, CI logs/build
      records and Python artifacts; no confirmed secrets or setup/family identifiers were found.
      Recheck privacy and licensing for future changed candidates.

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

- [x] Choose Apache-2.0 and align all three package metadata files.
- [x] Use GitHub private vulnerability reporting and document latest-0.0.x support.
      Reporting was enabled and its entry point verified at public launch.
- [x] Owner configured PyPI and TestPyPI accounts and publishers; successful OIDC uploads verified
      publishing access. Keep credentials and recovery codes outside the repository and knowledge.
- [x] Publish `keywright`, `keywright-server` and `keywright-router` version 0.0.1 on both indexes.
- [x] Register all three pending Trusted Publishers on PyPI: owner
      `johnrcarty`, repository `keywright`, workflow filename `publish-python.yml`.
      Use distinct environments per package as listed below. Pending publishers cannot share
      the same owner/repository/workflow/environment configuration across project names.
      The owner screenshot confirms `keywright` / `pypi`, `keywright-server` / `pypi-server`
      and `keywright-router` / `pypi-router`. First publication used all three successfully.
      Preserve the matching workflow and environment settings for future releases.
- [x] Register the three pending Trusted Publishers on TestPyPI using the settings below;
      the owner screenshot confirmed all mappings, and the rehearsal used all three successfully.
- [x] Create all six matching GitHub environments. TestPyPI permits `main` and `v*` tags;
      PyPI permits only `v*` tags. All three production environments require owner review;
      the workflow refuses production uploads until that protection is present.
- [x] Implement `publish-python.yml` with a validation-only default and `id-token: write`
      only on upload jobs. Each publisher receives only its own package files. Local validation
      passed strict wheel/sdist metadata checks for all six artifacts, clean wheel/source installs,
      entry-point and hazard checks, workflow lint and six publication guard regression tests.
- [x] Pass the workflow's GitHub Actions validation-only run and full CI at `fffef4c`:
      [Python validation](https://github.com/johnrcarty/keywright/actions/runs/41536560022)
      and [full CI](https://github.com/johnrcarty/keywright/actions/runs/41535548976).
      All index upload jobs were skipped. Full CI includes Python 3.12–3.14 and both native
      image/source-material retrieval checks. Repeat for a changed upload candidate.
- [x] Freeze/review the upload candidate, run TestPyPI upload and clean downloaded-artifact
      install checks, then publish the same reviewed bytes to PyPI and verify them again.
      Index SHA-256 checks reject existing versions with different bytes. Ordinary dependencies
      come from PyPI separately from the TestPyPI artifacts. See `PYTHON_PUBLISHING.md`.
- [x] Complete the owner-approved public launch after acceptance, verify anonymous installation,
      and publish the GitHub Release with installation assets, sources, notices and checksums.

| Package | PyPI environment | TestPyPI environment |
| --- | --- | --- |
| `keywright` | `pypi` | `testpypi` |
| `keywright-server` | `pypi-server` | `testpypi-server` |
| `keywright-router` | `pypi-router` | `testpypi-router` |

Publishing references: [PyPI pending publishers](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/),
[publisher configuration uniqueness](https://github.com/pypi/warehouse/blob/main/warehouse/oidc/models/github.py)
and [PyPA GitHub Actions publishing guide](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/).

LLM gateways, OIDC, inventory, semantic advice and mail are optional integrations.
MCP resources/prompts and tamper-evident audit history are subsequent work.
Use synthetic demonstrations and never merge historical operational branches into this repository.
