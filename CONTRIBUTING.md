# Contributing to Keywright

Small, focused pull requests are welcome. Describe the problem, the resulting
behavior and how you verified it. Discuss substantial behavior or architecture
changes in an issue before implementation. Security reports belong in the
[private reporting process](SECURITY.md), not a public issue or pull request.

Follow the development setup in [README.md](README.md). Install the client, server
and optional router from the same checkout. Use disposable broker data, test SSH
targets and synthetic knowledge documents. Never connect automated tests to a
production database, service or knowledge corpus.

Run the relevant Python tests for your change and `node --test tests/test_topology_layout.cjs`
when changing topology behavior. Before merging, CI must pass the server/client/router
suite on Python 3.12–3.14, including the PostgreSQL/pgvector integration tests.
Those tests require an isolated database and `KNOWLEDGE_TEST_PG_URL`. Add meaningful
regression coverage for behavior changes, especially permissions, revocation,
credential handling and collection isolation. Documentation-only changes do not
need artificial tests.

Keep local `.env` files, keys, tokens, agent profiles, databases, logs, screenshots
of live deployments and private knowledge out of commits and test fixtures. Use
reserved example domains and fictional data. Do not merge the historical private
development repository into this repository.

Keywright is Apache-2.0 licensed. Unless explicitly stated otherwise, contributions
intentionally submitted for inclusion are offered under Apache-2.0. Submit only
work you have the right to contribute. Preserve upstream copyright and license
notices and identify any copied or adapted third-party code. This project does
not require copyright assignment or a separate contributor agreement.

Container dependency changes require updating the reviewed source/notice lock,
runtime constraints and native binary hashes together. Follow
[the release material instructions](third_party/README.md); a passing application
test suite alone does not approve new dependency license coverage.
