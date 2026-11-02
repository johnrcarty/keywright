# Support scope

Keywright v0.0.1 is an experimental first release. Maintenance targets the latest
published 0.0.x patch release; there is no long-term support or guaranteed compatibility
between experimental releases. Back up the broker data and review release notes
before upgrading. No commercial support commitment is implied by this policy.

The primary installation method is the prebuilt Linux container image, available
for AMD64 and ARM64, with Docker Compose. Core SSH/MCP approval and revocation,
shared knowledge, and the optional PostgreSQL/pgvector search index are part of
the v0.0.1 scope. Python source/package checks run on Python 3.12, 3.13 and 3.14.
Native Windows/macOS server installations are not part of the release acceptance.

Full clean-VM acceptance was performed on AMD64. ARM64 image and installation
checks run in CI; this is not a claim of a full ARM64 VM acceptance run. External
identity providers, notification providers, mail routing, LLM gateways and device
controllers depend on third-party services and are supported on a best-effort
basis. Embedding models and separate service images retain their own licenses.

Knowledge search returns references, not verified answers. Users must check that
citations support their question. The synthetic retrieval evaluation does not
establish general no-answer detection or quality for every corpus and model.

Use [GitHub issues](https://github.com/johnrcarty/keywright/issues) for ordinary bugs
and feature requests. Include the version/image digest, architecture, expected and
actual behavior, and a small synthetic reproduction. Remove credentials, private
addresses, personal data and operational database dumps. For vulnerabilities, use
the [private security reporting process](SECURITY.md).
