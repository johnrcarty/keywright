# Security policy

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/johnrcarty/keywright/security/advisories/new).
Do not include vulnerability details, credentials, private hostnames or personal data
in a public issue, discussion or pull request.

The repository is currently a private release preview. GitHub's reporting form will
be enabled and verified when the repository becomes public. During the private
preview, use the private communication channel through which access was arranged.
If the form is unavailable after launch, open an issue asking the maintainer to
restore private reporting, without including details of the vulnerability.

Include the affected version or image digest, a description of the impact, and
minimal reproduction steps using disposable resources and synthetic data. Mention
whether the issue requires administrator, agent or unauthenticated access. Redact
tokens, SSH keys, database contents, personal information and deployment addresses.
Test only systems you own or have permission to test.

Reports about authentication, approval bypasses, revocation, credential disclosure,
knowledge collection isolation and unsafe handling of upstream tool output are in
scope. Please also report relevant dependency vulnerabilities. The maintainer will
assess reports privately and coordinate fixes and disclosure with the reporter.
This is a best-effort project; there is no guaranteed response time or bug bounty.

There is no published supported release yet. Once v0.0.1 is published, security fixes
will target the latest published 0.0.x release. Older patch releases, arbitrary
commits and preview images have no separate maintenance commitment. Upgrade to the
latest release when a fix is published. See [support scope](SUPPORT.md).

Keywright is a credential trust boundary. Protect the broker host and backups,
keep agent machines separate, use HTTPS for remote access, and configure trusted
proxy addresses explicitly. Command matching is not a shell sandbox and output
inspection cannot prove arbitrary text is secret-free.
