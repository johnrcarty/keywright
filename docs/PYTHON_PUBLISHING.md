# Publishing Python packages

The release workflow is `.github/workflows/publish-python.yml`. It is manually dispatched,
defaults to `validate`, and never uploads packages on a source push. The three distributions
share a version: `keywright`, `keywright-server` and `keywright-router`.

The pending publishers use GitHub owner `johnrcarty`, repository `keywright` and workflow
filename `publish-python.yml`. Configure these environments on both sides:

| Package | PyPI environment | TestPyPI environment |
| --- | --- | --- |
| `keywright` | `pypi` | `testpypi` |
| `keywright-server` | `pypi-server` | `testpypi-server` |
| `keywright-router` | `pypi-router` | `testpypi-router` |

Each upload job has its own environment and only uploads that package's wheel and source
archive. No PyPI passwords or API tokens belong in repository secrets. Pending publishers
do not reserve names; successful first publication creates the projects.

## Validate before uploading

Run the workflow with target `validate`. This builds all six archives, validates their names,
versions and license files, runs strict Twine metadata checks, and tests wheel and source
installs in fresh environments outside the checkout. The resulting `python-release` artifact
is retained for 30 days. This mode does not request an OIDC token or enter an upload environment.

The full `ci.yml` must also pass for the exact upload commit, including pgvector integration
tests and native image verification. Complete the release privacy review before uploading
even to TestPyPI: its packages are public too.

## TestPyPI rehearsal

Freeze the package contents and select target `testpypi` on `main` or the matching version
tag. Supply the full reviewed commit SHA in `reviewed_commit`; it must equal the workflow
commit. GitHub environment branch policies permit only `main` and `v*` tags for TestPyPI.

After upload, the workflow checks the index's complete file set and SHA-256 hashes against
the reviewed build, downloads both archives for every package, checks those bytes again,
and tests fresh installs. Third-party dependencies are installed exclusively from PyPI;
the downloaded Keywright archives are then installed with `--no-deps`. It does not combine
PyPI and TestPyPI with `--extra-index-url`.

Retries skip already uploaded files, but succeed only if every index file matches the build.
Do not delete/reupload or silently accept different files for an existing version. If package
contents change after rehearsal, choose a new shared version and repeat the review. Rehearse
and release the same commit: builds use its timestamp as `SOURCE_DATE_EPOCH` for reproducibility.

## Production publication

Before production, finish the release checklist and make the reviewed repository public.
Enable required-reviewer protection for all three production environments, assigning the
release owner. Keep production environments restricted to `v*` tags. If the repository plan
does not support reviewer protection while private, leave production blocked until it can
be enabled at public launch.

Dispatch target `pypi` at the version tag, such as `v0.0.1`, and supply its full reviewed commit
SHA. The workflow requires matching package versions, a matching version tag, successful
full CI on that SHA, public repository visibility and required reviewers on all production
environments. It repeats TestPyPI upload/hash/install verification before requesting production
environment approval. The production jobs reuse the very same build artifacts without rebuilding.
After approval and upload, downloaded PyPI wheel/source files undergo the same checks.

Do not mark the release complete until both registry verification and the other release
checklist gates pass. Partial uploads can be retried on the same commit; a mismatched existing
file is a failure that requires investigation.

References: [PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/)
and [PyPA publishing action](https://github.com/pypa/gh-action-pypi-publish).
