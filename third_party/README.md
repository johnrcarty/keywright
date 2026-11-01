# Third-party source and notices

Keywright's application code is Apache-2.0 licensed. Dependencies retain their own
licenses. `LICENSES.txt` supplements the notices installed by Python packages and
Debian. `notices.json` records the upstream notice paths and hashes.

`sources.lock.json` records reviewed source URLs and SHA-256 checksums, container
Python versions and native wheel binary hashes for AMD64 and ARM64. The base image
is digest-pinned and container dependencies use `deploy/runtime-constraints.txt`.
The verifier rejects unreviewed package versions, changed native binaries, missing
notices and pip caches. It runs during broker and router image builds.

CFFI 2.1.1's upstream release workflow pins statically linked libffi 3.4.6 and
renames `ffi_call` to `cffistatic_ffi_call`. The lock records that immutable workflow,
the libffi source and license, and reviewed binary hashes for both architectures.
OpenSSL 4.0.3 is bundled by cryptography; Debian's separate OpenSSL is covered by
its own source package and notices. Uvloop includes libuv 1.52.1. Rust notice/source
coverage includes the lockfiles' build and other-platform dependencies. The
missing r-efi and wit-bindgen-rt license texts were recovered from the exact Git
commits identified by their published source archives.

## Obtaining matching source

The image publisher uploads a **source-material image first**, in the same GHCR
package as the application image. Its digest is recorded in the application image's
`io.keywright.source-image` label. Thus source materials have the same registry
access rules and do not depend on an expiring Actions artifact. Preserve these
source-image versions for as long as the corresponding application images are
distributed. Never delete source versions as routine preview cleanup.

For an image already pulled locally:

```bash
docker image inspect YOUR_KEYWRIGHT_IMAGE --format '{{index .Config.Labels "io.keywright.source-image"}}'
```

Use the returned digest reference as `SOURCE_IMAGE` below. The source image is a
data archive, so create a stopped container and copy its files without running it:

```bash
SOURCE_IMAGE=ghcr.io/johnrcarty/keywright@sha256:REPLACE_WITH_SOURCE_DIGEST
container=$(docker create "$SOURCE_IMAGE" /unused)
docker cp "$container:/sources.tar" ./sources.tar
docker cp "$container:/SOURCE-MANIFEST.json" ./SOURCE-MANIFEST.json
docker cp "$container:/inventory.json" ./inventory.json
docker cp "$container:/NOTICES.txt" ./NOTICES.txt
docker cp "$container:/SHA256SUMS" ./SHA256SUMS
docker rm "$container"
sha256sum -c SHA256SUMS
```

The archive contains Debian source sets (including packaging patches/build rules),
Python source distributions, CPython source/build instructions, native library
sources, Rust crates, and the corresponding committed Keywright source tree.
Upstream archives are preserved unmodified and checked against the lock. Each
component retains its own license. The inventory and manifest identify coverage;
extra build and platform-specific source does not mean every component is linked
into every runtime image.

Version tags also prepare a **draft GitHub Release** with per-architecture source
archives, notices, inventories, source-image links, installer files and checksums.
Publishing that draft and making images public remain explicit release steps.

## Updating reviewed inputs

1. Update dependencies/base image in an isolated build and inventory both native
   architectures. Review upstream licenses and bundled native components.
2. Refresh the exact source versions, official HTTPS URLs and hashes in
   `sources.lock.json`, the runtime constraints and native binary hashes together.
   Preserve complete upstream notices and their provenance in `notices.json`.
3. Regenerate `LICENSES.txt` from those notices and update its checksum in the lock.
   Include exact build recipes where needed to establish native library provenance.
4. Build both images. CI verifies the inventory, downloads every locked source with
   checksum verification, prepares matching source images, and publishes those
   before publishing application images. A failed source download or coverage
   check must stop application publication.

For a local check, build the broker image and export its inventory:

```bash
docker build -f deploy/Dockerfile -t keywright-review .
docker run --rm --network none --entrypoint python keywright-review \
  /usr/share/keywright/release_materials.py inventory > inventory.json
python3 scripts/release_materials.py collect --license-root third_party \
  --inventory inventory.json --output dist/review-materials \
  --cache /tmp/keywright-source-cache --repository .
```

Collection requires a committed clean source tree. The cache is content-addressed
and revalidated before reuse. Source archives belong in release assets/registry
images, not in Git. Historical previews produced before this publishing scheme
must be removed from public-distribution scope or supplied equivalent source and
notice coverage before changing package visibility.
