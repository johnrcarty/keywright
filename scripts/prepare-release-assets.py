"""Prepare a draft release's source/notice assets; reject missing or altered files."""
import argparse
import hashlib
import shutil
import tarfile
from pathlib import Path


def verify(root):
    for line in (root / 'SHA256SUMS').read_text().splitlines():
        expected, name = line.split('  ', 1)
        if Path(name).name != name:
            raise ValueError('Checksum manifest must contain plain filenames')
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f'Checksum mismatch: {name}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    verify(args.input / 'install')
    with tarfile.open(args.output / 'keywright-install.tar.gz', 'w:gz') as tar:
        for file in sorted((args.input / 'install').iterdir()):
            tar.add(file, arcname=file.name, recursive=False)
    for arch in ('amd64', 'arm64'):
        root = args.input / ('third-party-' + arch)
        shutil.copyfile(args.input / ('third-party-source-' + arch) / 'sources.tar', root / 'sources.tar')
        verify(root)
        names = {'sources.tar': f'keywright-sources-{arch}.tar',
                 'NOTICES.txt': f'keywright-notices-{arch}.txt',
                 'inventory.json': f'keywright-inventory-{arch}.json',
                 'SOURCE-MANIFEST.json': f'keywright-source-manifest-{arch}.json',
                 'source-image.txt': f'keywright-source-image-{arch}.txt',
                 'application-image.txt': f'keywright-image-{arch}.txt'}
        for source, target in names.items():
            shutil.copyfile(root / source, args.output / target)
    (args.output / 'RELEASE-NOTES.txt').write_text(
        'Draft Keywright release — review before publication.\n\n'
        'The installation bundle pins the multi-platform application image.\n'
        'Per-architecture source archives, notices and inventories accompany it.\n'
        'Source images are already available at the digest references in these assets,\n'
        'under the same registry access rules as the application images.\n\n'
        'Before publishing: finish release notes, verify SECURITY.md reporting is active,\n'
        'review support/known limitations, validate final privacy checks and ensure that\n'
        'historical unaudited previews are excluded from public distribution.\n')
    files = sorted(args.output.iterdir())
    (args.output / 'SHA256SUMS').write_text(''.join(
        f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files))


if __name__ == '__main__':
    main()
