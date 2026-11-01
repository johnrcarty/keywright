"""Check downloaded source-image files against the corresponding runtime inventory."""
import hashlib
import json
import sys
import tarfile
from pathlib import Path


def verify(runtime, root):
    inventory = json.loads((root / 'inventory.json').read_text())
    if runtime != inventory:
        raise ValueError('Source image belongs to a different runtime inventory')
    required = {'sources.tar', 'SOURCE-MANIFEST.json', 'inventory.json', 'NOTICES.txt'}
    entries = {}
    for line in (root / 'SHA256SUMS').read_text().splitlines():
        checksum, name = line.split('  ', 1)
        if name in entries or name not in required:
            raise ValueError('Unexpected or repeated source checksum entry')
        entries[name] = checksum
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != checksum:
            raise ValueError(f'Source asset checksum mismatch: {name}')
    if set(entries) != required:
        raise ValueError('Source checksum manifest is incomplete')
    manifest = json.loads((root / 'SOURCE-MANIFEST.json').read_text())
    if manifest['source_lock_sha256'] != inventory['source_lock_sha256']:
        raise ValueError('Source lock differs from runtime inventory')
    with tarfile.open(root / 'sources.tar') as tar:
        expected = {'keywright-source.tar', 'SOURCE-MANIFEST.json', 'README.txt'}
        expected.update('sources/' + s['path'] for s in manifest['sources'])
        names = tar.getnames()
        if len(names) != len(set(names)) or set(names) != expected:
            raise ValueError('Source archive has missing, duplicate or unexpected members')
        for source in manifest['sources']:
            data = tar.extractfile('sources/' + source['path']).read()
            if hashlib.sha256(data).hexdigest() != source['sha256']:
                raise ValueError(f'Upstream source mismatch: {source["path"]}')
        if json.load(tar.extractfile('SOURCE-MANIFEST.json')) != manifest:
            raise ValueError('Embedded source manifest differs')
        data = tar.extractfile('keywright-source.tar').read()
        if hashlib.sha256(data).hexdigest() != manifest['keywright_source_sha256']:
            raise ValueError('Keywright source snapshot mismatch')
    print('Downloaded source image matches the runtime; all source and notice checksums verified')


if __name__ == '__main__':
    verify(json.loads(Path(sys.argv[1]).read_text()), Path(sys.argv[2]))
