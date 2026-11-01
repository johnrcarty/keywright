"""Release publication must stop on missing coverage or altered source materials."""
import hashlib
import importlib.util
import json
import subprocess
import tarfile
from pathlib import Path

import pytest


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


materials = module('release_materials', 'release_materials.py')
assets = module('release_assets', 'prepare-release-assets.py')
published = module('published_sources', 'check-published-sources.py')


@pytest.fixture
def reviewed():
    lock = {'python_version': '3.13.18', 'runtime_python': {'dependency': '1.2'},
            'sources': [{'ecosystem': 'debian', 'name': 'system-library', 'version': '1.0'}],
            'native_binary_sha256': {'amd64': {'dependency/native.so': 'reviewed-hash'}}}
    inventory = {'python_version': '3.13.18', 'architecture': 'amd64',
                 'python': [{'name': 'dependency', 'version': '1.2', 'notices': ['LICENSE']}],
                 'debian': [{'name': 'library', 'source_name': 'system-library', 'source_version': '1.0',
                             'notice_sha256': 'notice-hash'}],
                 'native_binary_sha256': {'dependency/native.so': 'reviewed-hash'}, 'pip_cache_files': 0}
    return inventory, lock


@pytest.mark.parametrize('change, message', [
    (lambda i: i['python'][0].update(version='1.3'), 'Unreviewed Python'),
    (lambda i: i['python'][0].update(notices=[]), 'Missing Python license'),
    (lambda i: i['debian'][0].update(source_version='2.0'), 'Unreviewed Debian'),
    (lambda i: i['debian'][0].update(notice_sha256=None), 'Missing Debian'),
    (lambda i: i['native_binary_sha256'].update({'dependency/native.so': 'changed'}), 'Unreviewed native'),
    (lambda i: i.update(architecture='unreviewed'), 'Unreviewed image architecture'),
    (lambda i: i.update(pip_cache_files=1), 'pip build-cache'),
    (lambda i: i.update(python_version='3.14.0'), 'CPython changed'),
])
def test_rejects_unreviewed_image_changes(reviewed, change, message):
    inventory, lock = reviewed
    materials.verify_inventory(inventory, lock)
    change(inventory)
    with pytest.raises(ValueError, match=message):
        materials.verify_inventory(inventory, lock)


def test_source_collector_keeps_verified_sources_and_committed_build_instructions(tmp_path, reviewed):
    inventory, lock = reviewed
    data = b'synthetic upstream source archive'
    checksum = hashlib.sha256(data).hexdigest()
    lock['sources'][0].update(path='debian/source.tar.gz', sha256=checksum, url='https://example.invalid/source')
    inventory.update(notices={'/usr/share/doc/library/copyright': 'Synthetic notice'},
                     source_lock_sha256=materials.digest(json.dumps(lock, sort_keys=True).encode()))
    cache = tmp_path / 'cache'
    cache.mkdir()
    (cache / checksum).write_bytes(data)
    repo = tmp_path / 'repository'
    repo.mkdir()
    subprocess.run(['git', 'init', '-q', str(repo)], check=True)
    (repo / 'Dockerfile').write_text('FROM scratch\n')
    subprocess.run(['git', 'add', 'Dockerfile'], cwd=repo, check=True)
    subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                    'commit', '-qm', 'Synthetic build instructions'], cwd=repo, check=True)
    output = tmp_path / 'output'
    materials.collect(inventory, lock, output, cache, repo)
    assets.verify(output)
    published.verify(inventory, output)
    with pytest.raises(ValueError, match='different runtime inventory'):
        published.verify(dict(inventory, architecture='arm64'), output)
    with tarfile.open(output / 'sources.tar') as tar:
        assert tar.extractfile('sources/debian/source.tar.gz').read() == data
        manifest = json.load(tar.extractfile('SOURCE-MANIFEST.json'))
        assert hashlib.sha256(tar.extractfile('keywright-source.tar').read()).hexdigest() == manifest['keywright_source_sha256']
        assert all(m.uid == 0 and m.gid == 0 and m.mtime == 0 for m in tar.getmembers())
    (output / 'NOTICES.txt').write_text('tampered')
    with pytest.raises(ValueError, match='Checksum mismatch'):
        assets.verify(output)
    with pytest.raises(ValueError, match='Source asset checksum mismatch'):
        published.verify(inventory, output)


def test_source_checksum_failure_never_enters_cache(tmp_path, monkeypatch):
    import io
    monkeypatch.setattr(materials.urllib.request, 'urlopen', lambda *a, **k: io.BytesIO(b'altered'))
    expected = hashlib.sha256(b'expected').hexdigest()
    with pytest.raises(ValueError, match='Source checksum mismatch'):
        materials.fetch_source({'url': 'https://example.invalid/source', 'sha256': expected, 'path': 'source'}, tmp_path)
    assert not (tmp_path / expected).exists()


@pytest.mark.parametrize('path', ['../escape', '/absolute', 'sources/../../escape'])
def test_source_paths_cannot_escape_bundle(path):
    with pytest.raises(ValueError, match='Unsafe source path'):
        materials.safe_path(path)
