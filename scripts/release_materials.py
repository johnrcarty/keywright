"""Verify container license coverage and assemble checksum-pinned source materials."""
import argparse
import hashlib
import io
import json
import platform
import re
import subprocess
import sysconfig
import tarfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from importlib import metadata
from pathlib import Path, PurePosixPath

LICENSE_ROOT = Path('/usr/share/keywright/licenses')


def canonical(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(value):
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('Unsafe source path')
    return str(path)


def verify_inventory(inventory, lock):
    if inventory['python_version'] != lock['python_version']:
        raise ValueError('CPython changed; refresh the reviewed source lock')
    for package in inventory['python']:
        name = canonical(package['name'])
        if name in ('keywright', 'keywright-server', 'keywright-router'):
            if package['license_expression'] != 'Apache-2.0':
                raise ValueError('Keywright license metadata is missing')
        elif lock['runtime_python'].get(name) != package['version']:
            raise ValueError(f'Unreviewed Python dependency: {name} {package["version"]}')
        if not package['notices']:
            raise ValueError(f'Missing Python license file: {name}')
    sources = {(s['name'], s['version']) for s in lock['sources'] if s['ecosystem'] == 'debian'}
    for package in inventory['debian']:
        if (package['source_name'], package['source_version']) not in sources:
            raise ValueError(f'Unreviewed Debian source version: {package["source_name"]} {package["source_version"]}')
        if not package['notice_sha256']:
            raise ValueError(f'Missing Debian copyright file: {package["name"]}')
    expected = lock['native_binary_sha256'].get(inventory['architecture'])
    if expected is None:
        raise ValueError('Unreviewed image architecture')
    for path, checksum in inventory['native_binary_sha256'].items():
        if expected.get(path) != checksum:
            raise ValueError(f'Unreviewed native wheel binary: {path}')
    if inventory['pip_cache_files']:
        raise ValueError('Image contains pip build-cache files')


def inventory_image(lock, license_root=LICENSE_ROOT):
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine(), platform.machine())
    notices, python, debian = {}, [], []

    def notice(path):
        path = Path(path)
        data = path.read_bytes()
        if not data:
            raise ValueError(f'Empty notice file: {path}')
        notices[str(path)] = data.decode('utf-8', errors='replace')
        return digest(data)

    for dist in sorted(metadata.distributions(), key=lambda d: canonical(d.metadata['Name'])):
        files = []
        for file in dist.files or []:
            # Include bundled pip notices as well as distribution metadata.
            if re.match(r'(?i)^(licen[cs]e|copying|notice|copyright)(?:[._-]|$)', Path(file).name):
                path = dist.locate_file(file)
                if path.is_file():
                    files.append({'path': str(path), 'sha256': notice(path)})
        python.append({'name': dist.metadata['Name'], 'version': dist.version,
                       'license_expression': dist.metadata.get('License-Expression'), 'notices': files})
    query = subprocess.check_output(['dpkg-query', '-W', '-f',
                                     '${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n'], text=True)
    for line in query.splitlines():
        name, version, source, source_version = line.split('\t')
        path = Path('/usr/share/doc') / name.split(':')[0] / 'copyright'
        debian.append({'name': name, 'version': version, 'source_name': source,
                       'source_version': source_version, 'notice_sha256': notice(path)})
    for path in Path('/usr/share/common-licenses').iterdir():
        if path.is_file():
            notice(path)
    notice(Path(sysconfig.get_path('stdlib')) / 'LICENSE.txt')
    for name in ('LICENSES.txt',):
        if notice(license_root / name) != lock['supplemental_notice_sha256']:
            raise ValueError('Supplemental notice checksum mismatch')
    packages = Path(sysconfig.get_path('platlib'))
    native = {str(p.relative_to(packages)): digest(p.read_bytes()) for p in sorted(packages.rglob('*.so'))}
    cffi = list(packages.glob('_cffi_backend*.so'))
    if cffi and lock['cffi_libffi']['symbol'].encode() not in cffi[0].read_bytes():
        raise ValueError('CFFI does not match the reviewed static-libffi build')
    result = {'schema_version': 1, 'architecture': architecture, 'python_version': platform.python_version(),
              'python': python, 'debian': debian, 'native_binary_sha256': native,
              'pip_cache_files': sum(p.is_file() for p in Path('/root/.cache/pip').rglob('*')),
              'notices': notices, 'source_lock_sha256': digest(json.dumps(lock, sort_keys=True).encode())}
    verify_inventory(result, lock)
    return result


def fetch_source(item, cache):
    path = cache / item['sha256']
    if path.exists() and digest(path.read_bytes()) == item['sha256']:
        return path
    if not item['url'].startswith('https://') or not re.fullmatch('[a-f0-9]{64}', item['sha256']):
        raise ValueError('Sources require HTTPS URLs and SHA-256 checksums')
    for attempt in range(3):
        try:
            request = urllib.request.Request(item['url'], headers={'User-Agent': 'Keywright-source-materials/0.0.1'})
            with urllib.request.urlopen(request, timeout=120) as response:
                data = response.read()
            break
        except OSError:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)
    if digest(data) != item['sha256']:
        raise ValueError(f'Source checksum mismatch: {item["path"]}')
    path.write_bytes(data)
    return path


def add_bytes(tar, name, data):
    info = tarfile.TarInfo(safe_path(name))
    info.size, info.mode, info.mtime = len(data), 0o644, 0
    tar.addfile(info, io.BytesIO(data))


def collect(inventory, lock, output, cache, repository):
    verify_inventory(inventory, lock)
    if inventory['source_lock_sha256'] != digest(json.dumps(lock, sort_keys=True).encode()):
        raise ValueError('Inventory and source lock differ')
    output.mkdir(parents=True, exist_ok=False)
    cache.mkdir(parents=True, exist_ok=True)
    paths = [safe_path(s['path']) for s in lock['sources']]
    if len(set(paths)) != len(paths):
        raise ValueError('Duplicate source archive paths')
    with ThreadPoolExecutor(max_workers=4) as pool:
        downloaded = list(pool.map(lambda s: fetch_source(s, cache), lock['sources']))
    # Only committed, tracked source enters distributed build instructions.
    subprocess.run(['git', 'diff', '--exit-code', 'HEAD', '--'], cwd=repository, check=True,
                   stdout=subprocess.DEVNULL)
    if subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], cwd=repository).strip():
        raise ValueError('Untracked source files must be reviewed and committed before collection')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repository, text=True).strip()
    own_source = subprocess.check_output(['git', 'archive', '--format=tar', 'HEAD'], cwd=repository)
    source_manifest = {'schema_version': 1, 'revision': revision, 'sources': lock['sources'],
                       'keywright_source_sha256': digest(own_source),
                       'source_lock_sha256': inventory['source_lock_sha256']}
    manifest_bytes = (json.dumps(source_manifest, indent=2) + '\n').encode()
    with tarfile.open(output / 'sources.tar', 'w') as tar:
        for item, path in zip(lock['sources'], downloaded):
            add_bytes(tar, 'sources/' + item['path'], path.read_bytes())
        add_bytes(tar, 'keywright-source.tar', own_source)
        add_bytes(tar, 'SOURCE-MANIFEST.json', manifest_bytes)
        add_bytes(tar, 'README.txt', (
            'Corresponding source and third-party materials for Keywright commit ' + revision + '\n\n'
            'Each component retains its upstream license. Debian source sets include .dsc,\n'
            'upstream archives and Debian patches/build rules. Python source distributions,\n'
            'CPython sources/build recipe, native library sources and locked Rust crates are\n'
            'included. The Rust collection also includes build and other-platform components.\n'
            'See keywright-source.tar for Dockerfiles and build/release instructions.\n'
            'SOURCE-MANIFEST.json identifies exact upstream versions, URLs and SHA-256 hashes.\n'
            'No upstream source files were modified for this collection.\n').encode())
    (output / 'SOURCE-MANIFEST.json').write_bytes(manifest_bytes)
    (output / 'inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
    (output / 'NOTICES.txt').write_text(''.join('\n' + '=' * 78 + '\n' + name + '\n' + text + '\n'
                                              for name, text in sorted(inventory['notices'].items())))
    (output / 'Dockerfile').write_text('FROM scratch\nCOPY sources.tar SOURCE-MANIFEST.json inventory.json NOTICES.txt SHA256SUMS /\n')
    names = ('sources.tar', 'SOURCE-MANIFEST.json', 'inventory.json', 'NOTICES.txt')
    (output / 'SHA256SUMS').write_text(''.join(f'{digest((output / n).read_bytes())}  {n}\n' for n in names))
    print(f'Prepared {len(downloaded)} verified upstream source files for {inventory["architecture"]}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('inventory', 'collect'))
    parser.add_argument('--license-root', type=Path, default=LICENSE_ROOT)
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--repository', type=Path, default=Path('.'))
    args = parser.parse_args()
    lock = json.loads((args.license_root / 'sources.lock.json').read_text())
    if args.command == 'inventory':
        print(json.dumps(inventory_image(lock, args.license_root), indent=2))
    else:
        if not all((args.inventory, args.output, args.cache)):
            parser.error('collect requires --inventory, --output and --cache')
        collect(json.loads(args.inventory.read_text()), lock, args.output, args.cache, args.repository)


if __name__ == '__main__':
    main()
