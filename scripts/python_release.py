"""Validate Python release artifacts and verify the exact bytes served by an index."""
from __future__ import annotations

import argparse
import email
import hashlib
import json
import subprocess
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import venv
import zipfile
from pathlib import Path

PACKAGES = {"keywright": "client", "keywright-server": ".", "keywright-router": "router"}
INDEXES = {"testpypi": "https://test.pypi.org", "pypi": "https://pypi.org"}


def metadata(path: Path):
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            candidates = [n for n in names if n.endswith(".dist-info/METADATA")]
            if len(candidates) != 1:
                raise ValueError(f"Expected one wheel metadata file: {path.name}")
            raw = archive.read(candidates[0])
    else:
        with tarfile.open(path, "r:gz") as archive:
            names = archive.getnames()
            candidates = [n for n in names if n.count("/") == 1 and n.endswith("/PKG-INFO")]
            if len(candidates) != 1:
                raise ValueError(f"Expected one sdist metadata file: {path.name}")
            raw = archive.extractfile(candidates[0]).read()
    for license_name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES"):
        if not any(n.endswith("/" + license_name) for n in names):
            raise ValueError(f"Missing {license_name} in {path.name}")
    return email.message_from_bytes(raw)


def validate(root: Path, version: str) -> dict[str, list[Path]]:
    expected = {Path(name) for name in PACKAGES}
    if {p.relative_to(root) for p in root.iterdir()} != expected:
        raise ValueError("Expected exactly the three package directories")
    result = {}
    for name in PACKAGES:
        paths = sorted((root / name).iterdir())
        stem = name.replace("-", "_") + "-" + version
        if {p.name for p in paths} != {stem + "-py3-none-any.whl", stem + ".tar.gz"}:
            raise ValueError(f"Unexpected artifacts for {name}")
        for path in paths:
            meta = metadata(path)
            if meta["Name"] != name or meta["Version"] != version:
                raise ValueError(f"Package identity mismatch: {path.name}")
            if meta["License-Expression"] != "Apache-2.0":
                raise ValueError(f"License metadata mismatch: {path.name}")
        result[name] = paths
    return result


def version(repository: Path) -> str:
    versions = []
    for name, folder in PACKAGES.items():
        project = tomllib.loads((repository / folder / "pyproject.toml").read_text())["project"]
        if project["name"] != name:
            raise ValueError(f"Unexpected project name in {folder}")
        versions.append(project["version"])
    if len(set(versions)) != 1:
        raise ValueError("All three package versions must match")
    return versions[0]


def verify_index_files(paths: list[Path], payload: dict) -> dict:
    files = {entry["filename"]: entry for entry in payload["urls"]}
    if set(files) != {p.name for p in paths}:
        raise ValueError("Index file set differs from the reviewed artifacts")
    for path in paths:
        entry = files[path.name]
        if entry.get("yanked"):
            raise ValueError(f"Index artifact is yanked: {path.name}")
        if entry["digests"]["sha256"] != hashlib.sha256(path.read_bytes()).hexdigest():
            raise ValueError(f"Index checksum mismatch: {path.name}")
    return files


def fetch_index(index: str, name: str, release_version: str) -> dict:
    url = f"{INDEXES[index]}/pypi/{name}/{release_version}/json"
    for attempt in range(12):
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code not in (404, 429, 500, 502, 503, 504) or attempt == 11:
                raise
            time.sleep(10)
    raise RuntimeError("Index did not become available")


def fetch_published(root: Path, index: str, release_version: str, output: Path):
    artifacts = validate(root, release_version)
    output.mkdir(parents=True, exist_ok=False)
    for name, paths in artifacts.items():
        files = verify_index_files(paths, fetch_index(index, name, release_version))
        directory = output / name
        directory.mkdir()
        for path in paths:
            entry = files[path.name]
            url = urllib.parse.urlparse(entry["url"])
            if url.scheme != "https" or url.hostname not in (
                "files.pythonhosted.org", "test-files.pythonhosted.org"
            ):
                raise ValueError("Unexpected index artifact host")
            with urllib.request.urlopen(entry["url"], timeout=60) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != entry["digests"]["sha256"]:
                raise ValueError(f"Downloaded checksum mismatch: {path.name}")
            (directory / path.name).write_bytes(data)
    validate(output, release_version)


def smoke(root: Path, release_version: str):
    artifacts = validate(root.resolve(), release_version)
    wheels = [str(p) for paths in artifacts.values() for p in paths if p.suffix == ".whl"]
    sdists = [str(p) for paths in artifacts.values() for p in paths if p.name.endswith(".tar.gz")]
    for kind, inputs in (("wheel", wheels), ("sdist", sdists)):
        with tempfile.TemporaryDirectory(prefix="keywright-install-") as directory:
            working = Path(directory)
            venv.EnvBuilder(with_pip=True).create(working / "venv")
            bin_dir = working / "venv/bin"
            python = str(bin_dir / "python")

            def run(*args, working=working):
                subprocess.run(args, cwd=working, check=True)

            # Resolve dependencies exclusively from PyPI using local Keywright wheels.
            # Then remove Keywright itself and install the selected archives without
            # dependency resolution. TestPyPI never supplies third-party dependencies.
            run(python, "-m", "pip", "--isolated", "install", "--index-url", INDEXES["pypi"] + "/simple",
                *wheels, "asyncpg>=0.30,<1")
            run(python, "-m", "pip", "uninstall", "-y", *PACKAGES)
            run(python, "-m", "pip", "--isolated", "install", "--index-url", INDEXES["pypi"] + "/simple",
                "--no-deps", *inputs)
            run(python, "-m", "pip", "check")
            run(str(bin_dir / "kw"), "version")
            run(str(bin_dir / "keywright"), "--help")
            run(str(bin_dir / "keywright-server"), "--help")
            run(str(bin_dir / "keywright-router"), "--help")
            run(python, "-c", "from importlib.metadata import version; "
                f"assert all(version(n) == {release_version!r} for n in {list(PACKAGES)!r}); "
                "import keywright_server.web.app, keywright_router, asyncpg")
            result = subprocess.run(
                [str(bin_dir / "kw"), "hazards", "git push --force"], cwd=working, check=False
            )
            if result.returncode != 2:
                raise ValueError("Installed hazard check did not block the synthetic command")
            print(f"Verified {kind} installs outside the checkout", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("version", "validate", "smoke", "fetch"))
    parser.add_argument("--root", type=Path, default=Path("dist/python-release"))
    parser.add_argument("--version")
    parser.add_argument("--index", choices=tuple(INDEXES))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    release_version = args.version or version(Path("."))
    if args.command == "version":
        print(release_version)
    elif args.command == "validate":
        validate(args.root, release_version)
    elif args.command == "smoke":
        smoke(args.root, release_version)
    else:
        if args.index is None or args.output is None:
            parser.error("fetch requires --index and --output")
        fetch_published(args.root, args.index, release_version, args.output)


if __name__ == "__main__":
    main()
