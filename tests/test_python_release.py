"""Publication must reject mismatched or incomplete distribution artifacts."""
import hashlib
import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "python_release", Path(__file__).parents[1] / "scripts/python_release.py"
)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


@pytest.fixture
def artifacts(tmp_path):
    for name in release.PACKAGES:
        folder = tmp_path / name
        folder.mkdir()
        stem = name.replace("-", "_") + "-0.0.1"
        meta = f"Name: {name}\nVersion: 0.0.1\nLicense-Expression: Apache-2.0\n\n".encode()
        with zipfile.ZipFile(folder / (stem + "-py3-none-any.whl"), "w") as archive:
            archive.writestr(stem + ".dist-info/METADATA", meta)
            for license_name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES"):
                archive.writestr(stem + ".dist-info/licenses/" + license_name, "synthetic notice")
        with tarfile.open(folder / (stem + ".tar.gz"), "w:gz") as archive:
            for filename, data in {"PKG-INFO": meta, "LICENSE": b"license", "NOTICE": b"notice",
                                   "THIRD_PARTY_NOTICES": b"third party"}.items():
                info = tarfile.TarInfo(stem + "/" + filename)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return tmp_path


def test_validates_both_archive_types_and_rejects_unexpected_files(artifacts):
    assert set(release.validate(artifacts, "0.0.1")) == set(release.PACKAGES)
    (artifacts / "keywright" / "unexpected.whl").touch()
    with pytest.raises(ValueError, match="Unexpected artifacts"):
        release.validate(artifacts, "0.0.1")


@pytest.mark.parametrize("replacement,message", [
    ("Name: unrelated\nVersion: 0.0.1\nLicense-Expression: Apache-2.0\n", "identity mismatch"),
    ("Name: keywright\nVersion: 9.9.9\nLicense-Expression: Apache-2.0\n", "identity mismatch"),
    ("Name: keywright\nVersion: 0.0.1\nLicense-Expression: MIT\n", "License metadata"),
])
def test_rejects_wrong_metadata(artifacts, replacement, message):
    wheel = next((artifacts / "keywright").glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    files[next(name for name in files if name.endswith("/METADATA"))] = replacement.encode()
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    with pytest.raises(ValueError, match=message):
        release.validate(artifacts, "0.0.1")


def test_rejects_missing_license(artifacts):
    wheel = next((artifacts / "keywright").glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        files = {name: archive.read(name) for name in archive.namelist() if not name.endswith("/NOTICE")}
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    with pytest.raises(ValueError, match="Missing NOTICE"):
        release.validate(artifacts, "0.0.1")


def test_existing_index_version_must_match_every_reviewed_byte(artifacts):
    paths = release.validate(artifacts, "0.0.1")["keywright"]
    payload = {"urls": [{"filename": path.name,
                         "digests": {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}}
                        for path in paths]}
    release.verify_index_files(paths, payload)
    payload["urls"][0]["digests"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="checksum mismatch"):
        release.verify_index_files(paths, payload)
    payload["urls"].pop()
    with pytest.raises(ValueError, match="file set differs"):
        release.verify_index_files(paths, payload)
