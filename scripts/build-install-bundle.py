"""Build a standalone installation directory from an explicit public-file allowlist."""
import argparse
import hashlib
import re
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="Registry image pinned with @sha256:...")
    parser.add_argument("output", type=Path, help="New output directory (must not exist)")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", args.image):
        parser.error("image must be a registry reference pinned to a SHA-256 digest")
    source = Path(__file__).resolve().parents[1] / "deploy"
    compose = (source / "compose.yaml").read_text()
    compose, count = re.subn(r"\$\{KEYWRIGHT_IMAGE:-[^}]+\}", args.image, compose)
    if count != 1:
        raise ValueError("Expected exactly one broker image default")
    files = {"compose.yaml": compose.encode(), "image.txt": (args.image + "\n").encode()}
    for name in ("README.md", ".env.example", "knowledge.compose.yml", "knowledge-schema.sql",
                 "knowledge.env.example", "llm.compose.yml", "litellm.yaml", "litellm.env.example"):
        files[name] = (source / name).read_bytes()
    # The sample configuration must not undo the pinned broker selection.
    files[".env.example"] = re.sub(rb"(?m)^KEYWRIGHT_IMAGE=.*\n", b"", files[".env.example"])
    args.output.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        (args.output / name).write_bytes(content)
    manifest = "".join(f"{hashlib.sha256(files[name]).hexdigest()}  {name}\n" for name in sorted(files))
    (args.output / "SHA256SUMS").write_text(manifest)
    print(f"Wrote {len(files)} pinned installation files and checksums to {args.output}")


if __name__ == "__main__":
    main()
