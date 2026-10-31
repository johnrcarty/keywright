"""Where the client finds its server and token.

`~/.config/keywright/config.toml` (XDG-aware), directory 0700 and file 0600, holds named
profiles. Environment wins over the file: KW_URL and KW_TOKEN describe an ad-hoc profile,
KW_PROFILE picks a named one. Written by hand (three keys) so the client needs no TOML writer.
"""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


class ConfigError(Exception):
    pass


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "keywright"


def config_file() -> Path:
    return config_dir() / "config.toml"


@dataclass(frozen=True)
class Profile:
    name: str
    url: str
    token: str

    @property
    def mcp_url(self) -> str:
        url = self.url.rstrip("/")
        return url if url.endswith("/mcp") else url + "/mcp"


def read_all() -> dict[str, dict[str, str]]:
    path = config_file()
    if not path.exists():
        return {}
    try:
        data = tomllib.loads(path.read_text())
    except (tomllib.TOMLDecodeError, OSError) as e:
        raise ConfigError(f"{path}: {e}") from e
    profiles = data.get("profiles") or {}
    return {k: v for k, v in profiles.items() if isinstance(v, dict)}


def load(name: str | None = None) -> Profile:
    env_url, env_token = os.environ.get("KW_URL"), os.environ.get("KW_TOKEN")
    if env_url and env_token:
        return Profile("env", env_url, env_token)
    name = name or os.environ.get("KW_PROFILE") or "default"
    profiles = read_all()
    p = profiles.get(name)
    if not p or not p.get("url") or not p.get("token"):
        raise ConfigError(f"no profile {name!r} in {config_file()}; run `kw login <url> --paste` "
                          "or set KW_URL and KW_TOKEN")
    return Profile(name, str(env_url or p["url"]), str(env_token or p["token"]))


def _write(profiles: dict[str, dict[str, str]]) -> None:
    d = config_dir()
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    lines = []
    for name, p in profiles.items():
        lines.append(f"[profiles.{json.dumps(name)}]" if not name.isidentifier() else f"[profiles.{name}]")
        for k in ("url", "token"):
            lines.append(f"{k} = {json.dumps(p[k])}")
        lines.append("")
    path = config_file()
    tmp = path.with_suffix(".tmp")
    tmp.write_text("\n".join(lines))
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    os.chmod(path, 0o600)


def save(name: str, url: str, token: str) -> Path:
    profiles = read_all()
    profiles[name] = {"url": url.strip(), "token": token.strip()}
    _write(profiles)
    return config_file()


def remove(name: str) -> bool:
    profiles = read_all()
    if name not in profiles:
        return False
    del profiles[name]
    _write(profiles)
    return True


def file_mode_ok() -> bool | None:
    path = config_file()
    if not path.exists():
        return None
    return (path.stat().st_mode & 0o077) == 0
