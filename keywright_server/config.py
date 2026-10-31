"""Process configuration. Everything else (resources, agents, notifiers) lives in the database
and is managed from the admin UI, so nothing device-specific is ever hard-coded here."""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("keywright.config")
_warned: set[str] = set()


def env(name: str, default: str | None = None) -> str | None:
    """KW_<name>, falling back to the pre-rename GK_<name> for one release."""
    value = os.environ.get(f"KW_{name}")
    if value is not None:
        return value
    legacy = os.environ.get(f"GK_{name}")
    if legacy is not None:
        if name not in _warned:
            _warned.add(name)
            log.warning("GK_%s is deprecated; set KW_%s instead", name, name)
        return legacy
    return default


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(env("DATA_DIR", "./data")).resolve())
    host: str = field(default_factory=lambda: env("HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(env("PORT", "8700")))
    # Used to build links in notifications. Configurable in the UI too (settings.public_url wins).
    public_url: str = field(default_factory=lambda: env("PUBLIC_URL", ""))
    # Reverse proxies whose X-Forwarded-Proto/Host/For headers are trusted (comma-separated IPs,
    # CIDRs or "*"). Empty keeps uvicorn's loopback-only default. Behind TLS-terminating proxies
    # this must name the proxy, or the app sees itself as http:// and rejects browser form posts.
    trusted_proxies: str = field(default_factory=lambda: env("TRUSTED_PROXIES", ""))
    admin_password: str | None = field(default_factory=lambda: env("ADMIN_PASSWORD"))
    auth_mode: str = field(default_factory=lambda: env("AUTH_MODE", "password"))
    oidc_issuer: str = field(default_factory=lambda: env("OIDC_ISSUER", ""))
    oidc_client_id: str = field(default_factory=lambda: env("OIDC_CLIENT_ID", ""))
    oidc_client_secret: str = field(default_factory=lambda: env("OIDC_CLIENT_SECRET", ""))
    oidc_admin_group: str = field(default_factory=lambda: env("OIDC_ADMIN_GROUP", ""))
    oidc_session_ttl_s: int = field(default_factory=lambda: int(env("OIDC_SESSION_TTL", "3600")))
    request_timeout_s: int = field(default_factory=lambda: int(env("REQUEST_TIMEOUT", "900")))
    # How long an unanswered "the agent needs you" nudge stays on the dashboard and the phone.
    nudge_ttl_s: int = field(default_factory=lambda: int(env("NUDGE_TTL", "43200")))
    # Upper bound on "this session" grants; the session itself usually ends sooner.
    session_grant_ttl_s: int = field(default_factory=lambda: int(env("SESSION_GRANT_TTL", "3600")))
    # How long a proxied LLM call waits for the human before answering 403 approval_required.
    llm_wait_s: int = field(default_factory=lambda: int(env("LLM_WAIT", "60")))
    log_level: str = field(default_factory=lambda: env("LOG_LEVEL", "INFO"))
    # TypeSafe key for Jev's second opinion on operations that prompt the human (semantic.py).
    # Absent, the feature is off and nothing leaves the host.
    typesafe_api_key: str | None = field(default_factory=lambda: env("TYPESAFE_API_KEY"))

    @property
    def db_path(self) -> Path:
        new, old = self.data_dir / "keywright.db", self.data_dir / "gatekeeper.db"
        if old.exists() and not new.exists():
            for suffix in ("", "-wal", "-shm"):
                if (old.parent / (old.name + suffix)).exists():
                    (old.parent / (old.name + suffix)).rename(new.parent / (new.name + suffix))
            log.warning("renamed %s to %s", old, new)
        return new

    @property
    def db_url(self) -> str:
        return env("DB_URL") or f"sqlite+aiosqlite:///{self.db_path}"

    @property
    def keys_dir(self) -> Path:
        return self.data_dir / "keys"

    def secret_key(self) -> bytes:
        """Signing key for sessions and decision tokens. Generated once, kept in the data dir."""
        configured = env("SECRET_KEY")
        if configured:
            return configured.encode()
        p = self.data_dir / "secret.key"
        if p.exists():
            return p.read_bytes().strip()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        key = secrets.token_urlsafe(48).encode()
        p.write_bytes(key)
        p.chmod(0o600)
        return key

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.data_dir, 0o700)
            os.chmod(self.keys_dir, 0o700)
        except OSError:
            pass


settings = Settings()
