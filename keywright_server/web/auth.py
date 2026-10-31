"""Admin authentication: local password or an OIDC browser session."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import OrderedDict, deque

from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, TimestampSigner

from ..config import settings
from ..settings_store import cached, put
from .security import safe_redirect

COOKIE = "kw_admin"
MAX_AGE = 30 * 86400
_signer: TimestampSigner | None = None


def signer() -> TimestampSigner:
    global _signer
    if _signer is None:
        _signer = TimestampSigner(settings.secret_key(), salt="admin-session")
    return _signer


def hash_password(pw: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000)
    return f"{salt}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(pw, salt), stored)


def password_is_set() -> bool:
    return bool((cached("admin") or {}).get("password_hash"))


async def set_password(db, pw: str) -> None:
    await put(db, "admin", {"password_hash": hash_password(pw)})


def check_password(pw: str) -> bool:
    if len(pw) > 1024:
        return False
    stored = (cached("admin") or {}).get("password_hash", "")
    return bool(stored) and verify_password(pw, stored)


def _session_payload() -> bytes:
    # A password reset invalidates previously issued cookies, including across restarts.
    stored = (cached("admin") or {}).get("password_hash", "")
    return b"admin:" + hashlib.sha256(stored.encode()).hexdigest().encode()


def is_logged_in(request: Request) -> bool:
    # Legacy password cookie validation stays separate from server-side OIDC sessions.
    if settings.auth_mode == "oidc":
        return False
    raw = request.cookies.get(COOKIE)
    if not raw or not password_is_set():
        return False
    try:
        return hmac.compare_digest(signer().unsign(raw, max_age=MAX_AGE), _session_payload())
    except BadSignature:
        return False


def oidc_enabled() -> bool:
    return settings.auth_mode in ("both", "oidc")


async def authenticated(request) -> bool:
    from .oidc import session_identity

    identity = await session_identity(request) if oidc_enabled() else None
    if identity is not None:
        request.state.admin_identity = identity
        return True
    if is_logged_in(request):
        request.state.admin_identity = {"method": "password"}
        return True
    return False


def login_response(url: str) -> RedirectResponse:
    resp = RedirectResponse(safe_redirect(url), status_code=303)
    resp.set_cookie(COOKIE, signer().sign(_session_payload()).decode(), max_age=MAX_AGE, httponly=True, samesite="lax")
    return resp


def logout_response(url: str) -> RedirectResponse:
    resp = RedirectResponse(safe_redirect(url), status_code=303)
    resp.delete_cookie(COOKIE)
    return resp


class RequireAdmin:
    """FastAPI dependency: redirect to setup/login when needed."""

    async def __call__(self, request: Request) -> None:
        if not password_is_set() and not oidc_enabled():
            raise HTTPException(status_code=303, headers={"Location": "/ui/setup"})
        if not await authenticated(request):
            raise HTTPException(status_code=303, headers={"Location": f"/ui/login?next={request.url.path}"})


require_admin = RequireAdmin()


# Bounded per-process throttles. Requests never trust client-supplied forwarding headers here.
_login_attempts: OrderedDict[str, deque[float]] = OrderedDict()
_global_attempts: deque[float] = deque()


def limit_login(request: Request) -> str:
    address = request.client.host if request.client else "unknown"
    at = time.monotonic()
    attempts = _login_attempts.setdefault(address, deque())
    _login_attempts.move_to_end(address)
    while len(_login_attempts) > 4096:
        _login_attempts.popitem(last=False)
    for queue in (attempts, _global_attempts):
        while queue and queue[0] <= at - 60:
            queue.popleft()
    if len(attempts) >= 8 or len(_global_attempts) >= 100:
        raise HTTPException(429, "Too many login attempts; try again in a minute", headers={"Retry-After": "60"})
    attempts.append(at)
    _global_attempts.append(at)
    return address


def login_succeeded(address: str) -> None:
    _login_attempts.pop(address, None)
