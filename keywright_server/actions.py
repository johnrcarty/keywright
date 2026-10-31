"""Compact authenticated actions for notification buttons: `<BODY>.<mac>`.

A phone renders a button as a short opaque string and hands it back when tapped. The MAC is what
carries the authority: knowing a request or nudge ID is not enough to act on one, and the strings
stay short enough for Android's action payload limits, which a signed token would not.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

from .config import settings

MAC_BYTES = 16  # 128 bits, the same budget itsdangerous spends, in a third of the characters


def sign(body: str) -> str:
    mac = hmac.new(settings.secret_key(), body.encode(), hashlib.sha256).digest()[:MAC_BYTES]
    return body + "." + base64.urlsafe_b64encode(mac).decode().rstrip("=")


def verify(action: str) -> str | None:
    """The body of an action we signed, or None. Constant-time; never raises."""
    try:
        body, _ = action.rsplit(".", 1)
    except ValueError:
        return None
    return body if hmac.compare_digest(action, sign(body)) else None
