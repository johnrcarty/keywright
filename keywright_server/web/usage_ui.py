"""Read-only, admin-authenticated LLM usage view."""
from datetime import UTC, date, datetime, time, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request

from ..db import session
from ..models import now
from ..usage import report
from . import auth
from .admin import render
from .security import require_same_origin

router = APIRouter(dependencies=[Depends(require_same_origin), Depends(auth.require_admin)])


@router.get("/ui/usage")
async def usage_page(request: Request, start: str = "", end: str = "", provider: str = "",
                     model: str = "", agent: str = "", key: str = ""):
    today = now().date()
    error = None
    try:
        first = date.fromisoformat(start) if start else today - timedelta(days=29)
        last = date.fromisoformat(end) if end else today
        if first > last:
            raise ValueError
        until = datetime.combine(last + timedelta(days=1), time.min, UTC)
    except (ValueError, OverflowError):
        first, last = today - timedelta(days=29), today
        until = datetime.combine(last + timedelta(days=1), time.min, UTC)
        error = "Choose valid dates with the start on or before the end. Showing the last 30 days."
    filters = {"start": first.isoformat(), "end": last.isoformat(), "provider": provider,
               "model": model, "agent": agent, "key": key}

    def usage_url(**changes):
        return "/ui/usage?" + urlencode({**filters, **changes})

    async with session() as db:
        data = await report(db, datetime.combine(first, time.min, UTC), until,
                            provider=provider, model=model, agent=agent, key=key)
    return render(request, "usage.html", **data, filters=filters, usage_url=usage_url, error=error)
