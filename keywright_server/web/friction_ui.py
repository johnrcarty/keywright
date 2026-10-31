"""Admin report and explicit review/save flow for constrained friction suggestions."""
from datetime import UTC, date, datetime, time, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import text

from .. import friction, policy_preview
from ..config import settings
from ..db import session
from ..models import now
from . import auth
from .admin import redirect, render
from .security import require_same_origin

router = APIRouter(dependencies=[Depends(require_same_origin), Depends(auth.require_admin)])


def dates(start, end):
    today = now().date()
    first = date.fromisoformat(start) if start else today - timedelta(days=29)
    last = date.fromisoformat(end) if end else today
    if first > last or last > today or (last - first).days >= 90:
        raise ValueError("Choose 1 to 90 days, ending no later than today.")
    return (datetime.combine(first, time.min, UTC),
            datetime.combine(last + timedelta(days=1), time.min, UTC))


def signer():
    return URLSafeTimedSerializer(settings.secret_key(), salt="friction-rule-review")


@router.get("/ui/friction")
async def friction_page(request: Request, start: str = "", end: str = "", agent: str = ""):
    error = None
    try:
        since, until = dates(start, end)
    except (ValueError, OverflowError):
        since, until = dates("", "")
        error = "Choose a valid range of 1 to 90 days, ending no later than today. Showing the last 30 days."
    filters = {"start": since.date().isoformat(), "end": (until - timedelta(days=1)).date().isoformat(),
               "agent": agent}
    async with session() as db:
        report = await friction.report(db, since, until, agent_id=agent)
    report.pop("proposals")  # Raw exact constraints are never passed to the report template.
    return render(request, "friction.html", **report, filters=filters, error=error,
                  review_query=urlencode(filters))


@router.get("/ui/friction/review/{rid}")
async def review(request: Request, rid: str, start: str = "", end: str = "", agent: str = ""):
    try:
        since, until = dates(start, end)
    except (ValueError, OverflowError):
        return redirect("/ui/friction", "Choose a valid date range before reviewing a suggestion.")
    filters = {"start": since.date().isoformat(), "end": (until - timedelta(days=1)).date().isoformat(),
               "agent": agent}
    async with session() as db:
        report = await friction.report(db, since, until, agent_id=agent)
        proposal = report["proposals"].get(rid)
        if proposal is None:
            return redirect("/ui/friction?" + urlencode(filters), "This suggestion is no longer eligible. Refresh the report.")
        rules = proposal["rules"]
        preview = await policy_preview.preview(db, rules[0], additional=tuple(rules[1:]))
    token = signer().dumps({"request": rid, "fingerprint": proposal["fingerprint"], "filters": filters})
    public = {k: proposal[k] for k in ("request_id", "agent", "resource", "tool", "support", "examples")}
    return render(request, "friction_review.html", proposal=public, preview=preview, token=token,
                  rule_count=len(rules), back="/ui/friction?" + urlencode(filters))


@router.post("/ui/friction/review/{rid}")
async def save(rid: str, token: str = Form(...)):
    try:
        reviewed = signer().loads(token, max_age=600)
        if reviewed["request"] != rid:
            raise ValueError
        filters = reviewed["filters"]
        since, until = dates(filters["start"], filters["end"])
    except (BadSignature, SignatureExpired, ValueError, TypeError, KeyError, OverflowError):
        return redirect("/ui/friction", "Review expired or invalid. Preview the suggestion again before saving.")
    async with session() as db:
        # Serialize SQLite writers while revalidating support, targets, hazards and standing policy.
        if db.bind.dialect.name == "sqlite":
            await db.execute(text("BEGIN IMMEDIATE"))
        report = await friction.report(db, since, until, agent_id=filters["agent"])
        proposal = report["proposals"].get(rid)
        if proposal is None or proposal["fingerprint"] != reviewed["fingerprint"]:
            return redirect("/ui/friction?" + urlencode(filters),
                            "Evidence or access settings changed. Review a fresh preview before saving.")
        added = await friction.save_proposal(db, proposal)
    return redirect("/ui/policies", f"Added {added} exact-operation rule(s) for {proposal['agent']}.")
