"""AIMFA dashboard: a small FastAPI web app (server-rendered HTML, our own CSS and JS).

Run: ``uvicorn aimfa.dashboard.app:app_factory --factory --host 127.0.0.1 --port 8501``
(normally ``scripts/run_demo.py`` starts it). It talks to the control plane ONLY through the
admin API (``AdminClient``). The admin key stays on this server and never reaches the browser.

How a page works: the route renders the full page once. ``static/app.js`` then re-fetches
just the live part (``/partials/<name>``) every 2.5 s and swaps it in. Buttons POST JSON to
``/api/...`` with a CSRF token (see ``security.py``).
"""

from __future__ import annotations

import json
import secrets
import sys
import threading
from collections import Counter
from collections.abc import Callable, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, TypeVar

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from aimfa.common.config import REPO_ROOT, Settings, get_settings
from aimfa.common.http import ApiError, install_error_handling
from aimfa.common.models import AgentStatus, ReasonCode
from aimfa.dashboard import views
from aimfa.dashboard.admin_client import AdminClient
from aimfa.dashboard.security import (
    ALLOWED_HOSTS,
    SECURITY_HEADERS,
    allowed_origins,
    csrf_ok,
    describe_error,
)

HERE = Path(__file__).parent
REFRESH_MS = 2500
T = TypeVar("T")

# path, nav label, page title, one-line "what am I looking at"
# Nav labels stay short and fixed: docs/DEMO.md and scripts/demo_autoplay.py name the tabs by them.
# Titles and blurbs are written for someone seeing the system for the first time (in-class demo).
PAGES: dict[str, tuple[str, str, str, str]] = {
    "home": (
        "/",
        "Home",
        "AIMFA control room",
        "AI agents can now read files, send email and move money on their own. Most of them "
        "carry one password that never changes, so anyone who steals it can act as the agent. "
        "AIMFA puts a security checkpoint between the agent and everything it uses: every "
        "request is checked, and anything risky needs a real person to say yes.",
    ),
    "agents": (
        "/agents",
        "Agents",
        "The AI agents we are watching",
        "Each row is one AI helper program, the job it was set up for, and whether it is "
        "currently allowed to work. If something looks wrong, the red button is an emergency "
        "stop: it cancels every pass the agent holds, instantly.",
    ),
    "tokens": (
        "/tokens",
        "Tokens",
        "Temporary passes (tokens)",
        "Instead of a permanent password, an agent gets a temporary pass for each job. A pass "
        "only allows that one job, expires by itself after a few minutes, and is useless to "
        "anyone who steals it, because it only works together with a secret key that never "
        "leaves the agent.",
    ),
    "risk": (
        "/risk",
        "Risk",
        "Suspicion meter (risk score)",
        "We watch what each agent does. Suspicious moves, like reading secrets and then "
        "emailing them out, add points. Past the orange line, a person must approve its next "
        "risky action. Past the red line, the agent is locked out on the spot.",
    ),
    "approvals": (
        "/approvals",
        "Approvals",
        "Waiting for a human to say yes",
        "Risky actions, like sending money, stop here until a person approves them. The "
        "approver types the 6-digit code from the authenticator app on their phone. If nobody "
        "answers in time, the answer is automatically no.",
    ),
    "audit": (
        "/audit",
        "Audit",
        "The permanent record (audit log)",
        "Every yes, no and wait-for-a-human decision is written down here as it happens. Each "
        "entry is locked to the one before it, like links in a chain, so if anyone secretly "
        "edits or deletes an entry later, the button below catches it.",
    ),
    "attack_lab": (
        "/attack-lab",
        "Attack Lab",
        "Attack Lab: try to break in",
        "Run 10 real attacks two ways: against the usual setup, where the agent has one "
        "password and nothing else ('baseline'), and against AIMFA. Each result shows whether "
        "the attack worked and, if not, which check stopped it.",
    ),
}

# Sidebar / header icon per page (names from templates/icons.html).
PAGE_ICONS = {
    "home": "home",
    "agents": "bot",
    "tokens": "key",
    "risk": "activity",
    "approvals": "user-check",
    "audit": "receipt",
    "attack_lab": "flask",
}

# Short line for the Home page's quick links.
PAGE_SHORT = {
    "agents": "The AI helpers, what they do, and the emergency stop.",
    "tokens": "Temporary passes and how long until each one runs out.",
    "risk": "How suspicious each agent looks right now.",
    "approvals": "Risky actions waiting for a person to say yes.",
    "audit": "A record of every decision that can't be secretly changed.",
    "attack_lab": "Try 10 attacks, with and without AIMFA.",
}

# Plain label for each home-page counter, and its hover text.
STATUS_LABELS = {
    AgentStatus.REGISTERED: "Signed up, not started",
    AgentStatus.ACTIVE: "Working normally",
    AgentStatus.QUARANTINED: "Locked out",
}
STATUS_HELP = {
    AgentStatus.REGISTERED: "Known to us, but they have not passed the ID check yet.",
    AgentStatus.ACTIVE: "Passed the ID check and allowed to work.",
    AgentStatus.QUARANTINED: "Behaved too suspiciously. All their passes were cancelled until "
    "an admin looks into it.",
}
STATUS_ICONS = {
    AgentStatus.REGISTERED: "clock",
    AgentStatus.ACTIVE: "shield-check",
    AgentStatus.QUARANTINED: "lock",
}

# The four independent checks every tool call must pass (see docs/LEARNING.md).
# icon, technical name (shown small), plain question, plain explanation
CHECKS = (
    (
        "scan",
        "Attestation",
        "ID check: is it really our agent?",
        "We take a fingerprint of the agent's code and instructions. If anyone changed even "
        "one letter, the fingerprint won't match and the agent is turned away.",
    ),
    (
        "key",
        "DPoP token",
        "Pass check: does it hold a valid pass?",
        "A temporary pass for this one job. It runs out in minutes and only works for its "
        "owner, like a key card that won't open doors for someone who stole it.",
    ),
    (
        "activity",
        "Risk monitor",
        "Behaviour check: is it acting normally?",
        "Suspicious moves add points. Too many points and a human must step in. Even more "
        "and the agent is locked out immediately.",
    ),
    (
        "user-check",
        "Phone + code",
        "Human check: does a person agree?",
        "Risky actions, like sending money, buzz a person's phone. Nothing happens until they "
        "approve with the code from their authenticator app.",
    ),
)


# ---------------------------------------------------------------------------- request bodies
class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DecideBody(_Body):
    approve: bool
    code: str = Field(default="", max_length=16)


class AttackRunBody(_Body):
    mode: Literal["aimfa", "baseline"]
    index: int | None = Field(default=None, ge=0)  # None = run all


class ActionResult(BaseModel):
    ok: bool
    kind: Literal["success", "warning", "error"]
    message: str


# ---------------------------------------------------------------------------- helpers
def ensure_repo_root_on_path() -> None:
    """``import attacks`` needs the repo root on sys.path. We append our own fixed root
    (never user input), so it can't shadow an installed package."""
    root = str(REPO_ROOT)
    if root not in sys.path:
        sys.path.append(root)


def _load_attacks() -> Sequence[Callable[[str], Any]]:
    ensure_repo_root_on_path()
    from attacks import run_all

    return run_all.ATTACKS


def create_app(
    settings: Settings,
    *,
    client: Any | None = None,
    load_attacks: Callable[[], Sequence[Callable[[str], Any]]] = _load_attacks,
    clock: Callable[[], datetime] | None = None,
    warm_up: bool = True,
) -> FastAPI:
    """Build the dashboard. ``client`` and ``load_attacks`` are injectable for tests."""
    client = client or AdminClient(settings)
    now = clock or (lambda: datetime.now(UTC))
    secret_list = views.secret_values(settings)
    csrf_token = secrets.token_urlsafe(32)  # per server process; embedded in every page
    origins = allowed_origins(settings.dashboard_url)
    templates = Jinja2Templates(directory=str(HERE / "templates"))

    audit_tail = views.AuditTail()
    audit_lock = threading.Lock()
    attack_results: list[Any] = []
    attack_lock = threading.Lock()  # guards the results list (held only briefly)
    run_lock = threading.Lock()  # one attack run at a time: each builds its own temp stack

    @asynccontextmanager
    async def lifespan(_app: FastAPI):  # noqa: ANN202
        # Import the attacks (slow: ~2 s) in the background so the Attack Lab opens fast.
        if warm_up:
            threading.Thread(target=_quiet(load_attacks), daemon=True).start()
        yield

    app = FastAPI(title="AIMFA dashboard", lifespan=lifespan, docs_url=None, redoc_url=None)
    install_error_handling(app)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(ALLOWED_HOSTS))

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # noqa: ANN001, ANN202
        response: Response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    def require_csrf(request: Request) -> None:
        h = request.headers
        if not csrf_ok(
            h.get("x-csrf-token"), csrf_token, h.get("origin"), h.get("sec-fetch-site"), origins
        ):
            raise ApiError(403, ReasonCode.UNAUTHORIZED, "missing or bad CSRF token")

    def call(fn: Callable[[], T]) -> tuple[T | None, dict[str, str] | None]:
        """Run an admin API call; on failure return a safe notice instead of raising."""
        try:
            return fn(), None
        except Exception as err:  # noqa: BLE001 - every failure becomes a safe message
            kind, text = describe_error(err, secret_list)
            return None, {"kind": kind, "message": text}

    def act(fn: Callable[[], Any], success: str) -> ActionResult:
        _, notice = call(fn)
        if notice is not None:
            return ActionResult(ok=False, **notice)
        return ActionResult(ok=True, kind="success", message=_safe(success))

    # ------------------------------------------------------------------ live contexts
    def home_ctx() -> dict[str, Any]:
        agents, notice = call(client.agents)
        if agents is None:
            return {"notice": notice, "cards": [], "pending": None}
        counts = Counter(a.status for a in agents)
        cards = [
            {
                "status": s.value,
                "count": counts.get(s, 0),
                "label": STATUS_LABELS.get(s, s.value),
                "help": STATUS_HELP.get(s, ""),
                "icon": STATUS_ICONS.get(s, "clock"),
            }
            for s in AgentStatus
        ]
        pending, _ = call(lambda: client.approvals("pending"))
        return {
            "notice": None,
            "cards": cards,
            "pending": None if pending is None else len(pending),
        }

    def agents_ctx() -> dict[str, Any]:
        agents, notice = call(client.agents)
        rows = [
            {
                "agent": a.agent_id,
                "role": a.role,
                "status": a.status.value,
                "approver": a.approver_id,
                "quarantined": a.status is AgentStatus.QUARANTINED,
            }
            for a in agents or []
        ]
        return {"notice": notice, "rows": rows, "loaded": agents is not None}

    def tokens_ctx() -> dict[str, Any]:
        tokens, notice = call(client.tokens)
        tokens = tokens or []
        return {
            "notice": notice,
            "loaded": notice is None,
            "rows": views.token_rows(tokens, now()),
            "max_ttl": settings.access_token_ttl_seconds,
            "live_agents": sorted({t.agent_id for t in tokens if not t.revoked}),
        }

    def risk_ctx() -> dict[str, Any]:
        scores, notice = call(client.risk)
        scores = scores or []
        return {
            "notice": notice,
            "loaded": notice is None,
            "chart": views.risk_bars(views.risk_chart(scores, settings)),
            "hits": views.rule_hits(scores),
        }

    def approvals_ctx() -> dict[str, Any]:
        pending, notice = call(lambda: client.approvals("pending"))
        pending = pending or []
        cards = []
        for rec, row in zip(pending, views.approval_rows(pending, now()), strict=True):
            args = json.dumps(row["args"], indent=2, default=str)
            cards.append({**row, "approver_id": rec.approver_id, "args_json": _safe(args)})
        return {"notice": notice, "loaded": notice is None, "cards": cards}

    def audit_ctx() -> dict[str, Any]:
        with audit_lock:
            _, notice = call(lambda: audit_tail.poll(client))
            rows = views.audit_rows(reversed(audit_tail.records))
        return {"notice": notice, "loaded": notice is None, "rows": rows}

    def attack_results_ctx() -> dict[str, Any]:
        with attack_lock:
            cards = views.attack_cards(list(attack_results))
        for card in cards:
            card["evidence"] = _safe(card["evidence"])
        return {
            "cards": list(reversed(cards)),
            "runs": len(cards),
            "blocked": sum(not c["succeeded"] and not c["not_applicable"] for c in cards),
            "worked": sum(c["succeeded"] and not c["not_applicable"] for c in cards),
        }

    def _safe(text: str) -> str:
        return views.redact(text, secret_list)

    live: dict[str, Callable[[], dict[str, Any]]] = {
        "home": home_ctx,
        "agents": agents_ctx,
        "tokens": tokens_ctx,
        "risk": risk_ctx,
        "approvals": approvals_ctx,
        "audit": audit_ctx,
        "attack_results": attack_results_ctx,
    }

    def page(request: Request, key: str, **extra: Any) -> HTMLResponse:
        path, _label, title, blurb = PAGES[key]
        ctx = {
            "nav": [(p[0], p[1], PAGE_ICONS[k]) for k, p in PAGES.items()],
            "active": path,
            "page_icon": PAGE_ICONS[key],
            "title": title,
            "blurb": blurb,
            "csrf_token": csrf_token,
            "refresh_ms": REFRESH_MS,
            "columns": COLUMN_HELP,
            **extra,
        }
        live_key = "attack_results" if key == "attack_lab" else key
        ctx.update(live[live_key]())
        return templates.TemplateResponse(request, f"{key}.html", ctx)

    # ------------------------------------------------------------------ pages
    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request) -> HTMLResponse:
        links = [
            {"href": PAGES[k][0], "label": PAGES[k][1], "icon": PAGE_ICONS[k], "text": text}
            for k, text in PAGE_SHORT.items()
        ]
        return page(request, "home", checks=CHECKS, links=links)

    @app.get("/agents", response_class=HTMLResponse)
    def agents_page(request: Request) -> HTMLResponse:
        return page(request, "agents")

    @app.get("/tokens", response_class=HTMLResponse)
    def tokens_page(request: Request) -> HTMLResponse:
        return page(request, "tokens")

    @app.get("/risk", response_class=HTMLResponse)
    def risk_page(request: Request) -> HTMLResponse:
        return page(request, "risk")

    @app.get("/approvals", response_class=HTMLResponse)
    def approvals_page(request: Request) -> HTMLResponse:
        return page(request, "approvals")

    @app.get("/audit", response_class=HTMLResponse)
    def audit_page(request: Request) -> HTMLResponse:
        return page(request, "audit")

    @app.get("/attack-lab", response_class=HTMLResponse)
    def attack_lab_page(request: Request) -> HTMLResponse:
        attacks, notice = call(load_attacks)
        buttons = views.attack_buttons(attacks or [])
        return page(request, "attack_lab", buttons=buttons, attack_notice=notice)

    @app.get("/partials/{name}", response_class=HTMLResponse)
    def partial(request: Request, name: str) -> HTMLResponse:
        if name not in live:
            raise ApiError(404, ReasonCode.INVALID_ARGUMENTS, "no such view")
        ctx: dict[str, Any] = {"columns": COLUMN_HELP}
        ctx.update(live[name]())
        return templates.TemplateResponse(request, f"partials/{name}.html", ctx)

    @app.get("/audit/verify", response_class=HTMLResponse)
    def audit_verify(request: Request) -> HTMLResponse:
        res, notice = call(client.verify_audit)
        return templates.TemplateResponse(
            request, "partials/audit_verify.html", {"res": res, "notice": notice}
        )

    # ------------------------------------------------------------------ actions (POST)
    guarded = [Depends(require_csrf)]

    @app.post("/api/agents/{agent_id}/clear-quarantine", dependencies=guarded)
    def clear_quarantine(agent_id: str) -> ActionResult:
        return act(lambda: client.clear_quarantine(agent_id), f"Cleared {agent_id}")

    @app.post("/api/agents/{agent_id}/revoke", dependencies=guarded)
    def revoke(agent_id: str) -> ActionResult:
        return act(lambda: client.revoke_agent(agent_id), f"Revoked all tokens of {agent_id}")

    @app.post("/api/approvals/{approval_id}/decide", dependencies=guarded)
    def decide(approval_id: str, body: DecideBody) -> ActionResult:
        # Look the approval up server-side, so the approver id comes from the control plane,
        # never from the browser.
        pending, notice = call(lambda: client.approvals("pending"))
        if notice is not None:
            return ActionResult(ok=False, **notice)
        rec = next((r for r in pending or [] if r.approval_id == approval_id), None)
        if rec is None:
            return ActionResult(ok=False, kind="warning", message="That approval is not pending.")
        verb = "Approved" if body.approve else "Denied"
        return act(
            lambda: client.decide(rec.approval_id, rec.approver_id, body.approve, body.code),
            f"{verb}: {rec.tool} for {rec.agent_id}",
        )

    @app.post("/api/attacks/run", dependencies=guarded)
    def run_attacks(body: AttackRunBody) -> ActionResult:
        attacks, notice = call(load_attacks)
        if notice is not None or not attacks:
            return ActionResult(ok=False, kind="error", message="Attacks could not be loaded.")
        if body.index is not None and body.index >= len(attacks):
            raise ApiError(422, ReasonCode.INVALID_ARGUMENTS, "no such attack")
        indices = range(len(attacks)) if body.index is None else [body.index]
        failed: list[str] = []
        with run_lock:
            for i in indices:
                try:
                    result = attacks[i](body.mode)
                except Exception as err:  # noqa: BLE001 - show failure, never as "blocked"
                    failed.append(f"A{i + 1} could not run: {type(err).__name__}")
                    continue
                with attack_lock:  # results appear one by one while "Run all" continues
                    attack_results.append(result)
        if failed:
            return ActionResult(ok=False, kind="error", message=_safe("; ".join(failed)))
        what = "all attacks" if body.index is None else f"A{body.index + 1}"
        return ActionResult(ok=True, kind="success", message=f"Ran {what} in {body.mode} mode.")

    @app.post("/api/attacks/clear", dependencies=guarded)
    def clear_attacks() -> ActionResult:
        with attack_lock:
            attack_results.clear()
        return ActionResult(ok=True, kind="success", message="Results cleared.")

    return app


COLUMN_HELP = {
    "agents": views.AGENT_COLUMNS,
    "tokens": views.TOKEN_COLUMNS,
    "rule_hits": views.RULE_HIT_COLUMNS,
    "audit": views.AUDIT_COLUMNS,
}


def _quiet(fn: Callable[[], Any]) -> Callable[[], None]:
    """Background warm-up must never crash the server; a real failure shows on the page."""

    def run() -> None:
        try:
            fn()
        except Exception:  # noqa: BLE001, S110 - warm-up only; the page reports errors itself
            pass

    return run


def app_factory() -> FastAPI:
    """Zero-arg entry point for ``uvicorn --factory`` (settings come from .env)."""
    return create_app(get_settings())
