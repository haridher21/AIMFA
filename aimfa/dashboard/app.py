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
PAGES: dict[str, tuple[str, str, str, str]] = {
    "home": (
        "/",
        "Home",
        "AIMFA admin console",
        "The control room for the zero-trust gateway. Watch agents, tokens, risk and the audit "
        "log live, and approve risky actions. Everything goes through the control plane's "
        "admin API: this app never reads the database.",
    ),
    "agents": (
        "/agents",
        "Agents",
        "Agents",
        "Every registered AI agent, its role and its current state. Revoke is the kill switch: "
        "it cancels all of the agent's tokens at once.",
    ),
    "tokens": (
        "/tokens",
        "Tokens",
        "Tokens",
        "Short-lived access tokens issued to agents. Each one is limited to one task and its "
        "scopes, works only with the agent's private key (DPoP), and expires on its own.",
    ),
    "risk": (
        "/risk",
        "Risk",
        "Risk",
        "How suspicious each agent's behavior looks. Each rule hit adds points, and points "
        "fade over time. Above the step-up line, actions need a human. At the revoke line, the "
        "agent is cut off and quarantined.",
    ),
    "approvals": (
        "/approvals",
        "Approvals",
        "Approvals",
        "Risky actions an agent is waiting to do. Nothing happens until a human approves with "
        "a TOTP code. Each request expires if nobody answers.",
    ),
    "audit": (
        "/audit",
        "Audit",
        "Audit",
        "Every allow, deny and pending decision, as it happens. Records are hash-chained, so "
        "editing or deleting one afterwards is detectable. Verify chain re-checks every link.",
    ),
    "attack_lab": (
        "/attack-lab",
        "Attack Lab",
        "Attack Lab",
        "Run real attacks against the system twice: once with only a shared password "
        "(baseline) and once with AIMFA. Each card shows whether the attack worked, and if "
        "not, which check stopped it.",
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
    "agents": "Who is registered, who is quarantined. Kill switch.",
    "tokens": "Live tokens and their countdowns.",
    "risk": "Behavior scores against the step-up and revoke lines.",
    "approvals": "Risky actions waiting for a human + TOTP.",
    "audit": "Tamper-evident log of every decision.",
    "attack_lab": "Run A1-A10, baseline vs AIMFA.",
}

STATUS_HELP = {
    AgentStatus.REGISTERED: "Known, but not attested yet.",
    AgentStatus.ACTIVE: "Attested: holds a valid identity credential.",
    AgentStatus.QUARANTINED: "Risk too high. All tokens revoked until an admin clears it.",
}
STATUS_ICONS = {
    AgentStatus.REGISTERED: "clock",
    AgentStatus.ACTIVE: "shield-check",
    AgentStatus.QUARANTINED: "lock",
}

# The four independent checks every tool call must pass (see docs/LEARNING.md).
# icon, mechanism, name, explanation
CHECKS = (
    (
        "scan",
        "Attestation",
        "What the agent IS",
        "Its code, prompt, tools and model are hashed and must match the registered "
        "'golden' value.",
    ),
    (
        "key",
        "DPoP token",
        "What the agent HAS",
        "A short-lived, scoped token that only works together with the agent's private key.",
    ),
    (
        "activity",
        "Risk monitor",
        "What the agent DOES",
        "A behavior risk score. High scores force step-up; very high scores revoke the agent "
        "and quarantine it.",
    ),
    (
        "user-check",
        "Push + TOTP",
        "A HUMAN for risky actions",
        "A phone push, then approval with a 6-digit code, bound to that exact action.",
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
