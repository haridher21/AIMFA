"""Control-plane app factory (:8000): identity provider, token service and admin API.

``create_app`` does all start-up work eagerly (directories, signing key, DB schema), so a
test can build an app with temp directories and an injected clock and use it immediately.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime

import httpx
from fastapi import FastAPI

from aimfa.common.config import Settings, get_settings
from aimfa.common.db import Database
from aimfa.common.dpop import ReplayCache
from aimfa.common.http import install_error_handling, require_strong_secrets
from aimfa.common.policy import Policy
from aimfa.control_plane import approvals, attestation, monitor, registry, revocation, sts
from aimfa.control_plane.audit import AuditLog
from aimfa.control_plane.notify import Notifier, NtfyNotifier
from aimfa.control_plane.state import (
    CPState,
    default_clock,
    load_or_create_signing_key,
    make_secret_guards,
)

NTFY_TIMEOUT_SECONDS = 3.0
# httpx logs every request URL at INFO, and the ntfy topic is part of that URL.
logging.getLogger("httpx").setLevel(logging.WARNING)


def create_app(
    settings: Settings,
    *,
    clock: Callable[[], datetime] | None = None,
    notifier: Notifier | None = None,
) -> FastAPI:
    """Build the control plane. ``clock`` must return a timezone-aware UTC datetime.

    ``notifier`` defaults to ntfy with a short timeout so a slow push cannot stall approvals.
    """
    require_strong_secrets(settings)
    clock = clock or default_clock
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.keys_dir.mkdir(parents=True, exist_ok=True)
    db = Database(settings.db_path)
    state = CPState(
        settings=settings,
        db=db,
        audit_log=AuditLog(db, clock=clock),
        policy=Policy.load(settings.policy_dir),
        signing_key=load_or_create_signing_key(settings.keys_dir),
        clock=clock,
        replay=ReplayCache(settings.dpop_max_age_seconds),
    )
    require_admin, require_internal = make_secret_guards(state)
    notifier = notifier or NtfyNotifier(settings, httpx.Client(timeout=NTFY_TIMEOUT_SECONDS))
    risk = monitor.RiskMonitor(
        db=db, policy=state.policy, settings=settings, audit_log=state.audit_log, clock=clock
    )

    app = FastAPI(title="AIMFA control plane")
    install_error_handling(app)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(registry.make_router(state, require_admin))
    app.include_router(attestation.make_router(state))
    app.include_router(sts.make_router(state))
    app.include_router(revocation.make_router(state, require_admin, require_internal))
    app.include_router(monitor.make_router(db, risk, require_admin, require_internal))
    app.include_router(
        approvals.make_router(
            state, require_admin, require_internal, notifier=notifier, monitor=risk
        )
    )
    return app


def app_factory() -> FastAPI:
    """Zero-arg entry point for ``uvicorn --factory`` (settings come from .env)."""
    return create_app(get_settings())
