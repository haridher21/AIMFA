"""Control-plane app factory (:8000): identity provider, token service and admin API.

``create_app`` does all start-up work eagerly (directories, signing key, DB schema), so a
test can build an app with temp directories and an injected clock and use it immediately.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from fastapi import FastAPI

from aimfa.common.config import Settings
from aimfa.common.db import Database
from aimfa.common.dpop import ReplayCache
from aimfa.common.http import install_error_handling, require_strong_secrets
from aimfa.common.policy import Policy
from aimfa.control_plane import approvals, attestation, registry, revocation, sts
from aimfa.control_plane.audit import AuditLog
from aimfa.control_plane.state import (
    CPState,
    default_clock,
    load_or_create_signing_key,
    make_secret_guards,
)


def create_app(settings: Settings, *, clock: Callable[[], datetime] | None = None) -> FastAPI:
    """Build the control plane. ``clock`` must return a timezone-aware UTC datetime."""
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

    app = FastAPI(title="AIMFA control plane")
    install_error_handling(app)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(registry.make_router(state, require_admin))
    app.include_router(attestation.make_router(state))
    app.include_router(sts.make_router(state))
    app.include_router(revocation.make_router(state, require_admin, require_internal))
    app.include_router(approvals.make_router(state, require_admin, require_internal))
    return app
