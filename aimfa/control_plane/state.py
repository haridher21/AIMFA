"""Shared state and small helpers for the control-plane routers.

``CPState`` bundles what every router needs (settings, database, audit log, policy, signing
key, clock, DPoP replay cache) so route modules stay thin and the security logic can live in
plain functions that take what they need as arguments.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import Header

from aimfa.common.config import Settings
from aimfa.common.crypto import (
    generate_keypair,
    jwk_thumbprint,
    load_private_key,
    save_private_key,
)
from aimfa.common.db import Database
from aimfa.common.dpop import ReplayCache
from aimfa.common.http import ApiError, secret_matches
from aimfa.common.models import AuditAppend, DecisionOutcome, PublicJWK, ReasonCode
from aimfa.common.policy import Policy
from aimfa.control_plane.audit import AuditLog

SIGNING_KEY_FILE = "control_plane_signing.pem"
_DETAIL_MAX = 120


def load_or_create_signing_key(keys_dir: Path) -> Ed25519PrivateKey:
    """The control plane's token-signing key: generated on first start, then reused.

    Reusing it means tokens and the JWKS stay valid across restarts. The private key stays
    in ``KEYS_DIR`` (git-ignored) and is never returned by any endpoint.
    """
    path = keys_dir / SIGNING_KEY_FILE
    if path.exists():
        return load_private_key(path)
    key = generate_keypair()
    save_private_key(key, path)
    return key


def public_key_from_jwk(jwk: PublicJWK) -> Ed25519PublicKey:
    """Turn a JWK into a key object. ``jwk_thumbprint`` first enforces the canonical form."""
    jwk_thumbprint(jwk)
    raw = base64.urlsafe_b64decode(jwk.x + "=")
    return Ed25519PublicKey.from_public_bytes(raw)


def clip(value: object) -> str:
    """Shorten attacker-controlled text before it goes into an audit record."""
    return str(value)[:_DETAIL_MAX]


@dataclass
class CPState:
    settings: Settings
    db: Database
    audit_log: AuditLog
    policy: Policy
    signing_key: Ed25519PrivateKey
    clock: Callable[[], datetime]
    replay: ReplayCache

    def now(self) -> datetime:
        return self.clock()

    def now_epoch(self) -> int:
        return int(self.clock().timestamp())

    def audit(
        self,
        actor: str,
        event: str,
        outcome: DecisionOutcome | str,
        reason: ReasonCode = ReasonCode.OK,
        **details: Any,
    ) -> None:
        """Append one record to the tamper-evident audit chain (AGENTS.md rule 10)."""
        self.audit_log.append(
            AuditAppend(
                component="control_plane",
                actor=actor,
                event=event,
                outcome=outcome,
                reason_code=reason,
                details=details,
            )
        )

    def deny(
        self,
        status: int,
        reason: ReasonCode,
        message: str,
        *,
        actor: str,
        event: str,
        **details: Any,
    ) -> ApiError:
        """Audit a denial and return the matching error for the caller to ``raise``."""
        self.audit(actor, event, DecisionOutcome.DENY, reason, **details)
        return ApiError(status, reason, message)


def default_clock() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------- header dependencies


def make_secret_guards(state: CPState) -> tuple[Callable[..., None], Callable[..., None]]:
    """Build the ``X-Admin-Key`` and ``X-Internal-Secret`` FastAPI dependencies.

    Both compare in constant time and fail with 401 UNAUTHORIZED; the failed attempt is
    audited (without the value that was tried).
    """

    def require_admin(x_admin_key: Annotated[str | None, Header()] = None) -> None:
        if not secret_matches(x_admin_key, state.settings.admin_api_key):
            raise state.deny(
                401, ReasonCode.UNAUTHORIZED, "admin key required",
                actor="unknown", event="admin.auth",
            )  # fmt: skip

    def require_internal(x_internal_secret: Annotated[str | None, Header()] = None) -> None:
        if not secret_matches(x_internal_secret, state.settings.internal_service_secret):
            raise state.deny(
                401, ReasonCode.UNAUTHORIZED, "internal secret required",
                actor="unknown", event="internal.auth",
            )  # fmt: skip

    return require_admin, require_internal
