"""Revocation and introspection: "is this token still good right now?" (T2.3).

A signed token stays cryptographically valid until it expires, so it cannot be recalled by
itself. The gateway therefore asks the control plane on every call; this is what makes the
kill switch and quarantine take effect immediately.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from fastapi import APIRouter, Depends

from aimfa.common.db import Database
from aimfa.common.models import (
    ActiveTokenView,
    AgentStatus,
    IntrospectRequest,
    IntrospectResponse,
    ReasonCode,
)
from aimfa.control_plane.state import CPState


def revoke_agent(db: Database, agent_id: str, now_epoch: int) -> int:
    """Kill switch: revoke every token AND invalidate the agent's current identity.

    Identity credentials issued up to now are refused from the next second on, so the agent
    cannot just trade its old identity for a fresh access token; it must re-attest.
    Returns how many access tokens were newly revoked.
    """
    return db.revoke_agent_identity(agent_id, not_before=now_epoch + 1)


def introspect(db: Database, jti: str, agent_id: str, now: datetime) -> IntrospectResponse:
    """Decide whether a token is active. Anything unexpected answers "inactive" (fail closed).

    The agent's status is checked BEFORE the token's own flag: a quarantined agent must be
    reported as AGENT_QUARANTINED (not merely "revoked"), and a token issued in the instant
    before quarantine must still be refused.
    """
    agent = db.get_agent(agent_id)
    token = db.get_token(jti)
    if agent is None or token is None or token.agent_id != agent_id:
        return IntrospectResponse(active=False, reason_code=ReasonCode.TOKEN_INVALID)
    if agent.status is AgentStatus.QUARANTINED:
        return IntrospectResponse(
            active=False, reason_code=ReasonCode.AGENT_QUARANTINED, agent_status=agent.status
        )
    if token.revoked:
        return IntrospectResponse(
            active=False, reason_code=ReasonCode.TOKEN_REVOKED, agent_status=agent.status
        )
    if token.expires_at <= now:
        return IntrospectResponse(
            active=False, reason_code=ReasonCode.TOKEN_EXPIRED, agent_status=agent.status
        )
    return IntrospectResponse(active=True, agent_status=agent.status)


def make_router(
    state: CPState, require_admin: Callable[..., None], require_internal: Callable[..., None]
) -> APIRouter:
    router = APIRouter()

    @router.get("/admin/tokens", dependencies=[Depends(require_admin)])
    def list_tokens() -> list[ActiveTokenView]:
        """Token metadata only; the token strings themselves are never stored."""
        return state.db.list_tokens()

    @router.post("/internal/introspect", dependencies=[Depends(require_internal)])
    def introspect_token(req: IntrospectRequest) -> IntrospectResponse:
        return introspect(state.db, req.jti, req.agent_id, state.now())

    return router
