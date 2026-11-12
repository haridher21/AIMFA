"""Registry + admin API: launchers, agents, approvers, kill switch, audit views (T2.1).

Everything here sits behind ``X-Admin-Key``. Registration is the "golden record" step: only
agents an admin registered (with a role, launcher and golden measurement) can ever attest.
"""

from __future__ import annotations

import base64
import secrets
from collections.abc import Callable

import pyotp
from fastapi import APIRouter, Depends, Query, Response

from aimfa.common.db import DuplicateError
from aimfa.common.http import ApiError
from aimfa.common.models import (
    AgentRecord,
    AgentRegistration,
    AgentStatus,
    ApprovalRecord,
    ApprovalStatus,
    ApproverEnrollment,
    ApproverEnrollmentRequest,
    AuditRecord,
    AuditVerifyResult,
    LauncherRegistration,
    ReasonCode,
)
from aimfa.common.policy import PolicyError
from aimfa.control_plane import revocation
from aimfa.control_plane.state import CPState

ISSUER_NAME = "AIMFA"


def new_totp_seed() -> str:
    """160 random bits as base32 (the RFC 4226 recommended size), from ``secrets``."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def provisioning_uri(seed: str, approver_id: str) -> str:
    """The ``otpauth://`` URI an authenticator app scans. It CONTAINS the seed."""
    return pyotp.TOTP(seed).provisioning_uri(name=approver_id, issuer_name=ISSUER_NAME)


def check_registration(state: CPState, reg: AgentRegistration) -> None:
    """Reject an agent that names an unknown role, launcher or approver.

    An unknown role must never be accepted: the token service would have no scopes to
    compare against, and a typo could otherwise silently mean "no limits".
    """
    try:
        state.policy.role(reg.role)
    except PolicyError:
        raise ApiError(422, ReasonCode.INVALID_ARGUMENTS, "unknown role") from None
    if state.db.get_launcher(reg.launcher_id) is None:
        raise ApiError(422, ReasonCode.INVALID_ARGUMENTS, "unknown launcher")
    if state.db.get_approver(reg.approver_id) is None:
        raise ApiError(422, ReasonCode.INVALID_ARGUMENTS, "unknown approver")


def _conflict(message: str) -> ApiError:
    return ApiError(409, ReasonCode.INVALID_ARGUMENTS, message)


def make_router(state: CPState, require_admin: Callable[..., None]) -> APIRouter:
    router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])
    db = state.db

    @router.post("/launchers", status_code=201)
    def add_launcher(reg: LauncherRegistration) -> LauncherRegistration:
        try:
            db.add_launcher(reg)
        except DuplicateError:
            raise _conflict("launcher already registered") from None
        state.audit("admin", "admin.launcher_registered", "info", launcher_id=reg.launcher_id)
        return reg

    @router.post("/approvers", status_code=201)
    def add_approver(req: ApproverEnrollmentRequest) -> ApproverEnrollment:
        seed = new_totp_seed()
        try:
            db.add_approver(req.approver_id, req.display_name, seed)
        except DuplicateError:
            # Never reveal or rotate an existing seed through this endpoint.
            raise _conflict("approver already enrolled") from None
        state.audit("admin", "admin.approver_enrolled", "info", approver_id=req.approver_id)
        return ApproverEnrollment(
            approver_id=req.approver_id, provisioning_uri=provisioning_uri(seed, req.approver_id)
        )

    @router.post("/agents", status_code=201)
    def add_agent(reg: AgentRegistration) -> AgentRecord:
        check_registration(state, reg)
        record = AgentRecord(**reg.model_dump(), created_at=state.now())
        try:
            db.add_agent(record)
        except DuplicateError:
            raise _conflict("agent already registered") from None
        state.audit("admin", "admin.agent_registered", "info", agent_id=reg.agent_id, role=reg.role)
        return record

    @router.get("/agents")
    def list_agents() -> list[AgentRecord]:
        return db.list_agents()

    @router.post("/agents/{agent_id}/revoke", status_code=204)
    def revoke_agent(agent_id: str) -> Response:
        if db.get_agent(agent_id) is None:
            raise ApiError(404, ReasonCode.ATTEST_UNKNOWN_AGENT, "unknown agent")
        revoked = revocation.revoke_agent(db, agent_id, state.now_epoch())
        state.audit(
            "admin", "admin.agent_revoked", "info", ReasonCode.TOKEN_REVOKED,
            agent_id=agent_id, tokens_revoked=revoked,
        )  # fmt: skip
        return Response(status_code=204)

    @router.post("/agents/{agent_id}/clear-quarantine")
    def clear_quarantine(agent_id: str) -> AgentRecord:
        agent = db.get_agent(agent_id)
        if agent is None:
            raise ApiError(404, ReasonCode.ATTEST_UNKNOWN_AGENT, "unknown agent")
        if agent.status is not AgentStatus.QUARANTINED:
            raise _conflict("agent is not quarantined")
        db.clear_quarantine(agent_id)
        db.delete_risk_events(agent_id)  # a fresh start, otherwise it is re-quarantined at once
        state.audit("admin", "admin.quarantine_cleared", "info", agent_id=agent_id)
        cleared = db.get_agent(agent_id)
        if cleared is None:  # deleted between the two reads: fail closed
            raise ApiError(404, ReasonCode.ATTEST_UNKNOWN_AGENT, "unknown agent")
        return cleared

    @router.get("/approvals")
    def list_approvals(status: ApprovalStatus | None = None) -> list[ApprovalRecord]:
        return db.list_approvals(status)

    @router.get("/audit")
    def list_audit(
        after_seq: int = Query(-1, ge=-1), limit: int = Query(100, ge=1, le=1000)
    ) -> list[AuditRecord]:
        return state.audit_log.list(after_seq=after_seq, limit=limit)

    @router.get("/audit/verify")
    def verify_audit() -> AuditVerifyResult:
        return state.audit_log.verify()

    return router
