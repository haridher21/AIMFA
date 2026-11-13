"""Human approvals (factor 4) and the gateway's audit endpoint.

When an action is risky, the gateway asks here for a human to approve THAT exact action.
The human proves they are present with a TOTP code. The approval can be used by exactly one
tool call, only for the same action hash, and only before it expires.

Push notifications (ntfy) are T4.3 and not part of this module yet.
"""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated

import pyotp
from fastapi import APIRouter, Depends, Header, Path

from aimfa.common.crypto import action_hash
from aimfa.common.http import ApiError
from aimfa.common.models import (
    ApprovalConsumeRequest,
    ApprovalCreate,
    ApprovalDecisionRequest,
    ApprovalRecord,
    ApprovalStatus,
    ApprovalStatusView,
    AuditAppend,
    AuditRecord,
    DecisionOutcome,
    ReasonCode,
)
from aimfa.control_plane.revocation import introspect
from aimfa.control_plane.state import CPState
from aimfa.control_plane.sts import check_dpop, parse_dpop_authorization, verify_access_token

TOTP_STEP_SECONDS = 30
APPROVAL_ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"

_LIVE = (ApprovalStatus.PENDING, ApprovalStatus.APPROVED)


# ------------------------------------------------------------------ pure helpers


def effective_status(rec: ApprovalRecord, now: datetime) -> ApprovalStatus:
    """The status as of ``now``: a pending or approved approval past its expiry is EXPIRED.

    Why: an approval is only a short-lived permission. Even a human "yes" must not be usable
    an hour later, so expiry is decided by the clock, not by whether anyone noticed.
    """
    if rec.status in _LIVE and now >= rec.expires_at:
        return ApprovalStatus.EXPIRED
    return rec.status


def consume_blocker(status: ApprovalStatus) -> ReasonCode | None:
    """Why an approval in ``status`` cannot be consumed (None = it can: only APPROVED)."""
    return {
        ApprovalStatus.PENDING: ReasonCode.APPROVAL_STILL_PENDING,
        ApprovalStatus.DENIED: ReasonCode.APPROVAL_DENIED,
        ApprovalStatus.EXPIRED: ReasonCode.APPROVAL_EXPIRED,
        ApprovalStatus.USED: ReasonCode.APPROVAL_ALREADY_USED,
    }.get(status)


def matching_totp_step(seed: str, code: str, now: datetime) -> int | None:
    """Return the 30-second step the code belongs to, or None if it is not valid right now.

    ``valid_window=1`` tolerates one step of clock drift either way. We also need WHICH step
    matched, because the caller records it so the same code can never be used twice.
    """
    totp = pyotp.TOTP(seed)
    if not totp.verify(code, for_time=now, valid_window=1):
        return None
    current = int(now.timestamp()) // TOTP_STEP_SECONDS
    for step in (current, current - 1, current + 1):
        when = datetime.fromtimestamp(step * TOTP_STEP_SECONDS, UTC)
        if step >= 0 and hmac.compare_digest(totp.at(when), code):
            return step
    return None


# ------------------------------------------------------------------ router


def make_router(
    state: CPState, require_admin: Callable[..., None], require_internal: Callable[..., None]
) -> APIRouter:
    router = APIRouter()
    internal = APIRouter(prefix="/internal", dependencies=[Depends(require_internal)])
    db = state.db
    base = state.settings.control_plane_url

    def refresh(rec: ApprovalRecord) -> ApprovalStatus:
        """Current status; persist EXPIRED the first time we notice (best effort)."""
        status = effective_status(rec, state.now())
        if status is ApprovalStatus.EXPIRED and rec.status is not ApprovalStatus.EXPIRED:
            db.transition_approval(rec.approval_id, rec.status, ApprovalStatus.EXPIRED)
        return status

    def get_or_404(approval_id: str, *, actor: str, event: str) -> ApprovalRecord:
        rec = db.get_approval(approval_id)
        if rec is None:
            raise state.deny(
                404, ReasonCode.APPROVAL_NOT_FOUND, "unknown approval",
                actor=actor, event=event, approval_id=approval_id,
            )  # fmt: skip
        return rec

    # ---- internal: gateway -> control plane --------------------------------------------

    @internal.post("/approvals", status_code=201)
    def create_approval(req: ApprovalCreate) -> ApprovalRecord:
        agent = db.get_agent(req.agent_id)
        if agent is None:
            raise state.deny(
                404, ReasonCode.ATTEST_UNKNOWN_AGENT, "unknown agent",
                actor="gateway", event="approval.create_denied",
            )  # fmt: skip
        # Defense in depth: the hash the human will later be held to must really describe
        # this action, so a buggy caller cannot park an approval for a different one.
        try:
            expected = action_hash(req.agent_id, req.task_id, req.tool, req.args)
        except (TypeError, ValueError):
            expected = ""
        if not hmac.compare_digest(expected, req.action_hash):
            raise state.deny(
                422, ReasonCode.INVALID_ARGUMENTS, "action_hash does not match the action",
                actor="gateway", event="approval.create_denied", agent_id=req.agent_id,
            )  # fmt: skip
        now = state.now()
        rec = ApprovalRecord(
            **req.model_dump(),
            approval_id=secrets.token_urlsafe(16),
            approver_id=agent.approver_id,
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=now + timedelta(seconds=state.settings.approval_timeout_seconds),
        )
        db.add_approval(rec)
        state.audit(
            req.agent_id, "approval.created", DecisionOutcome.PENDING, ReasonCode.PENDING_APPROVAL,
            approval_id=rec.approval_id, task_id=req.task_id, tool=req.tool,
            approver_id=rec.approver_id, approval_reason=req.reason.value,
        )  # fmt: skip
        # TODO(T4.3): send the ntfy push to the approver here. It must never block or fail
        # this request: a push outage must not stop the approval from existing.
        return rec

    @internal.post("/approvals/{approval_id}/consume")
    def consume_approval(
        approval_id: Annotated[str, Path(pattern=APPROVAL_ID_PATTERN)],
        req: ApprovalConsumeRequest,
    ) -> ApprovalRecord:
        rec = get_or_404(approval_id, actor="gateway", event="approval.consume_denied")
        actor = rec.agent_id

        def refuse(status: int, reason: ReasonCode) -> ApiError:
            return state.deny(
                status, reason, "approval cannot be used",
                actor=actor, event="approval.consume_denied", approval_id=approval_id,
            )  # fmt: skip

        blocker = consume_blocker(refresh(rec))
        if blocker is not None:
            raise refuse(403, blocker)
        # The human approved ONE action; any other agent/task/tool/args is a different hash.
        if not hmac.compare_digest(rec.action_hash, req.action_hash):
            raise refuse(403, ReasonCode.APPROVAL_MISMATCH)
        # One atomic UPDATE: two concurrent retries cannot both win.
        won = db.consume_approval(
            approval_id, agent_id=rec.agent_id, action_hash=req.action_hash, now=state.now()
        )
        if not won:
            latest = db.get_approval(approval_id)
            reason = (
                consume_blocker(effective_status(latest, state.now()))
                if latest is not None
                else None
            )
            raise refuse(403, reason or ReasonCode.APPROVAL_ALREADY_USED)
        state.audit(
            actor, "approval.consumed", DecisionOutcome.ALLOW,
            approval_id=approval_id, task_id=rec.task_id, tool=rec.tool,
        )  # fmt: skip
        used = db.get_approval(approval_id)
        if used is None:  # deleted between the two statements: fail closed
            raise refuse(404, ReasonCode.APPROVAL_NOT_FOUND)
        return used

    @internal.post("/audit", status_code=201)
    def append_audit(entry: AuditAppend) -> AuditRecord:
        """Let the gateway write its decisions into the same tamper-evident chain.

        Only ``component="gateway"`` is accepted: this endpoint must not let a caller
        forge records that claim to come from the control plane or the launcher.
        """
        if entry.component != "gateway":
            raise state.deny(
                422, ReasonCode.INVALID_ARGUMENTS, "internal audit is for the gateway only",
                actor="gateway", event="internal.audit_denied",
            )  # fmt: skip
        return state.audit_log.append(entry)

    # ---- agent: poll status ------------------------------------------------------------

    @router.get("/approvals/{approval_id}")
    def approval_status(
        approval_id: Annotated[str, Path(pattern=APPROVAL_ID_PATTERN)],
        authorization: Annotated[str | None, Header()] = None,
        dpop: Annotated[str | None, Header()] = None,
    ) -> ApprovalStatusView:
        actor = "unknown"
        try:
            token = parse_dpop_authorization(authorization)
            claims = verify_access_token(state, token)
            actor = claims.sub
            check_dpop(
                state, dpop,
                htu=f"{base}/approvals/{approval_id}",
                expected_jkt=claims.cnf.get("jkt", ""),
                access_token=token,
                htm="GET",
            )  # fmt: skip
            live = introspect(db, claims.jti, claims.sub, state.now())
            if not live.active:
                code = live.reason_code
                if code is ReasonCode.OK:
                    code = ReasonCode.TOKEN_INVALID
                raise ApiError(
                    403 if code is ReasonCode.AGENT_QUARANTINED else 401, code, "token not active"
                )
            rec = db.get_approval(approval_id)
            # Same agent AND same task only; anything else looks exactly like "no such id",
            # so an agent cannot discover other agents' approvals.
            if rec is None or rec.agent_id != claims.sub or rec.task_id != claims.task_id:
                raise ApiError(404, ReasonCode.APPROVAL_NOT_FOUND, "unknown approval")
        except ApiError as err:
            state.audit(
                actor, "approval.status_denied", DecisionOutcome.DENY, err.reason_code,
                approval_id=approval_id,
            )  # fmt: skip
            raise
        return ApprovalStatusView(approval_id=approval_id, status=refresh(rec))

    # ---- human: decide -----------------------------------------------------------------

    @router.post("/approvals/{approval_id}/decide", dependencies=[Depends(require_admin)])
    def decide_approval(
        approval_id: Annotated[str, Path(pattern=APPROVAL_ID_PATTERN)],
        req: ApprovalDecisionRequest,
    ) -> ApprovalRecord:
        actor = f"approver:{req.approver_id}"
        event = "approval.decide_denied"
        rec = get_or_404(approval_id, actor=actor, event=event)

        status = refresh(rec)
        if status is not ApprovalStatus.PENDING:
            # Decided or expired already: a second "yes" can never override a first answer.
            reason = (
                ReasonCode.APPROVAL_EXPIRED
                if status is ApprovalStatus.EXPIRED
                else ReasonCode.APPROVAL_ALREADY_USED
            )
            raise state.deny(
                409, reason, "approval is no longer pending",
                actor=actor, event=event, approval_id=approval_id,
            )  # fmt: skip

        def bad_totp() -> ApiError:
            return state.deny(
                401, ReasonCode.APPROVAL_INVALID_TOTP, "approver or code not accepted",
                actor=actor, event=event, approval_id=approval_id,
            )  # fmt: skip

        # Only the assigned approver may decide. The same message for "wrong person" and
        # "wrong code" tells an attacker nothing about which part was wrong.
        approver = db.get_approver(rec.approver_id)
        if req.approver_id != rec.approver_id or approver is None:
            raise bad_totp()
        step = matching_totp_step(approver.totp_seed.get_secret_value(), req.totp_code, state.now())
        # A code can be used once per approver: a shoulder-surfed code cannot be replayed.
        if step is None or not db.mark_totp_step_used(rec.approver_id, step):
            raise bad_totp()

        if not db.decide_approval(
            approval_id, approver_id=rec.approver_id, approve=req.approve, now=state.now()
        ):
            raise state.deny(
                409, ReasonCode.APPROVAL_EXPIRED, "approval is no longer pending",
                actor=actor, event=event, approval_id=approval_id,
            )  # fmt: skip
        if req.approve:
            state.audit(actor, "approval.approved", DecisionOutcome.ALLOW, approval_id=approval_id)
        else:
            # TODO(T4.x): report an APPROVAL_DENIED risk event to the monitor.
            state.audit(
                actor, "approval.denied", DecisionOutcome.DENY, ReasonCode.APPROVAL_DENIED,
                approval_id=approval_id,
            )  # fmt: skip
        decided = db.get_approval(approval_id)
        if decided is None:  # fail closed
            raise ApiError(404, ReasonCode.APPROVAL_NOT_FOUND, "unknown approval")
        return decided

    router.include_router(internal)
    return router
