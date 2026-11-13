"""The gateway's checkpoint: every tool call runs these steps, in this order (CONTRACTS.md).

Each step is a small function that either returns or raises ``ApiError`` with a specific
``ReasonCode``. Nothing is forwarded to the resources unless ALL steps passed, and every
outcome (allow, deny, pending) is written to the audit chain first.

    1 parse header -> 2 verify token -> 3 verify DPoP -> 4 introspect -> 5 resolve tool
    -> 6 scope -> 7 risk -> 8 tier -> 9 approval -> 10 forward
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from aimfa.common.config import Settings
from aimfa.common.crypto import action_hash, verify_jwt
from aimfa.common.dpop import DPoPError, ReplayCache, verify_proof
from aimfa.common.http import ApiError
from aimfa.common.models import (
    ACCESS_TOKEN_USE,
    GATEWAY_AUDIENCE,
    TOKEN_ISSUER,
    AccessTokenClaims,
    AgentStatus,
    ApprovalConsumeRequest,
    ApprovalCreate,
    ApprovalReason,
    AuditAppend,
    Decision,
    DecisionOutcome,
    EventType,
    IntrospectRequest,
    ReasonCode,
    RiskEvent,
    RiskScore,
    Tier,
    ToolCall,
    ToolCallResponse,
)
from aimfa.common.policy import Policy, PolicyError, ResolvedAction
from aimfa.control_plane.state import clip, public_key_from_jwk
from aimfa.control_plane.sts import parse_dpop_authorization
from aimfa.gateway import proxy
from aimfa.gateway.cp_client import ControlPlaneClient, ControlPlaneError

MAX_BODY_BYTES = 1_100_000  # a little over the resources' 1 MB file-write limit
APPROVAL_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
AUDIT_EVENT = "gateway.tool_call"
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ context


class RiskMonitor(Protocol):
    """Reports an event to the behavioral monitor and gets the agent's current score."""

    def report(self, event: RiskEvent) -> RiskScore: ...


class StubMonitor:
    """Placeholder until the real monitor is wired in (T4.2): never raises the score."""

    def report(self, event: RiskEvent) -> RiskScore:
        return RiskScore(
            agent_id=event.agent_id, score=0, status=AgentStatus.ACTIVE, step_up_required=False
        )


@dataclass
class GatewayContext:
    settings: Settings
    policy: Policy
    cp: ControlPlaneClient
    resources: httpx.Client
    monitor: RiskMonitor
    replay: ReplayCache
    clock: Callable[[], datetime]
    _key: Ed25519PublicKey | None = field(default=None, repr=False)

    def now(self) -> datetime:
        return self.clock()

    def now_epoch(self) -> int:
        return int(self.clock().timestamp())

    def public_key(self) -> Ed25519PublicKey:
        """The control plane's token-verification key, fetched once from its JWKS.

        If it cannot be fetched we cannot verify anything, so the call is refused.
        """
        if self._key is None:
            try:
                self._key = public_key_from_jwk(self.cp.jwks().keys[0])
            except (ControlPlaneError, IndexError, ValueError, TypeError):
                raise ApiError(502, ReasonCode.UPSTREAM_ERROR, "token key unavailable") from None
        return self._key


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class Trace:
    """What we learned about the call so far; goes into the audit record, never secrets."""

    actor: str = "unknown"
    task_id: str | None = None
    jti: str | None = None
    tool: str | None = None
    target: str | None = None
    tier: str | None = None
    approval_id: str | None = None
    action_hash: str | None = None

    def details(self) -> dict[str, Any]:
        return {k: v for k, v in vars(self).items() if k != "actor" and v is not None}


@dataclass(frozen=True)
class Verdict:
    outcome: DecisionOutcome  # ALLOW or PENDING (a denial is an ApiError instead)
    request: proxy.ResourceRequest
    approval_id: str | None
    risk_score: float


# ------------------------------------------------------------------ steps 1-4: who is calling?


def verify_token(token: str, key: Ed25519PublicKey, now: int) -> AccessTokenClaims:
    """Step 2: only OUR access token, for the gateway, unexpired.

    ``verify_jwt`` pins EdDSA and checks signature, ``iss``, ``aud`` and ``exp`` with the
    injected clock. ``token_use="access"`` stops an identity credential from being used here.
    """
    try:
        claims = verify_jwt(
            token, key, GATEWAY_AUDIENCE, TOKEN_ISSUER, token_use=ACCESS_TOKEN_USE, now=now
        )
        return AccessTokenClaims.model_validate(claims)
    except jwt.ExpiredSignatureError:
        raise ApiError(401, ReasonCode.TOKEN_EXPIRED, "access token expired") from None
    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise ApiError(401, ReasonCode.TOKEN_INVALID, "access token invalid") from None


def verify_dpop(
    proof: str | None,
    claims: AccessTokenClaims,
    token: str,
    *,
    htu: str,
    replay: ReplayCache,
    max_age: int,
    now: int,
) -> None:
    """Step 3: the caller must hold the key the token is bound to, for THIS request.

    The proof must be signed by the key whose thumbprint is the token's ``cnf.jkt``, name
    this method and URL, be fresh and unused, and carry the hash (``ath``) of this exact
    token. A stolen token alone therefore cannot be used.
    """
    if not proof:
        raise ApiError(401, ReasonCode.DPOP_MISSING, "DPoP proof required")
    jkt = claims.cnf.get("jkt")
    if not isinstance(jkt, str) or not jkt:
        # Passing None to verify_proof would mean "skip the key check": refuse instead.
        raise ApiError(401, ReasonCode.TOKEN_INVALID, "token is not key-bound")
    try:
        verify_proof(
            proof,
            htm="POST",
            htu=htu,
            expected_jkt=jkt,
            access_token=token,
            replay_cache=replay,
            max_age=max_age,
            now=now,
        )
    except DPoPError as err:
        raise ApiError(401, err.reason_code, "DPoP proof rejected") from None


def check_token_active(cp: ControlPlaneClient, claims: AccessTokenClaims) -> None:
    """Step 4: a signed token stays valid until it expires, so ask if it was revoked.

    This is what makes the kill switch and quarantine take effect on the very next call.
    If the control plane cannot answer, we refuse (fail closed).
    """
    try:
        live = cp.introspect(IntrospectRequest(jti=claims.jti, agent_id=claims.sub))
    except ControlPlaneError:
        raise ApiError(502, ReasonCode.UPSTREAM_ERROR, "token status unavailable") from None
    if live.active:
        return
    code = live.reason_code if live.reason_code is not ReasonCode.OK else ReasonCode.TOKEN_INVALID
    raise ApiError(403 if code is ReasonCode.AGENT_QUARANTINED else 401, code, "token not active")


# ------------------------------------------------------------------ steps 5-8: may it do this?


def parse_tool_call(raw: bytes) -> ToolCall:
    """The body must be exactly a ``ToolCall`` (unknown fields are rejected)."""
    if len(raw) > MAX_BODY_BYTES:
        raise ApiError(422, ReasonCode.INVALID_ARGUMENTS, "request too large")
    try:
        return ToolCall.model_validate_json(raw)
    except ValidationError:
        raise ApiError(422, ReasonCode.INVALID_ARGUMENTS, "request failed validation") from None


def resolve_action(policy: Policy, call: ToolCall) -> ResolvedAction:
    """Step 5: unknown tool -> 403, bad or traversing arguments -> 422, paths normalized."""
    try:
        return policy.resolve(call.tool, call.args)
    except PolicyError as err:
        status = 422 if err.reason_code is ReasonCode.INVALID_ARGUMENTS else 403
        raise ApiError(status, err.reason_code, err.message) from None


def require_scope(policy: Policy, claims: AccessTokenClaims, action: ResolvedAction) -> None:
    """Step 6: least privilege. The token's scopes must cover the NORMALIZED target."""
    if not policy.scope_allows(claims.scopes, action):
        raise ApiError(403, ReasonCode.SCOPE_DENIED, "token scopes do not cover this action")


def report_risk(
    monitor: RiskMonitor, claims: AccessTokenClaims, action: ResolvedAction, now: datetime
) -> RiskScore:
    """Step 7: tell the behavioral monitor what the agent is doing; get its score back.

    A monitor that fails or reports a quarantined agent blocks the call.
    """
    event = RiskEvent(
        agent_id=claims.sub,
        task_id=claims.task_id,
        event_type=EventType.TOOL_ALLOWED,  # TODO(T4.2): sensitive/external/out-of-profile
        tool=action.tool,
        target=action.target,
        timestamp=now,
    )
    try:
        score = monitor.report(event)
    except Exception:
        raise ApiError(502, ReasonCode.UPSTREAM_ERROR, "risk monitor unavailable") from None
    if score.status is AgentStatus.QUARANTINED:
        raise ApiError(403, ReasonCode.AGENT_QUARANTINED, "agent is quarantined")
    return score


def approval_reason(tier: Tier, risk: RiskScore) -> ApprovalReason | None:
    """Step 8: does this action need a human? (None = no, go ahead.)

    forbidden -> never; high -> always; medium -> only when the agent's risk is elevated.
    """
    if tier is Tier.FORBIDDEN:
        raise ApiError(403, ReasonCode.ACTION_FORBIDDEN, "action is forbidden by policy")
    if tier is Tier.HIGH:
        return ApprovalReason.HIGH_TIER
    if tier is Tier.MEDIUM and risk.step_up_required:
        return ApprovalReason.RISK_STEP_UP
    return None


# ------------------------------------------------------------------ step 9: the human


def consume_approval(cp: ControlPlaneClient, approval_id: str, expected_hash: str) -> None:
    """Spend an approval for exactly this action, or raise the specific APPROVAL_* error.

    ``approval_id`` comes from the agent, so it is shape-checked before it is used in a URL.
    A shape that cannot be one of ours is reported as "not found" without asking anyone.
    """
    if not APPROVAL_ID_RE.fullmatch(approval_id):
        raise ApiError(403, ReasonCode.APPROVAL_NOT_FOUND, "unknown approval")
    try:
        cp.consume_approval(approval_id, ApprovalConsumeRequest(action_hash=expected_hash))
    except ControlPlaneError as err:
        if err.reason_code.value.startswith("APPROVAL_"):
            raise ApiError(403, err.reason_code, "approval cannot be used") from None
        raise ApiError(502, ReasonCode.UPSTREAM_ERROR, "approval service unavailable") from None


def request_approval(
    cp: ControlPlaneClient,
    claims: AccessTokenClaims,
    action: ResolvedAction,
    digest: str,
    reason: ApprovalReason,
    risk: RiskScore,
) -> str:
    """Ask the control plane to park this exact action until a human decides."""
    try:
        rec = cp.create_approval(
            ApprovalCreate(
                agent_id=claims.sub,
                task_id=claims.task_id,
                tool=action.tool,
                args=action.args,
                action_hash=digest,
                reason=reason,
                risk_score=risk.score,
            )
        )
    except ControlPlaneError:
        raise ApiError(502, ReasonCode.UPSTREAM_ERROR, "approval service unavailable") from None
    return rec.approval_id


# ------------------------------------------------------------------ the whole pipeline


def evaluate(
    ctx: GatewayContext, raw: bytes, authorization: str | None, dpop: str | None, trace: Trace
) -> Verdict:
    """Run steps 1-9. Returns ALLOW/PENDING; any failure raises ``ApiError``."""
    settings = ctx.settings
    token = parse_dpop_authorization(authorization)  # 1
    claims = verify_token(token, ctx.public_key(), ctx.now_epoch())  # 2
    trace.actor, trace.task_id, trace.jti = claims.sub, claims.task_id, claims.jti  # verified
    verify_dpop(  # 3
        dpop,
        claims,
        token,
        htu=settings.gateway_url + "/tool",
        replay=ctx.replay,
        max_age=settings.dpop_max_age_seconds,
        now=ctx.now_epoch(),
    )
    check_token_active(ctx.cp, claims)  # 4

    call = parse_tool_call(raw)
    trace.tool, trace.approval_id = clip(call.tool), call.approval_id and clip(call.approval_id)
    action = resolve_action(ctx.policy, call)  # 5
    trace.target, trace.tier = clip(action.target), action.tier.value
    request = proxy.build_request(action.tool, action.args)  # uses the NORMALIZED args
    require_scope(ctx.policy, claims, action)  # 6
    risk = report_risk(ctx.monitor, claims, action, ctx.now())  # 7
    reason = approval_reason(action.tier, risk)  # 8

    if reason is None:
        return Verdict(DecisionOutcome.ALLOW, request, None, risk.score)

    digest = action_hash(claims.sub, claims.task_id, action.tool, action.args)
    trace.action_hash = digest
    if call.approval_id is None:  # 9a: first attempt, park it for a human
        approval_id = request_approval(ctx.cp, claims, action, digest, reason, risk)
        trace.approval_id = approval_id
        return Verdict(DecisionOutcome.PENDING, request, approval_id, risk.score)
    consume_approval(ctx.cp, call.approval_id, digest)  # 9b: retry with a human's yes
    return Verdict(DecisionOutcome.ALLOW, request, call.approval_id, risk.score)


def record(
    cp: ControlPlaneClient,
    trace: Trace,
    outcome: DecisionOutcome,
    reason: ReasonCode,
    request_id: str,
    event: str = AUDIT_EVENT,
) -> None:
    """Write one decision to the audit chain via the control plane."""
    cp.audit(
        AuditAppend(
            component="gateway",
            actor=trace.actor,
            event=event,
            outcome=outcome,
            reason_code=reason,
            details={"request_id": request_id, **trace.details()},
        )
    )


def record_denial(ctx: GatewayContext, trace: Trace, err: ApiError, request_id: str) -> None:
    """Audit a denial. If the audit write fails the call is STILL denied (never allowed)."""
    try:
        record(ctx.cp, trace, DecisionOutcome.DENY, err.reason_code, request_id)
    except ControlPlaneError:
        # The request is refused anyway; leave a local trace so the gap is visible.
        logger.warning("audit unavailable; denied request %s (%s)", request_id, err.reason_code)


def decision_response(
    outcome: DecisionOutcome,
    reason: ReasonCode,
    request_id: str,
    *,
    approval_id: str | None = None,
    risk_score: float | None = None,
    result: dict[str, Any] | None = None,
) -> ToolCallResponse:
    return ToolCallResponse(
        decision=Decision(
            outcome=outcome,
            reason_code=reason,
            request_id=request_id,
            approval_id=approval_id,
            risk_score=risk_score,
        ),
        result=result,
    )


def process_tool_call(
    ctx: GatewayContext, raw: bytes, authorization: str | None, dpop: str | None, request_id: str
) -> tuple[int, ToolCallResponse]:
    """Decide, audit, and only then (if allowed) forward. Returns (HTTP status, body)."""
    trace = Trace()
    try:
        verdict = evaluate(ctx, raw, authorization, dpop, trace)
    except ApiError as err:
        record_denial(ctx, trace, err, request_id)
        raise
    except Exception:
        # A bug or surprise in any step must still DENY and still be on record (rule 10),
        # not escape as an unaudited 500. Details stay in the server log, never the reply.
        logger.exception("gateway pipeline error (request %s)", request_id)
        err = ApiError(500, ReasonCode.UPSTREAM_ERROR, "internal error")
        record_denial(ctx, trace, err, request_id)
        raise err from None

    pending = verdict.outcome is DecisionOutcome.PENDING
    reason = ReasonCode.PENDING_APPROVAL if pending else ReasonCode.OK
    # The decision must be on record BEFORE anything happens. If we cannot write the
    # audit record we do not act: an unrecorded action is worse than a refused one.
    try:
        record(ctx.cp, trace, verdict.outcome, reason, request_id)
    except ControlPlaneError:
        raise ApiError(502, ReasonCode.UPSTREAM_ERROR, "audit unavailable") from None
    if pending:
        return 202, decision_response(
            verdict.outcome, reason, request_id,
            approval_id=verdict.approval_id, risk_score=verdict.risk_score,
        )  # fmt: skip

    try:
        result = proxy.send(ctx.resources, ctx.settings, verdict.request)
    except ApiError as err:
        record_denial(ctx, trace, err, request_id)
        raise
    return 200, decision_response(
        verdict.outcome, reason, request_id, risk_score=verdict.risk_score, result=result
    )
