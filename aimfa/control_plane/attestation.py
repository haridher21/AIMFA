"""Attestation (factor 1, "what the agent IS"): challenge, evidence check, identity token (T2.2).

Flow: the agent's trusted launcher asks for a one-time nonce, measures the agent (hash of
code + prompt + tools + model), and signs that measurement plus the nonce plus the agent's
fresh public key. We accept only if every check below passes, and then issue a short-lived
identity credential bound to that agent key.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import secrets
from datetime import timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter

from aimfa.common.crypto import public_jwk, sign_jwt
from aimfa.common.http import ApiError
from aimfa.common.models import (
    IDENTITY_TOKEN_USE,
    JWKS,
    SIGNING_ALG,
    STS_AUDIENCE,
    TOKEN_ISSUER,
    AgentRecord,
    AgentStatus,
    AttestationChallenge,
    AttestationChallengeRequest,
    AttestationEvidence,
    AttestationRequest,
    DecisionOutcome,
    IdentityCredentialClaims,
    IdentityCredentialResponse,
    ReasonCode,
)
from aimfa.control_plane.state import CPState, clip, public_key_from_jwk

NONCE_BYTES = 32
MAX_LIVE_NONCES_PER_AGENT = 5


def _fail(status: int, code: ReasonCode, message: str) -> ApiError:
    return ApiError(status, code, message)


def peek_payload(jws: str) -> dict[str, Any] | None:
    """Read the (UNVERIFIED) payload only to learn which agent/launcher it names.

    We need those names to look up the launcher's registered key, which is then used to
    verify the signature. Nothing read here is trusted: ``verify_evidence`` re-parses the
    payload after the signature checks out, and only those values are used afterwards.
    """
    try:
        parts = jws.split(".")
        if len(parts) != 3:
            return None
        segment = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(segment))
    except (ValueError, binascii.Error):
        return None
    return payload if isinstance(payload, dict) else None


def verify_evidence(jws: str, launcher_key: Ed25519PublicKey) -> AttestationEvidence:
    """Check the launcher's signature and parse the evidence. Raises ATTEST_BAD_SIGNATURE.

    The algorithm is pinned to EdDSA (no ``alg=none`` or HMAC tricks) and the key is the
    one WE registered for the launcher, never a key supplied inside the evidence. The
    evidence has no ``exp``: its freshness comes from the single-use nonce instead.
    """
    bad = _fail(401, ReasonCode.ATTEST_BAD_SIGNATURE, "evidence signature invalid")
    try:
        header = jwt.get_unverified_header(jws)
        if header.get("alg") != SIGNING_ALG or "crit" in header or "b64" in header:
            raise bad
        payload = jwt.decode(
            jws,
            launcher_key,
            algorithms=[SIGNING_ALG],
            options={
                "verify_signature": True,
                "verify_exp": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
                "require": [],
            },
        )
        return AttestationEvidence.model_validate(payload)
    except (jwt.InvalidTokenError, ValueError):
        raise bad from None


def measurement_matches(claimed: str, golden: str) -> bool:
    """Constant-time compare, so response timing cannot reveal the golden hash."""
    return hmac.compare_digest(
        claimed.encode("ascii", "replace"), golden.encode("ascii", "replace")
    )


def verify_attestation(state: CPState, jws: str) -> tuple[AgentRecord, AttestationEvidence]:
    """Run the contract's six checks in order; raise ``ApiError`` on the first failure."""
    db = state.db
    claimed = peek_payload(jws)
    if claimed is None:
        raise _fail(401, ReasonCode.ATTEST_BAD_SIGNATURE, "evidence is not a signed token")
    agent_id, launcher_id = claimed.get("agent_id"), claimed.get("launcher_id")
    if not isinstance(agent_id, str) or not isinstance(launcher_id, str):
        raise _fail(401, ReasonCode.ATTEST_BAD_SIGNATURE, "evidence is malformed")

    # 1. The agent must have been registered by an admin.
    agent = db.get_agent(agent_id)
    if agent is None:
        raise _fail(404, ReasonCode.ATTEST_UNKNOWN_AGENT, "unknown agent")

    # 2. The launcher must exist AND be the one assigned to this agent, so a launcher
    #    that was trusted for another agent cannot vouch for this one.
    launcher = db.get_launcher(launcher_id)
    if launcher is None or launcher_id != agent.launcher_id:
        raise _fail(401, ReasonCode.ATTEST_UNKNOWN_LAUNCHER, "launcher not trusted for this agent")

    # 3. Signature under the launcher's REGISTERED key.
    evidence = verify_evidence(jws, public_key_from_jwk(launcher.public_jwk))
    if evidence.agent_id != agent_id or evidence.launcher_id != launcher_id:
        raise _fail(401, ReasonCode.ATTEST_BAD_SIGNATURE, "evidence changed after lookup")

    # A malformed agent key must be refused BEFORE the nonce is spent or state changes.
    try:
        public_key_from_jwk(evidence.agent_public_jwk)
    except ValueError:
        raise _fail(422, ReasonCode.INVALID_ARGUMENTS, "agent public key invalid") from None

    # 4. Fresh, single-use nonce issued to THIS agent. One atomic UPDATE: a replay or a
    #    nonce issued to someone else changes nothing and fails.
    if not db.consume_nonce(evidence.nonce, agent_id, now=state.now()):
        raise _fail(401, ReasonCode.ATTEST_NONCE_INVALID, "nonce unknown, used, expired or foreign")

    # 5. The agent is running exactly the code/prompt/tools/model that was registered.
    if not measurement_matches(evidence.measurement, agent.golden_measurement):
        raise _fail(401, ReasonCode.ATTEST_MEASUREMENT_MISMATCH, "measurement mismatch")

    # 6. A quarantined agent stays out until an admin clears it.
    if agent.status is AgentStatus.QUARANTINED:
        raise _fail(403, ReasonCode.AGENT_QUARANTINED, "agent is quarantined")
    return agent, evidence


def issue_identity_token(
    state: CPState, agent: AgentRecord, evidence: AttestationEvidence
) -> IdentityCredentialResponse:
    """Sign the identity credential, bound to the agent key via ``cnf.jwk``."""
    now = state.now()
    iat = int(now.timestamp())
    # After a kill switch, a new identity must be dated AFTER the cutoff (see revoke_agent).
    not_before = state.db.get_identity_not_before(agent.agent_id)
    if not_before is not None:
        iat = max(iat, not_before)
    ttl = state.settings.identity_token_ttl_seconds
    claims = IdentityCredentialClaims(
        iss=TOKEN_ISSUER,
        sub=agent.agent_id,
        aud=STS_AUDIENCE,
        iat=iat,
        exp=iat + ttl,
        jti=secrets.token_urlsafe(16),
        token_use=IDENTITY_TOKEN_USE,
        role=agent.role,  # from OUR registry, not from the evidence
        measurement=agent.golden_measurement,
        cnf={"jwk": evidence.agent_public_jwk.model_dump(mode="json", exclude_none=True)},
    )
    token = sign_jwt(claims.model_dump(mode="json"), state.signing_key)
    return IdentityCredentialResponse(identity_token=token, expires_at=now + timedelta(seconds=ttl))


def make_router(state: CPState) -> APIRouter:
    router = APIRouter()

    @router.get("/.well-known/jwks.json")
    def jwks() -> JWKS:
        """Public verification key (safe to publish; the private key never leaves keys/)."""
        return JWKS(keys=[public_jwk(state.signing_key)])

    @router.post("/attest/challenge")
    def challenge(req: AttestationChallengeRequest) -> AttestationChallenge:
        if state.db.get_agent(req.agent_id) is None:
            raise state.deny(
                404, ReasonCode.ATTEST_UNKNOWN_AGENT, "unknown agent",
                actor="unknown", event="attest.challenge", agent_id=req.agent_id,
            )  # fmt: skip
        now = state.now()
        # Housekeeping + cap, so unauthenticated callers cannot grow the nonce table forever.
        state.db.delete_expired_nonces(now=now)
        if state.db.count_live_nonces(req.agent_id, now=now) >= MAX_LIVE_NONCES_PER_AGENT:
            raise state.deny(
                429, ReasonCode.RATE_LIMITED, "too many outstanding challenges",
                actor="unknown", event="attest.challenge", agent_id=req.agent_id,
            )  # fmt: skip
        expires_at = now + timedelta(seconds=state.settings.attest_nonce_ttl_seconds)
        nonce = secrets.token_urlsafe(NONCE_BYTES)
        state.db.add_nonce(nonce, req.agent_id, expires_at=expires_at)
        return AttestationChallenge(nonce=nonce, expires_at=expires_at)

    @router.post("/attest")
    def attest(req: AttestationRequest) -> IdentityCredentialResponse:
        try:
            agent, evidence = verify_attestation(state, req.evidence_jws)
        except ApiError as err:
            claimed = peek_payload(req.evidence_jws) or {}
            state.audit(
                "unknown", "attest.denied", DecisionOutcome.DENY, err.reason_code,
                claimed_agent_id=clip(claimed.get("agent_id")),
                claimed_launcher_id=clip(claimed.get("launcher_id")),
            )  # fmt: skip
            raise
        # Atomic: refuses if the agent was quarantined after the check above.
        if not state.db.activate_agent(agent.agent_id):
            state.audit(
                "unknown", "attest.denied", DecisionOutcome.DENY, ReasonCode.AGENT_QUARANTINED,
                agent_id=agent.agent_id,
            )  # fmt: skip
            raise ApiError(403, ReasonCode.AGENT_QUARANTINED, "agent is quarantined")
        response = issue_identity_token(state, agent, evidence)
        state.audit(
            agent.agent_id, "attest.ok", DecisionOutcome.ALLOW, launcher_id=evidence.launcher_id
        )
        return response

    return router
