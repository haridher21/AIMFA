"""AIMFA shared contracts.

THIS FILE IS FROZEN after team sign-off (ROADMAP T0.3). Every service, agent, test and
attack script imports its request/response shapes from here. Agents implementing a task
must NOT change this file; propose a "contract-change" PR instead (see AGENTS.md).

Human-readable companion: docs/CONTRACTS.md (endpoints, headers, status codes).

Naming conventions
------------------
* ``agent_id``    -- registered, stable name of an agent, e.g. ``expense-bot``.
* ``task_id``     -- id of one task an agent is doing; every access token is bound to one.
* ``measurement`` -- lowercase hex SHA-256 "fingerprint" of the agent (code + system
                     prompt + tool manifest + model id).
* ``jkt``         -- RFC 7638 JWK thumbprint (base64url, no padding) of the agent's
                     public key; binds an access token to that key (DPoP, RFC 9449).
* Scope strings   -- ``"<service>:<verb>:<target>"``, e.g. ``files:read:/expenses/*``,
                     ``email:send:internal``, ``bank:wire:*``. See policy/roles.yaml.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# --------------------------------------------------------------------------------------
# Shared field patterns
# --------------------------------------------------------------------------------------

AGENT_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$"
PRINCIPAL_ID_PATTERN = r"^[a-z0-9][a-z0-9_-]{1,62}[a-z0-9]$"
SHA256_HEX_PATTERN = r"^[0-9a-f]{64}$"
TOTP_PATTERN = r"^[0-9]{6}$"

# Literal values used inside tokens to prevent token-type confusion
# (an identity token must never be accepted where an access token is expected).
IDENTITY_TOKEN_USE = "identity"
ACCESS_TOKEN_USE = "access"
STS_AUDIENCE = "aimfa-sts"
GATEWAY_AUDIENCE = "aimfa-gateway"
TOKEN_ISSUER = "aimfa-control-plane"
SIGNING_ALG = "EdDSA"


class _Model(BaseModel):
    """Base model: reject unknown fields so typos and smuggled fields fail loudly."""

    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------------------
# Enums
# --------------------------------------------------------------------------------------


class Mode(StrEnum):
    AIMFA = "aimfa"
    BASELINE = "baseline"


class Tier(StrEnum):
    """Risk tier of an action (policy/actions.yaml)."""

    LOW = "low"  # allow
    MEDIUM = "medium"  # allow, extra monitor weight
    HIGH = "high"  # human step-up required
    FORBIDDEN = "forbidden"  # always deny


class AgentStatus(StrEnum):
    REGISTERED = "registered"  # known, never attested (or identity expired)
    ACTIVE = "active"  # holds a valid identity credential
    QUARANTINED = "quarantined"  # risk too high; all tokens revoked; admin must clear


class DecisionOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    PENDING = "pending"  # waiting for human approval


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    USED = "used"  # approved and already consumed by exactly one tool call


class ApprovalReason(StrEnum):
    HIGH_TIER = "high_tier"  # the action itself is high risk
    RISK_STEP_UP = "risk_step_up"  # agent's risk score is elevated


class ReasonCode(StrEnum):
    """Machine-readable reason attached to every decision and audit record.

    Tests and attack scripts assert on these, so each failure mode has its own code.
    """

    OK = "OK"
    PENDING_APPROVAL = "PENDING_APPROVAL"

    # Access token problems (gateway, HTTP 401)
    TOKEN_MISSING = "TOKEN_MISSING"
    TOKEN_INVALID = "TOKEN_INVALID"  # bad signature / alg / audience / token_use / malformed
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_REVOKED = "TOKEN_REVOKED"

    # DPoP proof problems (gateway + STS, HTTP 401)
    DPOP_MISSING = "DPOP_MISSING"
    DPOP_MALFORMED = "DPOP_MALFORMED"  # not a JWT, wrong typ/alg, missing claims
    DPOP_BAD_SIGNATURE = "DPOP_BAD_SIGNATURE"
    DPOP_KEY_MISMATCH = "DPOP_KEY_MISMATCH"  # proof key thumbprint != token cnf.jkt
    DPOP_HTM_MISMATCH = "DPOP_HTM_MISMATCH"
    DPOP_HTU_MISMATCH = "DPOP_HTU_MISMATCH"
    DPOP_STALE = "DPOP_STALE"  # iat outside the allowed window
    DPOP_REPLAY = "DPOP_REPLAY"  # jti already seen
    DPOP_ATH_MISMATCH = "DPOP_ATH_MISMATCH"  # proof not bound to this access token

    # Authorization (gateway, HTTP 403)
    SCOPE_DENIED = "SCOPE_DENIED"
    ACTION_FORBIDDEN = "ACTION_FORBIDDEN"  # unknown tool or forbidden tier
    INVALID_ARGUMENTS = "INVALID_ARGUMENTS"  # e.g. path traversal, missing arg
    AGENT_QUARANTINED = "AGENT_QUARANTINED"
    RATE_LIMITED = "RATE_LIMITED"

    # Human step-up
    APPROVAL_DENIED = "APPROVAL_DENIED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_MISMATCH = "APPROVAL_MISMATCH"  # approval was for a different action
    APPROVAL_ALREADY_USED = "APPROVAL_ALREADY_USED"
    APPROVAL_NOT_FOUND = "APPROVAL_NOT_FOUND"
    APPROVAL_STILL_PENDING = "APPROVAL_STILL_PENDING"
    APPROVAL_INVALID_TOTP = "APPROVAL_INVALID_TOTP"

    # Attestation (control plane)
    ATTEST_UNKNOWN_AGENT = "ATTEST_UNKNOWN_AGENT"
    ATTEST_UNKNOWN_LAUNCHER = "ATTEST_UNKNOWN_LAUNCHER"
    ATTEST_BAD_SIGNATURE = "ATTEST_BAD_SIGNATURE"
    ATTEST_NONCE_INVALID = "ATTEST_NONCE_INVALID"  # unknown, reused, or expired nonce
    ATTEST_MEASUREMENT_MISMATCH = "ATTEST_MEASUREMENT_MISMATCH"

    # Token service (control plane)
    STS_IDENTITY_INVALID = "STS_IDENTITY_INVALID"
    STS_SCOPE_ESCALATION = "STS_SCOPE_ESCALATION"

    # Misc
    BASELINE_API_KEY_INVALID = "BASELINE_API_KEY_INVALID"
    AUDIT_CHAIN_BROKEN = "AUDIT_CHAIN_BROKEN"
    UNAUTHORIZED = "UNAUTHORIZED"  # bad admin/internal secret
    UPSTREAM_ERROR = "UPSTREAM_ERROR"


class EventType(StrEnum):
    """Events the gateway reports to the behavioral monitor (RiskEvent.event_type)."""

    TOOL_ALLOWED = "tool_allowed"
    TOOL_PENDING = "tool_pending"
    SCOPE_DENIED = "scope_denied"
    ACTION_FORBIDDEN = "action_forbidden"
    OUT_OF_PROFILE = "out_of_profile"  # resource category not normal for the role
    SENSITIVE_READ = "sensitive_read"
    EXTERNAL_EGRESS = "external_egress"  # e.g. email to an outside domain
    TOKEN_FAILURE = "token_failure"
    DPOP_FAILURE = "dpop_failure"
    APPROVAL_DENIED = "approval_denied"
    RATE_EXCEEDED = "rate_exceeded"


# --------------------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------------------


class PublicJWK(_Model):
    """Ed25519 public key in JWK form (RFC 8037). Private keys never appear in contracts."""

    kty: Literal["OKP"] = "OKP"
    crv: Literal["Ed25519"] = "Ed25519"
    x: str = Field(min_length=43, max_length=43, description="base64url public key, no padding")
    kid: str | None = None


class JWKS(_Model):
    keys: list[PublicJWK]


# --------------------------------------------------------------------------------------
# Registry (admin API)
# --------------------------------------------------------------------------------------


class LauncherRegistration(_Model):
    """A trusted launcher: the root of trust that measures agents before they start."""

    launcher_id: str = Field(pattern=PRINCIPAL_ID_PATTERN)
    public_jwk: PublicJWK


class AgentRegistration(_Model):
    agent_id: str = Field(pattern=AGENT_ID_PATTERN)
    role: str = Field(description="Key in policy/roles.yaml")
    golden_measurement: str = Field(pattern=SHA256_HEX_PATTERN)
    launcher_id: str = Field(pattern=PRINCIPAL_ID_PATTERN)
    approver_id: str = Field(pattern=PRINCIPAL_ID_PATTERN)
    description: str = ""


class AgentRecord(AgentRegistration):
    status: AgentStatus = AgentStatus.REGISTERED
    created_at: datetime
    quarantined_at: datetime | None = None


class ApproverEnrollmentRequest(_Model):
    approver_id: str = Field(pattern=PRINCIPAL_ID_PATTERN)
    display_name: str = ""


class ApproverEnrollment(_Model):
    """Returned ONCE at enrollment. The otpauth URI contains the TOTP secret: show it as a
    QR code to the human, then discard it. It is never retrievable again."""

    approver_id: str
    provisioning_uri: str


# --------------------------------------------------------------------------------------
# Attestation (factor 1: what the agent IS)
# --------------------------------------------------------------------------------------


class AttestationChallengeRequest(_Model):
    agent_id: str = Field(pattern=AGENT_ID_PATTERN)


class AttestationChallenge(_Model):
    nonce: str = Field(min_length=16)
    expires_at: datetime


class AttestationEvidence(_Model):
    """Payload the launcher signs (as a compact JWS, EdDSA) and submits for attestation."""

    agent_id: str = Field(pattern=AGENT_ID_PATTERN)
    launcher_id: str = Field(pattern=PRINCIPAL_ID_PATTERN)
    nonce: str = Field(min_length=16)
    measurement: str = Field(pattern=SHA256_HEX_PATTERN)
    agent_public_jwk: PublicJWK = Field(description="Fresh per-instance key of the agent")
    iat: int = Field(description="Unix seconds")


class AttestationRequest(_Model):
    evidence_jws: str = Field(description="AttestationEvidence signed by the launcher key")


class IdentityCredentialClaims(_Model):
    """Claims of the identity credential (JWT, EdDSA, signed by the control plane)."""

    iss: Literal["aimfa-control-plane"] = TOKEN_ISSUER
    sub: str = Field(description="agent_id")
    aud: Literal["aimfa-sts"] = STS_AUDIENCE
    iat: int
    exp: int
    jti: str
    token_use: Literal["identity"] = IDENTITY_TOKEN_USE
    role: str
    measurement: str = Field(pattern=SHA256_HEX_PATTERN)
    cnf: dict[str, Any] = Field(description='{"jwk": <agent PublicJWK>}')


class IdentityCredentialResponse(_Model):
    identity_token: str
    expires_at: datetime


# --------------------------------------------------------------------------------------
# Token service (factor 2: what the agent HAS) -- least privilege, short-lived, key-bound
# --------------------------------------------------------------------------------------


class TokenRequest(_Model):
    """POST /token body. The request MUST also carry a `DPoP` header proof signed by the
    same key that is in the identity credential's cnf.jwk."""

    identity_token: str
    task_description: str = Field(min_length=1, max_length=500)
    requested_scopes: list[str] = Field(min_length=1)


class TokenResponse(_Model):
    access_token: str
    token_type: Literal["DPoP"] = "DPoP"
    expires_in: int
    task_id: str
    scopes: list[str]


class AccessTokenClaims(_Model):
    iss: Literal["aimfa-control-plane"] = TOKEN_ISSUER
    sub: str = Field(description="agent_id")
    aud: Literal["aimfa-gateway"] = GATEWAY_AUDIENCE
    iat: int
    exp: int
    jti: str
    token_use: Literal["access"] = ACCESS_TOKEN_USE
    task_id: str
    role: str
    scopes: list[str]
    cnf: dict[str, str] = Field(description='{"jkt": <RFC 7638 thumbprint of agent key>}')


class DPoPProofClaims(_Model):
    """Claims of a DPoP proof JWT (header: typ=dpop+jwt, alg=EdDSA, jwk=<agent PublicJWK>)."""

    jti: str = Field(min_length=16)
    htm: str = Field(description="HTTP method, e.g. POST")
    htu: str = Field(description="Full target URL without query/fragment")
    iat: int
    ath: str | None = Field(
        default=None,
        description="base64url(SHA-256(access_token)); REQUIRED when presenting an access token",
    )


# --------------------------------------------------------------------------------------
# Gateway (every tool call)
# --------------------------------------------------------------------------------------


class ToolCall(_Model):
    """POST /tool body. task_id is taken from the access token, never from the body."""

    tool: str = Field(description="Key in policy/actions.yaml")
    args: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = Field(
        default=None, description="Set when retrying an action a human has approved"
    )


class Decision(_Model):
    outcome: DecisionOutcome
    reason_code: ReasonCode
    message: str = ""
    request_id: str
    approval_id: str | None = None
    risk_score: float | None = None


class ToolCallResponse(_Model):
    decision: Decision
    result: dict[str, Any] | None = None


# --------------------------------------------------------------------------------------
# Human step-up (factor 4)
# --------------------------------------------------------------------------------------


class ApprovalCreate(_Model):
    """Internal: gateway -> control plane when an action needs a human."""

    agent_id: str
    task_id: str
    tool: str
    args: dict[str, Any]
    action_hash: str = Field(
        pattern=SHA256_HEX_PATTERN,
        description="sha256 of canonical JSON {agent_id, task_id, tool, args}",
    )
    reason: ApprovalReason
    risk_score: float = 0.0


class ApprovalRecord(ApprovalCreate):
    approval_id: str
    approver_id: str
    status: ApprovalStatus
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None = None


class ApprovalStatusView(_Model):
    """What an agent may see while polling: status only, no args/approver details."""

    approval_id: str
    status: ApprovalStatus


class ApprovalDecisionRequest(_Model):
    """POST /approvals/{id}/decide. The human proves presence with their TOTP code."""

    approver_id: str = Field(pattern=PRINCIPAL_ID_PATTERN)
    approve: bool
    totp_code: str = Field(pattern=TOTP_PATTERN)


class ApprovalConsumeRequest(_Model):
    """Internal: gateway asks to consume an approval for exactly this action."""

    action_hash: str = Field(pattern=SHA256_HEX_PATTERN)


# --------------------------------------------------------------------------------------
# Behavioral monitor (factor 3: what the agent DOES)
# --------------------------------------------------------------------------------------


class RiskEvent(_Model):
    agent_id: str
    task_id: str | None = None
    event_type: EventType
    tool: str | None = None
    target: str | None = None
    timestamp: datetime
    details: dict[str, Any] = Field(default_factory=dict)


class RiskContribution(_Model):
    rule: str
    points: float
    at: datetime


class RiskScore(_Model):
    agent_id: str
    score: float
    status: AgentStatus
    step_up_required: bool
    recent: list[RiskContribution] = Field(default_factory=list)


# --------------------------------------------------------------------------------------
# Revocation / introspection (internal: gateway -> control plane)
# --------------------------------------------------------------------------------------


class IntrospectRequest(_Model):
    jti: str
    agent_id: str


class IntrospectResponse(_Model):
    active: bool
    reason_code: ReasonCode = ReasonCode.OK
    agent_status: AgentStatus | None = None


class ActiveTokenView(_Model):
    """Admin/dashboard view of an issued access token (never the token itself)."""

    jti: str
    agent_id: str
    task_id: str
    scopes: list[str]
    issued_at: datetime
    expires_at: datetime
    revoked: bool


# --------------------------------------------------------------------------------------
# Audit log (tamper-evident hash chain)
# --------------------------------------------------------------------------------------


class AuditAppend(_Model):
    """What a component submits; seq/timestamps/hashes are assigned by the audit log."""

    component: Literal["control_plane", "gateway", "resources", "launcher", "dashboard"]
    actor: str = Field(description='agent_id, "admin", "approver:<id>" or "system"')
    event: str = Field(description='short dotted name, e.g. "gateway.tool_call"')
    outcome: DecisionOutcome | Literal["info"]
    reason_code: ReasonCode = ReasonCode.OK
    details: dict[str, Any] = Field(default_factory=dict)


class AuditRecord(AuditAppend):
    seq: int = Field(ge=0)
    timestamp: datetime
    prev_hash: str = Field(pattern=SHA256_HEX_PATTERN)
    hash: str = Field(pattern=SHA256_HEX_PATTERN)


class AuditVerifyResult(_Model):
    ok: bool
    records_checked: int
    first_bad_seq: int | None = None
    reason_code: ReasonCode = ReasonCode.OK


# --------------------------------------------------------------------------------------
# Errors (every non-2xx JSON body from any AIMFA service)
# --------------------------------------------------------------------------------------


class ErrorResponse(_Model):
    reason_code: ReasonCode
    message: str = ""
    request_id: str | None = None
