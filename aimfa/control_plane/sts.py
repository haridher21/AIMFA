"""Token service / STS (factor 2, "what the agent HAS") and task completion (T2.3).

An agent trades its identity credential plus a DPoP proof for a short-lived, least-privilege
access token tied to ONE task and to the agent's key. A stolen token is useless without the
key, and a stolen identity credential is useless for the same reason.
"""

from __future__ import annotations

import secrets
from datetime import timedelta
from typing import Annotated

import jwt
from fastapi import APIRouter, Header, Path, Response
from pydantic import ValidationError

from aimfa.common.crypto import jwk_thumbprint, sign_jwt, verify_jwt
from aimfa.common.dpop import DPoPError, verify_proof
from aimfa.common.http import ApiError
from aimfa.common.models import (
    ACCESS_TOKEN_USE,
    GATEWAY_AUDIENCE,
    IDENTITY_TOKEN_USE,
    STS_AUDIENCE,
    TOKEN_ISSUER,
    AccessTokenClaims,
    ActiveTokenView,
    AgentRecord,
    AgentStatus,
    DecisionOutcome,
    IdentityCredentialClaims,
    PublicJWK,
    ReasonCode,
    TokenRequest,
    TokenResponse,
)
from aimfa.control_plane.state import CPState, clip

MAX_REQUESTED_SCOPES = 50


def verify_identity_token(state: CPState, token: str) -> IdentityCredentialClaims:
    """Accept only OUR identity credential: signature, iss, aud=aimfa-sts, token_use, exp.

    ``token_use="identity"`` is what stops an access token (or any other token we sign)
    from being presented here and accepted. Any problem at all is a denial.
    """
    try:
        claims = verify_jwt(
            token,
            state.signing_key.public_key(),
            STS_AUDIENCE,
            TOKEN_ISSUER,
            token_use=IDENTITY_TOKEN_USE,
            now=state.now_epoch(),
        )
        return IdentityCredentialClaims.model_validate(claims)
    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise ApiError(401, ReasonCode.STS_IDENTITY_INVALID, "identity token invalid") from None


def verify_access_token(state: CPState, token: str) -> AccessTokenClaims:
    """Accept only OUR access token: aud=aimfa-gateway, token_use=access, not expired."""
    try:
        claims = verify_jwt(
            token,
            state.signing_key.public_key(),
            GATEWAY_AUDIENCE,
            TOKEN_ISSUER,
            token_use=ACCESS_TOKEN_USE,
            now=state.now_epoch(),
        )
        return AccessTokenClaims.model_validate(claims)
    except jwt.ExpiredSignatureError:
        raise ApiError(401, ReasonCode.TOKEN_EXPIRED, "access token expired") from None
    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise ApiError(401, ReasonCode.TOKEN_INVALID, "access token invalid") from None


def check_dpop(
    state: CPState,
    proof: str | None,
    *,
    htu: str,
    expected_jkt: str,
    access_token: str | None = None,
    htm: str = "POST",
) -> PublicJWK:
    """Verify the DPoP proof against a REQUIRED key thumbprint.

    ``expected_jkt`` is mandatory here (a ``None`` would mean "skip the key check"). At
    ``/token`` it is the thumbprint of the identity credential's key; for an access token it
    is that token's ``cnf.jkt``. ``htm`` is the HTTP method the proof must name (POST for
    every route except the approval poll, which is a GET).
    """
    if not proof:
        raise ApiError(401, ReasonCode.DPOP_MISSING, "DPoP proof required")
    try:
        return verify_proof(
            proof,
            htm=htm,
            htu=htu,
            expected_jkt=expected_jkt,
            access_token=access_token,
            replay_cache=state.replay,
            max_age=state.settings.dpop_max_age_seconds,
            now=state.now_epoch(),
        )
    except DPoPError as err:
        raise ApiError(401, err.reason_code, "DPoP proof rejected") from None


def parse_dpop_authorization(header: str | None) -> str:
    """Extract the token from ``Authorization: DPoP <token>``."""
    if not header:
        raise ApiError(401, ReasonCode.TOKEN_MISSING, "Authorization header required")
    scheme, _, token = header.partition(" ")
    if scheme != "DPoP" or not token.strip() or " " in token.strip():
        raise ApiError(401, ReasonCode.TOKEN_INVALID, "expected 'Authorization: DPoP <token>'")
    return token.strip()


def issue_access_token(
    state: CPState, agent: AgentRecord, scopes: list[str], jkt: str
) -> TokenResponse:
    """Mint a token for a NEW task, bind it to the agent key, and record its jti."""
    now = state.now()
    iat = int(now.timestamp())
    ttl = state.settings.access_token_ttl_seconds
    task_id = f"task-{secrets.token_urlsafe(12)}"
    claims = AccessTokenClaims(
        iss=TOKEN_ISSUER,
        sub=agent.agent_id,
        aud=GATEWAY_AUDIENCE,
        iat=iat,
        exp=iat + ttl,
        jti=secrets.token_urlsafe(16),
        token_use=ACCESS_TOKEN_USE,
        task_id=task_id,
        role=agent.role,
        scopes=scopes,
        cnf={"jkt": jkt},
    )
    state.db.add_token(
        ActiveTokenView(
            jti=claims.jti,
            agent_id=agent.agent_id,
            task_id=task_id,
            scopes=scopes,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl),
            revoked=False,
        )
    )
    token = sign_jwt(claims.model_dump(mode="json"), state.signing_key)
    return TokenResponse(access_token=token, expires_in=ttl, task_id=task_id, scopes=scopes)


def make_router(state: CPState) -> APIRouter:
    router = APIRouter()
    base = state.settings.control_plane_url

    def deny(err: ApiError, actor: str, event: str, **details: object) -> ApiError:
        state.audit(actor, event, DecisionOutcome.DENY, err.reason_code, **details)
        return err

    @router.post("/token")
    def token(req: TokenRequest, dpop: Annotated[str | None, Header()] = None) -> TokenResponse:
        # 1. Identity credential: ours, right type, unexpired.
        try:
            identity = verify_identity_token(state, req.identity_token)
        except ApiError as err:
            raise deny(err, "unknown", "sts.token_denied") from None
        agent = state.db.get_agent(identity.sub)
        if agent is None:
            raise deny(
                ApiError(401, ReasonCode.STS_IDENTITY_INVALID, "unknown agent"),
                "unknown", "sts.token_denied",
            )  # fmt: skip

        not_before = state.db.get_identity_not_before(agent.agent_id)
        if not_before is not None and identity.iat < not_before:
            # Issued before an admin revoked this agent: the kill switch must stick.
            raise deny(
                ApiError(401, ReasonCode.STS_IDENTITY_INVALID, "identity was revoked"),
                agent.agent_id,
                "sts.token_denied",
            )

        # 2. Proof of possession: the request must be signed by the key the identity
        #    credential names, so a stolen credential alone is useless.
        try:
            holder = PublicJWK.model_validate(identity.cnf.get("jwk"))
            check_dpop(state, dpop, htu=f"{base}/token", expected_jkt=jwk_thumbprint(holder))
        except (ValidationError, ValueError):
            raise deny(
                ApiError(401, ReasonCode.STS_IDENTITY_INVALID, "identity key invalid"),
                agent.agent_id, "sts.token_denied",
            ) from None  # fmt: skip
        except ApiError as err:
            raise deny(err, agent.agent_id, "sts.token_denied") from None

        # 3. Quarantine and least privilege.
        if agent.status is AgentStatus.QUARANTINED:
            raise deny(
                ApiError(403, ReasonCode.AGENT_QUARANTINED, "agent is quarantined"),
                agent.agent_id, "sts.token_denied",
            )  # fmt: skip
        scopes = list(dict.fromkeys(req.requested_scopes))
        if len(scopes) > MAX_REQUESTED_SCOPES or not state.policy.role_permits(agent.role, scopes):
            raise deny(
                ApiError(403, ReasonCode.STS_SCOPE_ESCALATION, "scopes exceed the agent's role"),
                agent.agent_id, "sts.token_denied",
                requested=[clip(s) for s in scopes[:10]],
            )  # fmt: skip

        response = issue_access_token(state, agent, scopes, jwk_thumbprint(holder))
        state.audit(
            agent.agent_id, "sts.token_issued", DecisionOutcome.ALLOW,
            task_id=response.task_id, scopes=scopes,
        )  # fmt: skip
        return response

    @router.post("/tasks/{task_id}/complete", status_code=204)
    def complete_task(
        task_id: Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,64}$")],
        authorization: Annotated[str | None, Header()] = None,
        dpop: Annotated[str | None, Header()] = None,
    ) -> Response:
        actor = "unknown"
        try:
            access_token = parse_dpop_authorization(authorization)
            claims = verify_access_token(state, access_token)
            actor = claims.sub
            # The proof must be signed by the key this token is bound to AND cover this
            # exact token (ath), so neither a stolen token nor a stolen proof works alone.
            check_dpop(
                state, dpop,
                htu=f"{base}/tasks/{task_id}/complete",
                expected_jkt=claims.cnf.get("jkt", ""),
                access_token=access_token,
            )  # fmt: skip
            stored = state.db.get_token(claims.jti)
            if stored is None or stored.revoked or stored.agent_id != claims.sub:
                raise ApiError(401, ReasonCode.TOKEN_REVOKED, "token revoked")
            if task_id != claims.task_id:
                # Authenticated, but may only close its OWN task.
                raise ApiError(403, ReasonCode.SCOPE_DENIED, "token is not for this task")
        except ApiError as err:
            raise deny(err, actor, "sts.task_complete_denied", task_id=task_id) from None
        state.db.revoke_task_tokens(claims.sub, claims.task_id)
        state.audit(actor, "sts.task_completed", DecisionOutcome.ALLOW, task_id=task_id)
        return Response(status_code=204)

    return router
