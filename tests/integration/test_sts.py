"""T2.3 token service + revocation. See conftest.py for factory/clock assumptions.

Extra assumptions: an expired/garbage/wrong-type/wrongly-signed identity token ->
401 STS_IDENTITY_INVALID; missing DPoP header -> 401 DPOP_MISSING; an expired access token on
/tasks/*/complete -> 401 TOKEN_EXPIRED; wrong task id -> 403 (any ErrorResponse);
introspect without the internal secret -> 401 UNAUTHORIZED; a completed task's token stays
listed in /admin/tokens with revoked=true.
"""

from __future__ import annotations

import pytest

from aimfa.common.crypto import generate_keypair, jwk_thumbprint, public_jwk, verify_jwt
from aimfa.common.models import AccessTokenClaims, ActiveTokenView, TokenResponse
from tests.integration.conftest import b64url_pubkey

READ = ["files:read:/expenses/*"]


def issue(h, scopes=READ, agent_id="expense-bot", role="expense_reader"):
    key, ident = h.onboard(agent_id, role)
    r = h.request_token(key, ident, scopes)
    assert r.status_code == 200, r.text
    return key, ident, TokenResponse.model_validate(r.json())


def introspect(h, access_token, agent_id="expense-bot", headers=None):
    jwks = h.cp.get("/.well-known/jwks.json").json()["keys"][0]
    jti = verify_jwt(
        access_token, b64url_pubkey(jwks), "aimfa-gateway", "aimfa-control-plane",
        token_use="access",
    )["jti"]  # fmt: skip
    return h.cp.post(
        "/internal/introspect",
        json={"jti": jti, "agent_id": agent_id},
        headers=h.internal if headers is None else headers,
    )


def err(resp, status, code):
    assert resp.status_code == status, resp.text
    assert resp.json()["reason_code"] == code


def test_token_scopes_subset_of_role_and_bound_to_agent_key(h):
    key, _, tr = issue(h)
    assert tr.scopes == READ and tr.token_type == "DPoP"
    assert tr.expires_in == h.settings.access_token_ttl_seconds
    jwks = h.cp.get("/.well-known/jwks.json").json()["keys"][0]
    claims = verify_jwt(
        tr.access_token, b64url_pubkey(jwks), "aimfa-gateway", "aimfa-control-plane",
        token_use="access",
    )  # fmt: skip
    parsed = AccessTokenClaims.model_validate(claims)
    assert parsed.cnf == {"jkt": jwk_thumbprint(public_jwk(key))}
    assert parsed.task_id == tr.task_id and parsed.sub == "expense-bot"
    assert parsed.scopes == READ and parsed.exp - parsed.iat == tr.expires_in


def test_each_token_gets_a_fresh_task_id_and_jti(h):
    key, ident, first = issue(h)
    second = TokenResponse.model_validate(h.request_token(key, ident, READ).json())
    assert first.task_id != second.task_id
    assert len(h.cp.get("/admin/tokens", headers=h.admin).json()) == 2


@pytest.mark.parametrize(
    "scopes",
    [
        ["bank:wire:*"],
        ["files:read:/engineering/*"],
        READ + ["email:send:external"],  # one good scope must not smuggle a bad one
        ["files:read:/expenses/../engineering/*"],
    ],
)
def test_scope_escalation_is_403(h, scopes):
    key, ident = h.onboard()
    r = h.request_token(key, ident, scopes)
    err(r, 403, "STS_SCOPE_ESCALATION")
    h.assert_audited("STS_SCOPE_ESCALATION")
    assert h.cp.get("/admin/tokens", headers=h.admin).json() == []


def test_access_token_presented_as_identity_token_is_rejected(h):
    key, _, tr = issue(h)
    err(h.request_token(key, tr.access_token, READ), 401, "STS_IDENTITY_INVALID")


@pytest.mark.parametrize("bad", ["", "garbage", "a.b.c"])
def test_garbage_identity_token_is_rejected(h, bad):
    key, _ = h.onboard()
    err(h.request_token(key, bad, READ), 401, "STS_IDENTITY_INVALID")


def test_identity_token_signed_by_attacker_is_rejected(h):
    from aimfa.common.crypto import sign_jwt

    key, _ = h.onboard()
    now = h.now()
    forged = sign_jwt(
        {
            "iss": "aimfa-control-plane", "sub": "expense-bot", "aud": "aimfa-sts",
            "iat": now, "exp": now + 600, "jti": "j" * 20, "token_use": "identity",
            "role": "expense_reader", "measurement": "0" * 64,
            "cnf": {"jwk": public_jwk(key).model_dump(mode="json")},
        },
        generate_keypair(),
    )  # fmt: skip
    err(h.request_token(key, forged, READ), 401, "STS_IDENTITY_INVALID")


def test_expired_identity_token_is_rejected(h):
    key, ident = h.onboard()
    h.clock.advance(h.settings.identity_token_ttl_seconds + 1)
    err(h.request_token(key, ident, READ), 401, "STS_IDENTITY_INVALID")


def test_stolen_identity_token_with_other_key_fails_dpop_key_mismatch(h):
    _, ident = h.onboard()
    thief = generate_keypair()
    err(h.request_token(thief, ident, READ), 401, "DPOP_KEY_MISMATCH")
    h.assert_audited("DPOP_KEY_MISMATCH")


def test_token_request_without_dpop_header_is_rejected(h):
    _, ident = h.onboard()
    body = {"identity_token": ident, "task_description": "t", "requested_scopes": READ}
    err(h.cp.post("/token", json=body), 401, "DPOP_MISSING")


def test_replayed_and_wrong_htu_proofs_are_rejected(h):
    key, ident = h.onboard()
    proof = h.proof(key, "POST", "/token")
    assert h.request_token(key, ident, READ, proof=proof).status_code == 200
    err(h.request_token(key, ident, READ, proof=proof), 401, "DPOP_REPLAY")
    wrong_htu = h.proof(key, "POST", "/tasks/x/complete")
    err(h.request_token(key, ident, READ, proof=wrong_htu), 401, "DPOP_HTU_MISMATCH")


def test_stale_proof_is_rejected(h):
    key, ident = h.onboard()
    old = h.proof(key, "POST", "/token", now=h.now() - 3600)
    err(h.request_token(key, ident, READ, proof=old), 401, "DPOP_STALE")


def test_quarantined_agent_gets_no_token(h):
    key, ident = h.onboard()
    h.quarantine("expense-bot")
    err(h.request_token(key, ident, READ), 403, "AGENT_QUARANTINED")


def test_unknown_request_fields_are_422(h):
    key, ident = h.onboard()
    body = {"identity_token": ident, "task_description": "t", "requested_scopes": READ, "role": "x"}
    r = h.cp.post("/token", json=body, headers={"DPoP": h.proof(key, "POST", "/token")})
    assert r.status_code == 422


def test_complete_task_revokes_token_and_introspect_reports_it(h):
    key, _, tr = issue(h)
    live = introspect(h, tr.access_token)
    assert live.status_code == 200 and live.json()["active"] is True

    path = f"/tasks/{tr.task_id}/complete"
    r = h.cp.post(path, headers=h.auth_headers(key, tr.access_token, "POST", path))
    assert r.status_code == 204

    dead = introspect(h, tr.access_token).json()
    assert dead["active"] is False and dead["reason_code"] == "TOKEN_REVOKED"
    raw = h.cp.get("/admin/tokens", headers=h.admin).json()
    views = [ActiveTokenView.model_validate(v) for v in raw]
    assert views[0].revoked is True


def test_completing_another_tasks_id_is_403_and_leaves_it_active(h):
    key, ident, task_a = issue(h)
    task_b = TokenResponse.model_validate(h.request_token(key, ident, READ).json())
    path = f"/tasks/{task_b.task_id}/complete"
    r = h.cp.post(path, headers=h.auth_headers(key, task_a.access_token, "POST", path))
    assert r.status_code == 403
    assert introspect(h, task_b.access_token).json()["active"] is True
    assert introspect(h, task_a.access_token).json()["active"] is True


def test_completing_another_agents_task_is_403(h):
    _, _, victim = issue(h, agent_id="expense-bot")
    key2, ident2 = h.onboard("eng-bot", "eng_assistant")
    mine = TokenResponse.model_validate(
        h.request_token(key2, ident2, ["files:read:/engineering/*"]).json()
    )
    path = f"/tasks/{victim.task_id}/complete"
    r = h.cp.post(path, headers=h.auth_headers(key2, mine.access_token, "POST", path))
    assert r.status_code == 403
    assert introspect(h, victim.access_token).json()["active"] is True


def test_complete_with_wrong_dpop_key_and_expired_token_are_401(h):
    key, _, tr = issue(h)
    path = f"/tasks/{tr.task_id}/complete"
    thief = generate_keypair()
    r = h.cp.post(path, headers=h.auth_headers(thief, tr.access_token, "POST", path))
    err(r, 401, "DPOP_KEY_MISMATCH")
    h.clock.advance(h.settings.access_token_ttl_seconds + 1)
    r = h.cp.post(path, headers=h.auth_headers(key, tr.access_token, "POST", path))
    err(r, 401, "TOKEN_EXPIRED")


def test_introspect_requires_internal_secret(h):
    _, _, tr = issue(h)
    for hdrs in ({}, {"X-Internal-Secret": "nope"}, {"X-Admin-Key": "test-admin-key"}):
        err(introspect(h, tr.access_token, headers=hdrs), 401, "UNAUTHORIZED")


def test_introspect_reports_quarantine_and_admin_revoke(h):
    _, _, tr = issue(h)
    h.quarantine("expense-bot")
    r = introspect(h, tr.access_token).json()
    assert r["active"] is False and r["reason_code"] == "AGENT_QUARANTINED"
    h.cp.post("/admin/agents/expense-bot/clear-quarantine", headers=h.admin)
    h.cp.post("/admin/agents/expense-bot/revoke", headers=h.admin)
    r = introspect(h, tr.access_token).json()
    assert r["active"] is False and r["reason_code"] == "TOKEN_REVOKED"


def test_admin_tokens_never_expose_the_token_string(h):
    _, _, tr = issue(h)
    r = h.cp.get("/admin/tokens", headers=h.admin)
    assert tr.access_token not in r.text
    assert "access_token" not in r.json()[0]
