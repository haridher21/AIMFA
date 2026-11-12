"""Regression tests for the Phase 2 security-review fixes."""

from __future__ import annotations

import jwt
import pytest
from pydantic import SecretStr

from aimfa.common.config import Settings
from aimfa.common.crypto import generate_keypair, public_jwk, sign_jwt, verify_jwt
from aimfa.common.db import Database
from aimfa.common.http import require_strong_secrets
from tests.integration.conftest import GOLDEN

READ = ["files:read:/expenses/*"]


def test_revoke_kills_old_identity_but_reattest_works(h):
    key, ident = h.onboard()
    assert h.request_token(key, ident, READ).status_code == 200
    assert h.cp.post("/admin/agents/expense-bot/revoke", headers=h.admin).status_code == 204

    r = h.request_token(key, ident, READ)
    assert r.status_code == 401 and r.json()["reason_code"] == "STS_IDENTITY_INVALID"
    h.assert_audited("STS_IDENTITY_INVALID")

    new_key = generate_keypair()
    assert h.attest(agent_key=new_key).status_code == 200
    fresh = h.attest(agent_key=new_key)  # unused nonce path: just ensure a second attest works
    assert fresh.status_code == 200
    assert h.request_token(new_key, fresh.json()["identity_token"], READ).status_code == 200


def test_revoke_does_not_unquarantine(h):
    h.add_agent()
    h.quarantine("expense-bot")
    h.cp.post("/admin/agents/expense-bot/revoke", headers=h.admin)
    assert h.cp.get("/admin/agents", headers=h.admin).json()[0]["status"] == "quarantined"


@pytest.mark.parametrize(
    "field", ["admin_api_key", "internal_service_secret", "gateway_resource_secret"]
)
def test_default_or_short_secrets_refuse_startup(settings, field):
    from aimfa.control_plane.app import create_app as cp_app
    from aimfa.resources.app import create_app as res_app

    require_strong_secrets(settings)  # the test settings are fine
    bad = settings.model_copy(update={field: SecretStr("change-me-xyz")})
    with pytest.raises(ValueError):
        require_strong_secrets(bad)
    for factory in (cp_app, res_app):
        with pytest.raises(ValueError):
            factory(bad)
    assert isinstance(Settings(_env_file=None), Settings)  # defaults still constructible


def test_challenges_are_capped_and_expired_nonces_purged(h):
    h.add_agent()
    for _ in range(5):
        assert h.cp.post("/attest/challenge", json={"agent_id": "expense-bot"}).status_code == 200
    r = h.cp.post("/attest/challenge", json={"agent_id": "expense-bot"})
    assert r.status_code == 429 and r.json()["reason_code"] == "RATE_LIMITED"
    h.clock.advance(h.settings.attest_nonce_ttl_seconds + 1)
    assert h.cp.post("/attest/challenge", json={"agent_id": "expense-bot"}).status_code == 200


def test_verify_jwt_with_now_rejects_future_iat():
    key = generate_keypair()
    claims = {"iss": "i", "aud": "a", "exp": 2000, "iat": 1000, "token_use": "access"}
    pub = key.public_key()
    assert verify_jwt(sign_jwt(claims, key), pub, "a", "i", now=1000)["iat"] == 1000
    assert verify_jwt(sign_jwt({**claims, "iat": 1020}, key), pub, "a", "i", now=1000)
    with pytest.raises(jwt.InvalidTokenError):
        verify_jwt(sign_jwt({**claims, "iat": 1100}, key), pub, "a", "i", now=1000)


def test_malformed_agent_key_is_denied_before_nonce_is_spent(h):
    h.add_agent()
    nonce = h.challenge()
    jwk = public_jwk(generate_keypair()).model_dump(mode="json")
    jwk["x"] = jwk["x"][:-1] + "B"  # non-canonical encoding of the key
    evidence = {
        "agent_id": "expense-bot", "launcher_id": "launcher-1", "nonce": nonce,
        "measurement": GOLDEN, "agent_public_jwk": jwk, "iat": h.now(),
    }  # fmt: skip
    jws = sign_jwt(evidence, h.launcher_keys["launcher-1"])
    r = h.cp.post("/attest", json={"evidence_jws": jws})
    assert r.status_code == 422 and r.json()["reason_code"] == "INVALID_ARGUMENTS"
    h.assert_audited("INVALID_ARGUMENTS")
    assert Database(h.settings.db_path).get_nonce(nonce).used is False
    assert h.cp.get("/admin/agents", headers=h.admin).json()[0]["status"] == "registered"
