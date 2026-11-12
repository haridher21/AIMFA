"""T2.2 attestation. See conftest.py for factory/clock assumptions.

Extra assumptions: an unknown agent at /attest -> 404 ATTEST_UNKNOWN_AGENT; a launcher that is
unregistered OR not the agent's assigned launcher -> 401 ATTEST_UNKNOWN_LAUNCHER; a garbage or
alg=none JWS -> 401 ATTEST_BAD_SIGNATURE; every failure appends an audit record carrying the
same reason_code (readable via GET /admin/audit).
"""

from __future__ import annotations

import base64
import json

from aimfa.common.crypto import generate_keypair, jwk_thumbprint, public_jwk, verify_jwt
from aimfa.common.models import IdentityCredentialClaims
from tests.integration.conftest import GOLDEN, b64url_pubkey


def fail(h, resp, status, code):
    assert resp.status_code == status, resp.text
    assert resp.json()["reason_code"] == code
    h.assert_audited(code)


def test_challenge_for_unknown_agent_is_404(h):
    r = h.cp.post("/attest/challenge", json={"agent_id": "ghost-bot"})
    assert r.status_code == 404 and r.json()["reason_code"] == "ATTEST_UNKNOWN_AGENT"


def test_challenge_nonces_are_unique_and_long(h):
    h.add_agent()
    a, b = h.challenge(), h.challenge()
    assert a != b and len(a) >= 16


def test_happy_path_issues_valid_identity_token(h):
    h.add_agent()
    key = generate_keypair()
    r = h.attest(agent_key=key)
    assert r.status_code == 200
    token = r.json()["identity_token"]

    jwks = h.cp.get("/.well-known/jwks.json").json()
    assert len(jwks["keys"]) == 1
    claims = verify_jwt(
        token,
        b64url_pubkey(jwks["keys"][0]),
        audience="aimfa-sts",
        issuer="aimfa-control-plane",
        token_use="identity",
    )
    parsed = IdentityCredentialClaims.model_validate(claims)
    assert parsed.sub == "expense-bot" and parsed.role == "expense_reader"
    assert parsed.measurement == GOLDEN
    assert jwk_thumbprint(public_jwk(key)) == jwk_thumbprint(
        type(public_jwk(key)).model_validate(parsed.cnf["jwk"])
    )
    assert parsed.exp - parsed.iat == h.settings.identity_token_ttl_seconds
    assert h.cp.get("/admin/agents", headers=h.admin).json()[0]["status"] == "active"


def test_signing_key_is_generated_into_keys_dir_and_stable(h, settings, clock):
    from aimfa.control_plane.app import create_app
    from fastapi.testclient import TestClient

    first = h.cp.get("/.well-known/jwks.json").json()
    assert any(settings.keys_dir.iterdir())
    again = TestClient(create_app(settings, clock=clock)).get("/.well-known/jwks.json").json()
    assert first == again


def test_unknown_agent_is_404(h):
    h.add_launcher()
    h.add_agent()
    nonce = h.challenge()
    key = h.launcher_keys["launcher-1"]
    jws = h.evidence_jws(
        key,
        agent_id="ghost-bot",
        launcher_id="launcher-1",
        nonce=nonce,
        measurement=GOLDEN,
        agent_key=generate_keypair(),
    )
    fail(h, h.cp.post("/attest", json={"evidence_jws": jws}), 404, "ATTEST_UNKNOWN_AGENT")


def test_unregistered_launcher_is_rejected(h):
    h.add_agent()
    rogue = generate_keypair()
    r = h.attest(signing_key=rogue, launcher_id="launcher-evil")
    fail(h, r, 401, "ATTEST_UNKNOWN_LAUNCHER")


def test_launcher_not_assigned_to_agent_is_rejected(h):
    h.add_agent()
    other = h.add_launcher("launcher-2")
    r = h.attest(signing_key=other, launcher_id="launcher-2")
    fail(h, r, 401, "ATTEST_UNKNOWN_LAUNCHER")


def test_evidence_signed_by_wrong_key_is_rejected(h):
    h.add_agent()
    r = h.attest(signing_key=generate_keypair())  # claims launcher-1 but signed by attacker
    fail(h, r, 401, "ATTEST_BAD_SIGNATURE")


def test_garbage_and_alg_none_jws_are_rejected(h):
    h.add_agent()
    r = h.cp.post("/attest", json={"evidence_jws": "not-a-jws"})
    assert r.status_code in (401, 422)
    nonce = h.challenge()
    claims = {
        "agent_id": "expense-bot", "launcher_id": "launcher-1", "nonce": nonce,
        "measurement": GOLDEN, "iat": h.now(),
        "agent_public_jwk": public_jwk(generate_keypair()).model_dump(mode="json"),
    }  # fmt: skip
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    unsigned = f"{seg({'alg': 'none', 'typ': 'JWT'})}.{seg(claims)}."
    fail(h, h.cp.post("/attest", json={"evidence_jws": unsigned}), 401, "ATTEST_BAD_SIGNATURE")


def test_unknown_nonce_is_rejected(h):
    h.add_agent()
    fail(h, h.attest(nonce="n" * 32), 401, "ATTEST_NONCE_INVALID")


def test_reused_nonce_is_rejected(h):
    h.add_agent()
    nonce = h.challenge()
    assert h.attest(nonce=nonce).status_code == 200
    fail(h, h.attest(nonce=nonce), 401, "ATTEST_NONCE_INVALID")


def test_expired_nonce_is_rejected(h):
    h.add_agent()
    nonce = h.challenge()
    h.clock.advance(h.settings.attest_nonce_ttl_seconds + 1)
    fail(h, h.attest(nonce=nonce), 401, "ATTEST_NONCE_INVALID")


def test_nonce_issued_for_another_agent_is_rejected(h):
    h.add_agent("expense-bot")
    h.add_agent("other-bot")
    nonce = h.challenge("other-bot")
    fail(h, h.attest("expense-bot", nonce=nonce), 401, "ATTEST_NONCE_INVALID")
    # the victim's nonce was not burned by the failed cross-agent attempt
    assert h.attest("other-bot", nonce=nonce).status_code == 200


def test_measurement_mismatch_is_rejected(h):
    h.add_agent()
    r = h.attest(measurement="0" * 64)
    fail(h, r, 401, "ATTEST_MEASUREMENT_MISMATCH")
    assert h.cp.get("/admin/agents", headers=h.admin).json()[0]["status"] == "registered"


def test_quarantined_agent_cannot_attest(h):
    h.add_agent()
    h.quarantine("expense-bot")
    fail(h, h.attest(), 403, "AGENT_QUARANTINED")
