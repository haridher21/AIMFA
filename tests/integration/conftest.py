"""Shared fixtures for Phase 2 integration tests (control plane + resources).

ASSUMPTIONS the implementation must satisfy:
* `aimfa.control_plane.app.create_app(settings, *, clock=None) -> FastAPI`
  `clock` is a zero-arg callable returning a tz-aware UTC `datetime`; None means real time.
  The app uses it for nonce expiry, JWT iat/exp, DPoP `now`, and token expiry.
* `aimfa.resources.app.create_app(settings) -> FastAPI`.
* Both factories do all startup work eagerly (create dirs, signing key in KEYS_DIR, DB schema,
  seed data), because tests use `TestClient(app)` without a lifespan context.
* The control plane uses `settings.db_path` (shared SQLite), so tests may also open
  `Database(settings.db_path)` to set up state (e.g. quarantine an agent).
* Settings are built directly with `_env_file=None`, a tmp DATA_DIR and KEYS_DIR.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient

from aimfa.common.config import Settings
from aimfa.common.crypto import generate_keypair, public_jwk, sha256_hex, sign_jwt
from aimfa.common.db import Database
from aimfa.common.dpop import make_proof
from aimfa.common.models import AttestationEvidence

GOLDEN = sha256_hex(b"golden-agent-build")
ADMIN_KEY = "test-admin-key"
INTERNAL_SECRET = "test-internal-secret"
GATEWAY_SECRET = "test-gateway-secret"
APPROVER = "alice-approver"


class FakeClock:
    def __init__(self) -> None:
        # Start at real "now": some tests verify app-issued JWTs with PyJWT,
        # which checks exp against the wall clock, not this fake clock.
        self.now = datetime.now(UTC).replace(microsecond=0)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def b64url_pubkey(jwk: dict[str, Any]) -> Ed25519PublicKey:
    x = jwk["x"]
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)))


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        data_dir=tmp_path / "data",
        keys_dir=tmp_path / "keys",
        admin_api_key=ADMIN_KEY,
        internal_service_secret=INTERNAL_SECRET,
        gateway_resource_secret=GATEWAY_SECRET,
        identity_token_ttl_seconds=600,
        access_token_ttl_seconds=300,
        attest_nonce_ttl_seconds=60,
        dpop_max_age_seconds=60,
        ntfy_enabled=False,
    )


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


class Harness:
    def __init__(self, settings: Settings, clock: FakeClock) -> None:
        from aimfa.control_plane.app import create_app

        self.settings, self.clock = settings, clock
        self.cp = TestClient(create_app(settings, clock=clock))
        self.admin = {"X-Admin-Key": ADMIN_KEY}
        self.internal = {"X-Internal-Secret": INTERNAL_SECRET}
        self.launcher_keys: dict[str, Any] = {}

    # --- time / urls
    def now(self) -> int:
        return int(self.clock().timestamp())

    def url(self, path: str) -> str:
        return self.settings.control_plane_url + path

    # --- registry
    def add_launcher(self, launcher_id: str = "launcher-1"):
        key = generate_keypair()
        self.launcher_keys[launcher_id] = key
        body = {"launcher_id": launcher_id, "public_jwk": public_jwk(key).model_dump(mode="json")}
        r = self.cp.post("/admin/launchers", json=body, headers=self.admin)
        assert r.status_code == 201, r.text
        return key

    def add_agent(self, agent_id="expense-bot", role="expense_reader", launcher_id="launcher-1"):
        if launcher_id not in self.launcher_keys:
            self.add_launcher(launcher_id)
        # 201 first time, 409 afterwards; both are fine here.
        self.cp.post("/admin/approvers", json={"approver_id": APPROVER}, headers=self.admin)
        body = {
            "agent_id": agent_id,
            "role": role,
            "golden_measurement": GOLDEN,
            "launcher_id": launcher_id,
            "approver_id": APPROVER,
        }
        r = self.cp.post("/admin/agents", json=body, headers=self.admin)
        assert r.status_code == 201, r.text

    # --- attestation
    def challenge(self, agent_id="expense-bot") -> str:
        r = self.cp.post("/attest/challenge", json={"agent_id": agent_id})
        assert r.status_code == 200, r.text
        return r.json()["nonce"]

    def evidence_jws(self, signing_key, *, agent_id, launcher_id, nonce, measurement, agent_key):
        ev = AttestationEvidence(
            agent_id=agent_id,
            launcher_id=launcher_id,
            nonce=nonce,
            measurement=measurement,
            agent_public_jwk=public_jwk(agent_key),
            iat=self.now(),
        )
        return sign_jwt(ev.model_dump(mode="json", exclude_none=True), signing_key)

    def attest(
        self,
        agent_id="expense-bot",
        *,
        agent_key=None,
        signing_key=None,
        launcher_id="launcher-1",
        measurement=GOLDEN,
        nonce=None,
    ):
        agent_key = agent_key or generate_keypair()
        signing_key = signing_key or self.launcher_keys[launcher_id]
        nonce = nonce or self.challenge(agent_id)
        jws = self.evidence_jws(
            signing_key,
            agent_id=agent_id,
            launcher_id=launcher_id,
            nonce=nonce,
            measurement=measurement,
            agent_key=agent_key,
        )
        return self.cp.post("/attest", json={"evidence_jws": jws})

    def onboard(self, agent_id="expense-bot", role="expense_reader"):
        """Register + attest an agent. Returns (agent_private_key, identity_token)."""
        self.add_agent(agent_id, role)
        key = generate_keypair()
        r = self.attest(agent_id, agent_key=key)
        assert r.status_code == 200, r.text
        return key, r.json()["identity_token"]

    # --- token service
    def proof(self, key, method, path, access_token=None, now=None) -> str:
        return make_proof(key, method, self.url(path), access_token, now=now or self.now())

    def request_token(self, key, identity_token, scopes, *, proof_key=None, proof=None):
        body = {
            "identity_token": identity_token,
            "task_description": "summarize expenses",
            "requested_scopes": scopes,
        }
        headers = {"DPoP": proof or self.proof(proof_key or key, "POST", "/token")}
        return self.cp.post("/token", json=body, headers=headers)

    def auth_headers(self, key, access_token, method, path) -> dict[str, str]:
        return {
            "Authorization": f"DPoP {access_token}",
            "DPoP": self.proof(key, method, path, access_token),
        }

    # --- misc
    def audit(self) -> list[dict[str, Any]]:
        r = self.cp.get("/admin/audit?limit=1000", headers=self.admin)
        assert r.status_code == 200, r.text
        return r.json()

    def assert_audited(self, reason_code: str) -> None:
        assert any(rec["reason_code"] == reason_code for rec in self.audit()), reason_code

    def quarantine(self, agent_id: str) -> None:
        Database(self.settings.db_path).quarantine_agent(agent_id, at=self.clock())


@pytest.fixture
def h(settings, clock) -> Harness:
    return Harness(settings, clock)
