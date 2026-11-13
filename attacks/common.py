"""Shared plumbing for the attack scripts: result type, layer names and an isolated stack.

Every attack gets a FRESH in-process stack (control plane + gateway + resources, all
``TestClient``s, a temp DATA_DIR/KEYS_DIR, random throwaway secrets, ntfy off, no network).
It does not use pytest fixtures, so ``attacks/run_all.py`` runs standalone.

Judging rule: an attack ``succeeded`` only if a REAL effect happened (an email in the outbox,
a changed bank balance, an HTTP 200, a clean audit verify). Nothing is hard-coded.

The ``Env`` is the *evaluator*: it holds the admin and gateway secrets so it can set the
scene and read the evidence. The attacker code paths only use what a real attacker would have
(a leaked token, a captured request, an agent's own key).
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pyotp
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from aimfa.agents.client import AimfaError
from aimfa.agents.launcher import (
    LAUNCHER_ID,
    MANIFEST_DIR,
    AgentManifest,
    Launcher,
    load_manifest,
    load_or_create_launcher_key,
)
from aimfa.common.config import Settings
from aimfa.common.crypto import generate_keypair, public_jwk, sha256_hex, sign_jwt
from aimfa.common.dpop import make_proof
from aimfa.common.models import (
    AttestationEvidence,
    Mode,
    ReasonCode,
    TokenRequest,
    ToolCall,
    ToolCallResponse,
)
from aimfa.control_plane.app import create_app as control_plane_app
from aimfa.gateway.app import create_app as gateway_app
from aimfa.gateway.cp_client import HttpControlPlaneClient
from aimfa.resources.app import create_app as resources_app

MODE_AIMFA = "aimfa"
MODE_BASELINE = "baseline"
MODES = (MODE_AIMFA, MODE_BASELINE)

# Which defence layer stopped the attack (the "blocked_by" column of the results table).
LAYER_ATTESTATION = "attestation"
LAYER_DPOP = "dpop"
LAYER_DPOP_REPLAY = "dpop_replay"
LAYER_SCOPE_MONITOR = "scope_monitor"
LAYER_STEP_UP = "step_up"
LAYER_TTL_REVOCATION = "ttl_revocation"
LAYER_STS_POLICY = "sts_policy"
LAYER_HASH_CHAIN = "hash_chain"
LAYER_TOTP_BINDING = "totp_action_binding"

APPROVER_ID = "attack-approver"
ATTACKER_EMAIL = "attacker@evil.example"
SECRETS_PATH = "/engineering/secrets.env"


class AttackError(RuntimeError):
    """The scene could not be set up (e.g. the victim's legit call failed).

    Why: if setup breaks, "nothing happened" must not be reported as "AIMFA blocked it".
    """


@dataclass(frozen=True)
class AttackResult:
    name: str
    succeeded: bool
    blocked_by: str | None
    reason_code: ReasonCode | None
    evidence: str
    mode: str = ""


def check_mode(mode: str) -> str:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
    return mode


def reason_of(resp: httpx.Response) -> ReasonCode | None:
    """Reason code from an ErrorResponse or a ToolCallResponse body (None if unreadable)."""
    try:
        body = resp.json()
        raw = body.get("reason_code") or (body.get("decision") or {}).get("reason_code")
        return ReasonCode(raw)
    except (ValueError, AttributeError, TypeError):
        return None


def read_outbox(data_dir: Path) -> list[dict[str, Any]]:
    path = data_dir / "outbox.jsonl"
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


class Clock:
    """A settable UTC clock so expiry tests need no sleeping."""

    def __init__(self) -> None:
        self.now = datetime.now(UTC).replace(microsecond=0)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class BaselineSession:
    """Runs a scripted agent the OLD way: one static API key, no identity, no task token."""

    def __init__(self, env: Env) -> None:
        self._env = env

    def start_task(self, description: str, scopes: list[str]) -> None:
        return None

    def complete_task(self) -> None:
        return None

    def call(self, tool: str, /, **args: Any) -> ToolCallResponse:
        resp = self._env.baseline_call(tool, args)
        if resp.status_code != 200:
            raise AimfaError(reason_of(resp) or ReasonCode.UPSTREAM_ERROR, resp.status_code)
        return ToolCallResponse.model_validate(resp.json())


class Env:
    """One isolated stack. Use as a context manager; the temp dir is removed on exit."""

    def __init__(self, mode: str = MODE_AIMFA, *, access_ttl: int = 300) -> None:
        check_mode(mode)
        self.mode = mode
        self._tmp = tempfile.TemporaryDirectory(prefix="aimfa-attack-", ignore_cleanup_errors=True)
        root = Path(self._tmp.name)
        self._admin_key = secrets.token_urlsafe(24)
        self._baseline_key = secrets.token_urlsafe(24)
        self.settings = Settings(
            _env_file=None,
            aimfa_mode=Mode(mode),
            data_dir=root / "data",
            keys_dir=root / "keys",
            admin_api_key=self._admin_key,
            internal_service_secret=secrets.token_urlsafe(24),
            gateway_resource_secret=secrets.token_urlsafe(24),
            baseline_api_key=self._baseline_key,
            access_token_ttl_seconds=access_ttl,
            ntfy_enabled=False,
        )
        self.clock = Clock()
        self.admin = {"X-Admin-Key": self._admin_key}
        self.cp = TestClient(control_plane_app(self.settings, clock=self.clock))
        self.res = TestClient(resources_app(self.settings))
        self.gw = TestClient(
            gateway_app(
                self.settings,
                control_plane_client=HttpControlPlaneClient(self.cp, self.settings),
                resources_http=self.res,
                clock=self.clock,
            )
        )
        self._launcher_key: Ed25519PrivateKey | None = None
        self._launcher_registered = False
        self._totp_seed = self._enroll_approver()

    def __enter__(self) -> Env:
        return self

    def __exit__(self, *exc: object) -> None:
        for client in (self.gw, self.res, self.cp):
            client.close()
        self._tmp.cleanup()

    # ------------------------------------------------------------------ time / urls
    def now(self) -> int:
        return int(self.clock().timestamp())

    # ------------------------------------------------------------------ setup
    def _enroll_approver(self) -> str:
        resp = self.cp.post(
            "/admin/approvers", json={"approver_id": APPROVER_ID}, headers=self.admin
        )
        if resp.status_code != 201:
            raise AttackError(f"approver enrollment failed: HTTP {resp.status_code}")
        match = re.search(r"secret=([A-Za-z0-9]+)", resp.json()["provisioning_uri"])
        if match is None:
            raise AttackError("no TOTP seed in provisioning uri")
        return match.group(1)

    def launcher_key(self) -> Ed25519PrivateKey:
        if self._launcher_key is None:
            self._launcher_key = load_or_create_launcher_key(self.settings)
        return self._launcher_key

    def ensure_launcher(self) -> None:
        if self._launcher_registered:
            return
        body = {
            "launcher_id": LAUNCHER_ID,
            "public_jwk": public_jwk(self.launcher_key()).model_dump(mode="json"),
        }
        resp = self.cp.post("/admin/launchers", json=body, headers=self.admin)
        if resp.status_code != 201:
            raise AttackError(f"launcher registration failed: HTTP {resp.status_code}")
        self._launcher_registered = True

    def _register_agent(self, agent_id: str, role: str, golden: str) -> None:
        body = {
            "agent_id": agent_id,
            "role": role,
            "golden_measurement": golden,
            "launcher_id": LAUNCHER_ID,
            "approver_id": APPROVER_ID,
        }
        resp = self.cp.post("/admin/agents", json=body, headers=self.admin)
        if resp.status_code != 201:
            raise AttackError(f"agent registration failed: HTTP {resp.status_code}")

    def register_manifest(self, name: str) -> tuple[Launcher, AgentManifest]:
        """Register a real manifest's golden measurement; return the real Launcher for it."""
        self.ensure_launcher()
        launcher = Launcher(
            self.settings,
            self.launcher_key(),
            LAUNCHER_ID,
            cp_http=self.cp,
            gateway_http=self.gw,
        )
        manifest = load_manifest(MANIFEST_DIR / f"{name}.yaml")
        self._register_agent(manifest.agent_id, manifest.role, launcher.measure_agent(manifest))
        return launcher, manifest

    def onboard(self, agent_id: str, role: str) -> tuple[Ed25519PrivateKey, str]:
        """Register + attest a victim agent we control. Returns (agent key, identity token)."""
        self.ensure_launcher()
        self._register_agent(agent_id, role, sha256_hex(f"attack-lab:{agent_id}".encode()))
        key = generate_keypair()
        chal = self.cp.post("/attest/challenge", json={"agent_id": agent_id})
        if chal.status_code != 200:
            raise AttackError(f"challenge failed: HTTP {chal.status_code}")
        evidence = AttestationEvidence(
            agent_id=agent_id,
            launcher_id=LAUNCHER_ID,
            nonce=chal.json()["nonce"],
            measurement=sha256_hex(f"attack-lab:{agent_id}".encode()),
            agent_public_jwk=public_jwk(key),
            iat=self.now(),
        )
        jws = sign_jwt(evidence.model_dump(mode="json", exclude_none=True), self.launcher_key())
        resp = self.cp.post("/attest", json={"evidence_jws": jws})
        if resp.status_code != 200:
            raise AttackError(f"attestation failed: HTTP {resp.status_code}")
        return key, resp.json()["identity_token"]

    # ------------------------------------------------------------------ AIMFA-mode calls
    def proof(
        self, key: Ed25519PrivateKey, method: str, base: str, path: str, token: str | None
    ) -> str:
        return make_proof(key, method, base + path, token, now=self.now())

    def request_token(
        self, key: Ed25519PrivateKey, identity_token: str, scopes: list[str]
    ) -> httpx.Response:
        body = TokenRequest(
            identity_token=identity_token,
            task_description="attack lab task",
            requested_scopes=scopes,
        ).model_dump(mode="json")
        proof = self.proof(key, "POST", self.settings.control_plane_url, "/token", None)
        return self.cp.post("/token", json=body, headers={"DPoP": proof})

    def get_token(
        self, key: Ed25519PrivateKey, identity_token: str, scopes: list[str]
    ) -> dict[str, Any]:
        resp = self.request_token(key, identity_token, scopes)
        if resp.status_code != 200:
            raise AttackError(f"legit token request failed: HTTP {resp.status_code}")
        return resp.json()

    def gateway_headers(self, key: Ed25519PrivateKey, token: str) -> dict[str, str]:
        proof = self.proof(key, "POST", self.settings.gateway_url, "/tool", token)
        return {"Authorization": f"DPoP {token}", "DPoP": proof}

    def gateway_call(
        self,
        key: Ed25519PrivateKey | None,
        token: str,
        tool: str,
        args: dict[str, Any],
        *,
        approval_id: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        body = ToolCall(tool=tool, args=args, approval_id=approval_id).model_dump(mode="json")
        if headers is None:
            if key is None:
                raise ValueError("need a key or explicit headers")
            headers = self.gateway_headers(key, token)
        return self.gw.post("/tool", json=body, headers=headers)

    def complete_task(self, key: Ed25519PrivateKey, token: str, task_id: str) -> None:
        path = f"/tasks/{quote(task_id, safe='')}/complete"
        headers = {
            "Authorization": f"DPoP {token}",
            "DPoP": self.proof(key, "POST", self.settings.control_plane_url, path, token),
        }
        resp = self.cp.post(path, headers=headers)
        if resp.status_code != 204:
            raise AttackError(f"complete_task failed: HTTP {resp.status_code}")

    # ------------------------------------------------------------------ baseline calls
    def baseline_call(
        self, tool: str, args: dict[str, Any], *, api_key: str | None = None
    ) -> httpx.Response:
        headers = {"X-API-Key": api_key if api_key is not None else self._baseline_key}
        return self.gw.post("/tool", json={"tool": tool, "args": args}, headers=headers)

    def leaked_baseline_key(self) -> str:
        """The static key as an attacker would have it after a leak (A2 baseline)."""
        return self._baseline_key

    # ------------------------------------------------------------------ approvals
    def totp_code(self) -> str:
        return pyotp.TOTP(self._totp_seed).at(self.clock())

    def wrong_totp_code(self) -> str:
        totp = pyotp.TOTP(self._totp_seed)
        near = {totp.at(self.clock() + timedelta(seconds=d)) for d in (-60, -30, 0, 30, 60)}
        return next(c for c in (f"{i:06d}" for i in range(1_000_000)) if c not in near)

    def decide(self, approval_id: str, *, approve: bool, code: str) -> httpx.Response:
        body = {"approver_id": APPROVER_ID, "approve": approve, "totp_code": code}
        return self.cp.post(f"/approvals/{approval_id}/decide", json=body, headers=self.admin)

    def approvals(self, status: str | None = None) -> list[dict[str, Any]]:
        url = "/admin/approvals" + (f"?status={status}" if status else "")
        return self.cp.get(url, headers=self.admin).json()

    def human_sleep(self, *, approve: bool) -> Callable[[float], None]:
        """A stand-in for sleep(): the human opens the push, types a TOTP code and decides."""

        def _sleep(_seconds: float) -> None:
            for rec in self.approvals("pending"):
                resp = self.decide(rec["approval_id"], approve=approve, code=self.totp_code())
                if resp.status_code != 200:
                    raise AttackError(f"human decision failed: HTTP {resp.status_code}")

        return _sleep

    # ------------------------------------------------------------------ evidence
    def outbox(self) -> list[dict[str, Any]]:
        return read_outbox(self.settings.data_dir)

    def balance(self) -> float:
        """Bank balance read straight from the mock resource DB (evaluator view)."""
        conn = sqlite3.connect(self.settings.data_dir / "resources.db")
        try:
            row = conn.execute("SELECT balance FROM bank WHERE id = ?", (1,)).fetchone()
        finally:
            conn.close()
        return float(row[0])

    def audit(self) -> list[dict[str, Any]]:
        resp = self.cp.get("/admin/audit?limit=1000", headers=self.admin)
        return resp.json()


def result(
    name: str,
    mode: str,
    *,
    succeeded: bool,
    blocked_by: str | None = None,
    reason_code: ReasonCode | None = None,
    evidence: str,
) -> AttackResult:
    """Build a result; a successful attack is never labelled as blocked."""
    if succeeded:
        blocked_by, reason_code = None, None
    return AttackResult(name, succeeded, blocked_by, reason_code, evidence, mode)
