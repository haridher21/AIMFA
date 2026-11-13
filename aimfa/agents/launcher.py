"""The launcher: the trusted root that measures an agent and vouches for it (ADR-0003).

Why it exists: an agent cannot attest itself (a tampered agent would just report the
golden hash). The launcher measures the code, system prompt, tool list and model id from
the manifest, makes a FRESH in-memory key for this instance, signs the evidence with its own
registered key, and only then hands the agent an ``AgentClient``.

The system prompt comes ONLY from the manifest's prompt file, which is part of the
measurement. The instance private key is never written to disk; the launcher's own
long-term key is (``keys/launcher.pem``, git-ignored), like a host key.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import httpx
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aimfa.agents.client import HTTP_TIMEOUT_SECONDS, AgentClient, AimfaError, error_for
from aimfa.common import crypto
from aimfa.common.config import REPO_ROOT, Settings
from aimfa.common.models import (
    AGENT_ID_PATTERN,
    AttestationChallenge,
    AttestationChallengeRequest,
    AttestationEvidence,
    AttestationRequest,
    ErrorResponse,
    ReasonCode,
)

LAUNCHER_ID = "local-launcher"
MANIFEST_DIR = Path(__file__).resolve().parent / "manifests"


class AgentManifest(BaseModel):
    """What the launcher measures. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str = Field(pattern=AGENT_ID_PATTERN)
    role: str
    description: str = ""
    model_id: str
    prompt_file: str
    tools: list[str]
    code_paths: list[str]
    # Filled by load_manifest from prompt_file only; never accepted from the YAML itself.
    system_prompt: str = Field(default="", exclude=True)


def load_manifest(path: str | Path) -> AgentManifest:
    """Read a manifest and its prompt file. Raises ValueError on anything malformed."""
    manifest_path = Path(path).resolve(strict=True)
    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "system_prompt" in raw:
        raise ValueError(f"{manifest_path.name}: malformed manifest")
    try:
        manifest = AgentManifest.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(f"{manifest_path.name}: invalid manifest ({exc.error_count()})") from None
    base = manifest_path.parent
    prompt_path = (base / manifest.prompt_file).resolve()
    # Why: a prompt outside the manifest dir could be swapped without anyone noticing.
    if not prompt_path.is_relative_to(base) or prompt_path == base:
        raise ValueError(f"{manifest_path.name}: prompt_file escapes the manifest directory")
    prompt = prompt_path.read_text(encoding="utf-8")
    return manifest.model_copy(update={"system_prompt": prompt})


def measure_agent(manifest: AgentManifest, *, root: Path = REPO_ROOT) -> str:
    """Hash code + prompt + (tools, role) + model id. Any change gives a new value."""
    tool_manifest: dict[str, Any] = {"tools": sorted(manifest.tools), "role": manifest.role}
    # crypto.measure resolves paths against the CWD, so anchor them at root; it then rejects
    # anything that escapes root.
    code_paths = [root / p for p in manifest.code_paths]
    return crypto.measure(
        code_paths, manifest.system_prompt, tool_manifest, manifest.model_id, root=root
    )


def load_or_create_launcher_key(settings: Settings) -> Ed25519PrivateKey:
    """The launcher's long-term key, stored at ``keys/launcher.pem`` (never per-agent keys)."""
    path = settings.keys_dir / "launcher.pem"
    if path.exists():
        return crypto.load_private_key(path)
    key = crypto.generate_keypair()
    crypto.save_private_key(key, path)
    return key


class Launcher:
    def __init__(
        self,
        settings: Settings,
        launcher_key: Ed25519PrivateKey,
        launcher_id: str = LAUNCHER_ID,
        *,
        cp_http: httpx.Client | None = None,
        gateway_http: httpx.Client | None = None,
        root: Path = REPO_ROOT,
    ) -> None:
        self._settings = settings
        self._key = launcher_key
        self.launcher_id = launcher_id
        self._cp = cp_http or httpx.Client(
            base_url=settings.control_plane_url, timeout=HTTP_TIMEOUT_SECONDS
        )
        self._gw = gateway_http or httpx.Client(
            base_url=settings.gateway_url, timeout=HTTP_TIMEOUT_SECONDS
        )
        self._root = root

    def __repr__(self) -> str:  # never show the key
        return f"Launcher(launcher_id={self.launcher_id!r})"

    def measure_agent(self, manifest: AgentManifest) -> str:
        return measure_agent(manifest, root=self._root)

    def _post(self, path: str, body: dict[str, Any]) -> httpx.Response:
        try:
            return self._cp.post(path, json=body)
        except httpx.HTTPError:
            raise AimfaError(ReasonCode.UPSTREAM_ERROR) from None

    @staticmethod
    def _fail(resp: httpx.Response) -> AimfaError:
        try:
            reason = ErrorResponse.model_validate(resp.json()).reason_code
        except (ValueError, ValidationError):
            reason = ReasonCode.UPSTREAM_ERROR
        return error_for(resp.status_code, reason)

    def launch(self, manifest: AgentManifest, **client_kwargs: Any) -> AgentClient:
        """challenge -> measure -> fresh key -> signed evidence -> identity -> AgentClient."""
        resp = self._post(
            "/attest/challenge",
            AttestationChallengeRequest(agent_id=manifest.agent_id).model_dump(mode="json"),
        )
        if resp.status_code != 200:
            raise self._fail(resp)
        try:
            nonce = AttestationChallenge.model_validate(resp.json()).nonce
        except (ValueError, ValidationError):
            raise AimfaError(ReasonCode.UPSTREAM_ERROR, resp.status_code) from None

        measurement = self.measure_agent(manifest)
        agent_key = crypto.generate_keypair()  # in memory only, never saved
        evidence = AttestationEvidence(
            agent_id=manifest.agent_id,
            launcher_id=self.launcher_id,
            nonce=nonce,
            measurement=measurement,
            agent_public_jwk=crypto.public_jwk(agent_key),
            iat=int(time.time()),
        )
        jws = crypto.sign_jwt(evidence.model_dump(mode="json", exclude_none=True), self._key)
        resp = self._post("/attest", AttestationRequest(evidence_jws=jws).model_dump(mode="json"))
        if resp.status_code != 200:
            raise self._fail(resp)
        try:
            identity_token = resp.json()["identity_token"]
        except (ValueError, KeyError, TypeError):
            raise AimfaError(ReasonCode.UPSTREAM_ERROR, resp.status_code) from None
        return AgentClient(
            self._settings,
            agent_key,
            identity_token,
            cp_http=self._cp,
            gateway_http=self._gw,
            **client_kwargs,
        )
