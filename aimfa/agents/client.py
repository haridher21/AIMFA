"""``AgentClient``: how an agent talks to AIMFA without ever handling raw bearer tokens.

It holds the agent's private key (in memory only), trades the identity credential for a
task-scoped access token, and signs a FRESH DPoP proof for every single request, so a
copied token or a replayed proof is useless. When the gateway answers 202 (a human must
approve), it polls the control plane and then retries the identical call.

Never logged or exposed: the private key, the identity credential and the access token.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from aimfa.common.config import Settings
from aimfa.common.dpop import make_proof
from aimfa.common.models import (
    ApprovalStatus,
    ApprovalStatusView,
    ErrorResponse,
    ReasonCode,
    TokenRequest,
    TokenResponse,
    ToolCall,
    ToolCallResponse,
)

HTTP_TIMEOUT_SECONDS = 15.0


class AimfaError(Exception):
    """Base class. Carries only the machine-readable reason, never a token or key."""

    def __init__(self, reason_code: ReasonCode, status_code: int | None = None) -> None:
        super().__init__(f"{reason_code.value} (HTTP {status_code})")
        self.reason_code = reason_code
        self.status_code = status_code


class AuthError(AimfaError):
    """401: the token or proof was not accepted (missing, expired, revoked, bad proof)."""


class PolicyDenied(AimfaError):
    """403/422: authenticated, but the action or arguments are not allowed."""


class ApprovalTimeout(AimfaError):
    """A human did not answer within ``poll_timeout``. The action was NOT executed."""


def error_for(status: int, reason_code: ReasonCode) -> AimfaError:
    """Pick the exception class from the HTTP status."""
    if status == 401:
        return AuthError(reason_code, status)
    if status in (403, 422):
        return PolicyDenied(reason_code, status)
    return AimfaError(reason_code, status)


class AgentClient:
    def __init__(
        self,
        settings: Settings,
        private_key: Ed25519PrivateKey,
        identity_token: str,
        *,
        cp_http: httpx.Client | None = None,
        gateway_http: httpx.Client | None = None,
        poll_interval: float = 1.0,
        poll_timeout: float = 60.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if poll_interval <= 0 or poll_timeout < 0:
            raise ValueError("poll_interval must be > 0 and poll_timeout >= 0")
        self._settings = settings
        self._key = private_key
        self._identity_token = identity_token
        self._cp = cp_http or httpx.Client(
            base_url=settings.control_plane_url, timeout=HTTP_TIMEOUT_SECONDS
        )
        self._gw = gateway_http or httpx.Client(
            base_url=settings.gateway_url, timeout=HTTP_TIMEOUT_SECONDS
        )
        self._interval = poll_interval
        self._timeout = poll_timeout
        self._sleep = sleep
        self._access_token: str | None = None
        self._task_id: str | None = None

    def __repr__(self) -> str:  # never show the key or tokens
        return f"AgentClient(task_id={self._task_id!r})"

    @property
    def task_id(self) -> str | None:
        return self._task_id

    # ---------------------------------------------------------------- plumbing

    def _proof(self, method: str, base_url: str, path: str, access_token: str | None) -> str:
        """A fresh single-use proof for ONE request. ``path`` has no query string."""
        return make_proof(self._key, method, base_url + path, access_token)

    def _auth_headers(self, method: str, base_url: str, path: str) -> dict[str, str]:
        token = self._require_token()
        return {
            "Authorization": f"DPoP {token}",
            "DPoP": self._proof(method, base_url, path, token),
        }

    def _require_token(self) -> str:
        if self._access_token is None:
            raise AuthError(ReasonCode.TOKEN_MISSING)  # fail closed: no task started
        return self._access_token

    def _request(
        self,
        http: httpx.Client,
        method: str,
        path: str,
        *,
        headers: dict[str, str],
        body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        try:
            return http.request(method, path, json=body, headers=headers)
        except httpx.HTTPError:
            raise AimfaError(ReasonCode.UPSTREAM_ERROR) from None

    @staticmethod
    def _fail(resp: httpx.Response) -> AimfaError:
        try:
            reason = ErrorResponse.model_validate(resp.json()).reason_code
        except (ValueError, ValidationError):
            reason = ReasonCode.UPSTREAM_ERROR
        return error_for(resp.status_code, reason)

    # ---------------------------------------------------------------- tasks

    def start_task(self, description: str, scopes: list[str]) -> TokenResponse:
        """Trade the identity credential for an access token limited to ``scopes``."""
        body = TokenRequest(
            identity_token=self._identity_token,
            task_description=description,
            requested_scopes=scopes,
        ).model_dump(mode="json")
        headers = {"DPoP": self._proof("POST", self._settings.control_plane_url, "/token", None)}
        resp = self._request(self._cp, "POST", "/token", headers=headers, body=body)
        if resp.status_code != 200:
            raise self._fail(resp)
        try:
            token = TokenResponse.model_validate(resp.json())
        except (ValueError, ValidationError):
            raise AimfaError(ReasonCode.UPSTREAM_ERROR, resp.status_code) from None
        self._access_token, self._task_id = token.access_token, token.task_id
        return token

    def complete_task(self) -> None:
        """Tell the control plane the task is done; it revokes the task's token."""
        if self._task_id is None:
            raise AuthError(ReasonCode.TOKEN_MISSING)
        path = f"/tasks/{quote(self._task_id, safe='')}/complete"
        headers = self._auth_headers("POST", self._settings.control_plane_url, path)
        resp = self._request(self._cp, "POST", path, headers=headers)
        if resp.status_code != 204:
            raise self._fail(resp)

    # ---------------------------------------------------------------- tool calls

    def call(self, tool: str, /, **args: Any) -> ToolCallResponse:
        """Call a tool. Returns the final 200 response, waiting for a human if needed."""
        approval_id: str | None = None
        while True:
            resp = self._post_tool(tool, args, approval_id)
            if resp.status_code == 200:
                return self._parse_tool_response(resp)
            if resp.status_code != 202:
                raise self._fail(resp)
            pending = self._parse_tool_response(resp).decision.approval_id
            if approval_id is not None or pending is None:
                # Already holding an approval, or none was given: do not loop forever.
                raise AimfaError(ReasonCode.PENDING_APPROVAL, 202)
            approval_id = pending
            self._wait_for_approval(approval_id)
            # Approved: loop to retry the IDENTICAL call, now carrying the approval id.

    def _post_tool(
        self, tool: str, args: dict[str, Any], approval_id: str | None
    ) -> httpx.Response:
        body = ToolCall(tool=tool, args=args, approval_id=approval_id).model_dump(mode="json")
        headers = self._auth_headers("POST", self._settings.gateway_url, "/tool")
        return self._request(self._gw, "POST", "/tool", headers=headers, body=body)

    @staticmethod
    def _parse_tool_response(resp: httpx.Response) -> ToolCallResponse:
        try:
            return ToolCallResponse.model_validate(resp.json())
        except (ValueError, ValidationError):
            raise AimfaError(ReasonCode.UPSTREAM_ERROR, resp.status_code) from None

    # ---------------------------------------------------------------- approvals

    def _approval_status(self, approval_id: str) -> ApprovalStatus:
        path = f"/approvals/{quote(approval_id, safe='')}"
        headers = self._auth_headers("GET", self._settings.control_plane_url, path)
        resp = self._request(self._cp, "GET", path, headers=headers)
        if resp.status_code != 200:
            raise self._fail(resp)
        try:
            return ApprovalStatusView.model_validate(resp.json()).status
        except (ValueError, ValidationError):
            raise AimfaError(ReasonCode.UPSTREAM_ERROR, resp.status_code) from None

    def _wait_for_approval(self, approval_id: str) -> None:
        """Poll until a human approves. Denied/expired/timeout raise; nothing is executed.

        The timeout is counted from the sleeps we ask for, so tests need no real clock.
        """
        waited = 0.0
        while True:
            status = self._approval_status(approval_id)
            if status is ApprovalStatus.APPROVED:
                return
            if status is ApprovalStatus.DENIED:
                raise PolicyDenied(ReasonCode.APPROVAL_DENIED, 403)
            if status is ApprovalStatus.EXPIRED:
                raise PolicyDenied(ReasonCode.APPROVAL_EXPIRED, 403)
            if status is ApprovalStatus.USED:
                raise PolicyDenied(ReasonCode.APPROVAL_ALREADY_USED, 403)
            if waited >= self._timeout:
                raise ApprovalTimeout(ReasonCode.PENDING_APPROVAL, 202)
            self._sleep(self._interval)
            waited += self._interval

    # ---------------------------------------------------------------- cleanup

    def close(self) -> None:
        self._cp.close()
        self._gw.close()
