"""Typed client for the control plane's admin API (the dashboard's ONLY data source).

Why a separate class: the dashboard must never touch the database. Going through the admin
API means every action is authenticated (``X-Admin-Key``), validated and audited by the
control plane. No streamlit import here, so it is unit-testable.
"""

from __future__ import annotations

import functools
import re
from typing import Any, TypeVar
from urllib.parse import quote

import httpx
from pydantic import BaseModel, TypeAdapter, ValidationError

from aimfa.common.config import Settings
from aimfa.common.models import (
    TOTP_PATTERN,
    ActiveTokenView,
    AgentRecord,
    ApprovalDecisionRequest,
    ApprovalRecord,
    AuditRecord,
    AuditVerifyResult,
    ErrorResponse,
    ReasonCode,
    RiskScore,
)

T = TypeVar("T", bound=BaseModel)
TIMEOUT_SECONDS = 5.0


@functools.cache
def _list_adapter(model: type[BaseModel]) -> TypeAdapter[Any]:
    """Building a TypeAdapter compiles a schema; pages poll every few seconds, so cache it."""
    return TypeAdapter(list[model])  # type: ignore[valid-type]


class AdminApiError(Exception):
    """The control plane answered with a non-2xx status. Never carries headers or secrets."""

    def __init__(self, status: int, reason_code: ReasonCode, message: str = "") -> None:
        self.status = status
        self.reason_code = reason_code
        self.message = message
        super().__init__(f"HTTP {status} {reason_code.value}: {message}")


class ControlPlaneUnavailable(Exception):
    """The control plane could not be reached (down, refused, timed out)."""


class InvalidTotpCode(ValueError):
    """The typed code is not 6 digits. Checked before sending: no empty/garbage approvals."""


def check_totp_format(code: str) -> str:
    """Fail closed on a malformed code; the server re-checks the code itself."""
    if not isinstance(code, str) or re.fullmatch(TOTP_PATTERN, code) is None:
        raise InvalidTotpCode("TOTP code must be exactly 6 digits")
    return code


LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def check_local_url(url: str) -> str:
    """The admin key is only ever sent to this laptop. A tampered ``.env`` pointing the
    control plane URL elsewhere must not leak it, so refuse (fail closed)."""
    if httpx.URL(url).host not in LOCAL_HOSTS:
        raise ValueError("control plane URL must be on localhost")
    return url


class AdminClient:
    def __init__(self, settings: Settings | None = None, *, http: httpx.Client | None = None):
        self._settings = settings or Settings()
        # trust_env=False: never route the admin key through an HTTP(S)_PROXY from the
        # environment (e.g. a debugging proxy). No redirects: the key must not follow one.
        self._http = http or httpx.Client(
            base_url=check_local_url(self._settings.control_plane_url),
            timeout=TIMEOUT_SECONDS,
            trust_env=False,
            follow_redirects=False,
        )

    def __repr__(self) -> str:  # never include the key
        return f"AdminClient(url={self._settings.control_plane_url!r})"

    __str__ = __repr__

    # ------------------------------------------------------------------ plumbing
    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = {"X-Admin-Key": self._settings.admin_api_key.get_secret_value()}
        try:
            resp = self._http.request(method, path, headers=headers, **kwargs)
        except httpx.HTTPError:
            # Deliberately drop the original error: it could echo request details.
            raise ControlPlaneUnavailable("control plane unreachable") from None
        if resp.is_success:
            return resp
        try:
            err = ErrorResponse.model_validate(resp.json())
            raise AdminApiError(resp.status_code, err.reason_code, err.message)
        except (ValueError, ValidationError):
            raise AdminApiError(resp.status_code, ReasonCode.UPSTREAM_ERROR, "") from None

    def _parse(self, resp: httpx.Response, model: type[T]) -> T:
        try:
            return model.model_validate(resp.json())
        except (ValueError, ValidationError):
            raise AdminApiError(
                resp.status_code, ReasonCode.UPSTREAM_ERROR, "unexpected response"
            ) from None

    def _parse_list(self, resp: httpx.Response, model: type[T]) -> list[T]:
        try:
            return _list_adapter(model).validate_python(resp.json())
        except (ValueError, ValidationError):
            raise AdminApiError(
                resp.status_code, ReasonCode.UPSTREAM_ERROR, "unexpected response"
            ) from None

    @staticmethod
    def _id(value: str) -> str:
        """Encode an id as ONE path segment. '/' is percent-encoded, but '.' and '..' would
        still be resolved as dot segments by httpx and change the endpoint, so refuse them."""
        if value in ("", ".", ".."):
            raise ValueError("invalid id")
        return quote(value, safe="")

    # ------------------------------------------------------------------ reads
    def agents(self) -> list[AgentRecord]:
        return self._parse_list(self._request("GET", "/admin/agents"), AgentRecord)

    def tokens(self) -> list[ActiveTokenView]:
        return self._parse_list(self._request("GET", "/admin/tokens"), ActiveTokenView)

    def risk(self) -> list[RiskScore]:
        return self._parse_list(self._request("GET", "/admin/risk"), RiskScore)

    def approvals(self, status: str | None = None) -> list[ApprovalRecord]:
        params = {"status": status} if status else None
        resp = self._request("GET", "/admin/approvals", params=params)
        return self._parse_list(resp, ApprovalRecord)

    def audit(self, after_seq: int = -1, limit: int = 100) -> list[AuditRecord]:
        params = {"after_seq": after_seq, "limit": limit}
        return self._parse_list(self._request("GET", "/admin/audit", params=params), AuditRecord)

    def verify_audit(self) -> AuditVerifyResult:
        return self._parse(self._request("GET", "/admin/audit/verify"), AuditVerifyResult)

    # ------------------------------------------------------------------ actions
    def decide(
        self, approval_id: str, approver_id: str, approve: bool, totp_code: str
    ) -> ApprovalRecord:
        """Approve/deny. The human-typed TOTP code is mandatory and format-checked first."""
        body = ApprovalDecisionRequest(
            approver_id=approver_id, approve=approve, totp_code=check_totp_format(totp_code)
        )
        path = f"/approvals/{self._id(approval_id)}/decide"
        resp = self._request("POST", path, json=body.model_dump(mode="json"))
        return self._parse(resp, ApprovalRecord)

    def revoke_agent(self, agent_id: str) -> bool:
        """Kill switch: revokes every token of the agent. True once the CP confirmed it."""
        self._request("POST", f"/admin/agents/{self._id(agent_id)}/revoke")
        return True

    def clear_quarantine(self, agent_id: str) -> AgentRecord:
        resp = self._request("POST", f"/admin/agents/{self._id(agent_id)}/clear-quarantine")
        return self._parse(resp, AgentRecord)
