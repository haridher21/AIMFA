"""How the gateway talks to the control plane (internal, secret-protected endpoints).

The gateway only needs five things from the control plane, so they are a small ``Protocol``.
Tests and in-process demos plug in any ``httpx``-compatible client (e.g. a FastAPI
``TestClient``); real runs use a client pointed at ``CONTROL_PLANE_URL``. Every request uses a
RELATIVE path (the client owns the base URL) and carries ``X-Internal-Secret``.
"""

from __future__ import annotations

from typing import Protocol, TypeVar
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ValidationError

from aimfa.common.config import Settings
from aimfa.common.models import (
    JWKS,
    ApprovalConsumeRequest,
    ApprovalCreate,
    ApprovalRecord,
    AuditAppend,
    ErrorResponse,
    IntrospectRequest,
    IntrospectResponse,
    ReasonCode,
)

_M = TypeVar("_M", bound=BaseModel)


class ControlPlaneError(Exception):
    """The control plane refused, or could not be reached. Never carries a secret.

    ``reason_code`` is the control plane's own code when it sent an ``ErrorResponse``, else
    ``UPSTREAM_ERROR``.
    """

    def __init__(self, status: int, reason_code: ReasonCode) -> None:
        super().__init__(f"{status} {reason_code.value}")
        self.status = status
        self.reason_code = reason_code


class ControlPlaneClient(Protocol):
    def jwks(self) -> JWKS: ...

    def introspect(self, req: IntrospectRequest) -> IntrospectResponse: ...

    def audit(self, entry: AuditAppend) -> None: ...

    def create_approval(self, req: ApprovalCreate) -> ApprovalRecord: ...

    def consume_approval(self, approval_id: str, req: ApprovalConsumeRequest) -> ApprovalRecord: ...


class HttpControlPlaneClient:
    """``ControlPlaneClient`` over HTTP. ``http`` must already know the control plane's URL."""

    def __init__(self, http: httpx.Client, settings: Settings) -> None:
        self._http = http
        self._headers = {"X-Internal-Secret": settings.internal_service_secret.get_secret_value()}

    def _send(self, method: str, path: str, body: dict | None = None) -> dict:
        try:
            resp = self._http.request(method, path, json=body, headers=self._headers)
        except httpx.HTTPError:
            raise ControlPlaneError(502, ReasonCode.UPSTREAM_ERROR) from None
        if resp.status_code >= 300:
            raise ControlPlaneError(resp.status_code, _reason_of(resp))
        try:
            data = resp.json()
        except ValueError:
            raise ControlPlaneError(502, ReasonCode.UPSTREAM_ERROR) from None
        if not isinstance(data, dict):
            raise ControlPlaneError(502, ReasonCode.UPSTREAM_ERROR)
        return data

    def _parse(self, model: type[_M], data: dict) -> _M:
        try:
            return model.model_validate(data)
        except ValidationError:
            # A reply that does not match the contract is never trusted.
            raise ControlPlaneError(502, ReasonCode.UPSTREAM_ERROR) from None

    def jwks(self) -> JWKS:
        return self._parse(JWKS, self._send("GET", "/.well-known/jwks.json"))

    def introspect(self, req: IntrospectRequest) -> IntrospectResponse:
        data = self._send("POST", "/internal/introspect", req.model_dump(mode="json"))
        return self._parse(IntrospectResponse, data)

    def audit(self, entry: AuditAppend) -> None:
        self._send("POST", "/internal/audit", entry.model_dump(mode="json"))

    def create_approval(self, req: ApprovalCreate) -> ApprovalRecord:
        data = self._send("POST", "/internal/approvals", req.model_dump(mode="json"))
        return self._parse(ApprovalRecord, data)

    def consume_approval(self, approval_id: str, req: ApprovalConsumeRequest) -> ApprovalRecord:
        # approval_id came from an agent: quote it so it can only ever be ONE path segment
        # (never "../admin/..." aimed at an internal route that carries our secret).
        path = f"/internal/approvals/{quote(approval_id, safe='')}/consume"
        return self._parse(ApprovalRecord, self._send("POST", path, req.model_dump(mode="json")))


def _reason_of(resp: httpx.Response) -> ReasonCode:
    """The control plane's ReasonCode from an error body, else UPSTREAM_ERROR."""
    try:
        return ErrorResponse.model_validate(resp.json()).reason_code
    except (ValueError, ValidationError):
        return ReasonCode.UPSTREAM_ERROR
