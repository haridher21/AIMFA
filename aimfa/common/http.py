"""Shared HTTP plumbing for the AIMFA services: one error shape and one secret check.

Every non-2xx body is an ``ErrorResponse`` with a specific ``ReasonCode`` (AGENTS.md), so
clients and tests can tell failures apart without parsing English messages.
"""

from __future__ import annotations

import hmac
import secrets

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import SecretStr
from starlette.exceptions import HTTPException as StarletteHTTPException

from aimfa.common.config import Settings
from aimfa.common.models import ErrorResponse, ReasonCode


class ApiError(Exception):
    """Raise from any handler to produce an ``ErrorResponse`` with this status/reason."""

    def __init__(self, status: int, reason_code: ReasonCode, message: str = "") -> None:
        super().__init__(reason_code.value)
        self.status = status
        self.reason_code = reason_code
        self.message = message


def secret_matches(provided: str | None, expected: SecretStr) -> bool:
    """Constant-time check of a shared secret from a header.

    A normal ``==`` stops at the first wrong character, so response timing would leak how
    much of a guess was right. ``hmac.compare_digest`` takes the same time either way. We
    compare UTF-8 bytes because compare_digest refuses non-ASCII ``str``. A missing or empty
    header never matches, even if the configured secret were empty (fail closed).
    """
    want = expected.get_secret_value().encode("utf-8")
    if not provided or not want:
        return False
    return hmac.compare_digest(provided.encode("utf-8", "surrogatepass"), want)


MIN_SECRET_LENGTH = 12


def require_strong_secrets(settings: Settings) -> None:
    """Refuse to start with placeholder or short shared secrets.

    The shipped defaults (``change-me-*``) are public, so a service running with them would
    accept anyone who read the repo. Raises ``ValueError`` (never logs the secret).
    """
    named = {
        "ADMIN_API_KEY": settings.admin_api_key,
        "INTERNAL_SERVICE_SECRET": settings.internal_service_secret,
        "GATEWAY_RESOURCE_SECRET": settings.gateway_resource_secret,
    }
    for name, secret in named.items():
        value = secret.get_secret_value()
        if value.startswith("change-me") or len(value) < MIN_SECRET_LENGTH:
            raise ValueError(f"{name} is a default or too short; set a strong value in .env")


def _error(request: Request, status: int, code: ReasonCode, message: str) -> JSONResponse:
    body = ErrorResponse(
        reason_code=code, message=message, request_id=getattr(request.state, "request_id", None)
    )
    return JSONResponse(body.model_dump(mode="json"), status_code=status)


def install_error_handling(app: FastAPI) -> None:
    """Add request ids and map every failure to an ``ErrorResponse``."""

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):  # noqa: ANN001, ANN202
        request.state.request_id = secrets.token_hex(8)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return _error(request, exc.status, exc.reason_code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Do not echo exc.errors(): it contains the rejected input, which may be a secret.
        return _error(request, 422, ReasonCode.INVALID_ARGUMENTS, "request failed validation")

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _error(request, exc.status_code, ReasonCode.INVALID_ARGUMENTS, "request not served")
