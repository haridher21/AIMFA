"""Gateway app factory (:8100): the single door every agent tool call goes through.

The route handlers here are thin on purpose: all security decisions live in ``pipeline.py``
(AIMFA mode) or ``baseline.py`` (the intentionally weak comparison mode).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse

from aimfa.common.config import Settings, get_settings
from aimfa.common.dpop import ReplayCache
from aimfa.common.http import install_error_handling, require_strong_secrets
from aimfa.common.models import Mode, ToolCallResponse
from aimfa.common.policy import Policy
from aimfa.gateway.baseline import baseline_tool_call
from aimfa.gateway.cp_client import ControlPlaneClient, HttpControlPlaneClient
from aimfa.gateway.pipeline import (
    ControlPlaneMonitor,
    GatewayContext,
    RiskMonitor,
    process_tool_call,
    utc_now,
)

UPSTREAM_TIMEOUT_SECONDS = 10.0


async def raw_body(request: Request) -> bytes:
    """Read the body ourselves so a malformed one is audited like any other denial."""
    return await request.body()


def _json(status: int, body: ToolCallResponse) -> JSONResponse:
    return JSONResponse(body.model_dump(mode="json"), status_code=status)


def create_app(
    settings: Settings,
    *,
    control_plane_client: ControlPlaneClient | None = None,
    resources_http: httpx.Client | None = None,
    monitor: RiskMonitor | None = None,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    """Build the gateway. Anything not injected is created from ``settings``."""
    require_strong_secrets(settings)
    if control_plane_client is None:
        control_plane_client = HttpControlPlaneClient(
            httpx.Client(base_url=settings.control_plane_url, timeout=UPSTREAM_TIMEOUT_SECONDS),
            settings,
        )
    if resources_http is None:
        resources_http = httpx.Client(
            base_url=settings.resources_url, timeout=UPSTREAM_TIMEOUT_SECONDS
        )
    ctx = GatewayContext(
        settings=settings,
        policy=Policy.load(settings.policy_dir),
        cp=control_plane_client,
        resources=resources_http,
        monitor=monitor or ControlPlaneMonitor(control_plane_client),
        replay=ReplayCache(settings.dpop_max_age_seconds),
        clock=clock or utc_now,
    )

    app = FastAPI(title="AIMFA gateway")
    install_error_handling(app)
    mode = settings.aimfa_mode

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": mode.value}

    if mode is Mode.BASELINE:

        @app.post("/tool")
        def tool_baseline(
            request: Request,
            raw: Annotated[bytes, Depends(raw_body)],
            x_api_key: Annotated[str | None, Header()] = None,
        ) -> JSONResponse:
            status, body = baseline_tool_call(ctx, raw, x_api_key, request.state.request_id)
            return _json(status, body)

    else:

        @app.post("/tool")
        def tool_aimfa(
            request: Request,
            raw: Annotated[bytes, Depends(raw_body)],
            authorization: Annotated[str | None, Header()] = None,
            dpop: Annotated[str | None, Header()] = None,
        ) -> JSONResponse:
            status, body = process_tool_call(
                ctx, raw, authorization, dpop, request.state.request_id
            )
            return _json(status, body)

    return app


def app_factory() -> FastAPI:
    """Zero-arg entry point for ``uvicorn --factory`` (settings come from .env)."""
    return create_app(get_settings())
