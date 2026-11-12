"""Mock company systems (:8200). Thin FastAPI routes over ``ResourceStore``.

The only way in is the gateway, which holds ``X-Gateway-Secret``. Agents never see that
secret, so an agent that skips the gateway is turned away here with 403.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, Header, Query, Response
from pydantic import BaseModel, ConfigDict, Field

from aimfa.common.config import Settings
from aimfa.common.http import (
    ApiError,
    install_error_handling,
    require_strong_secrets,
    secret_matches,
)
from aimfa.common.models import ReasonCode
from aimfa.common.policy import PolicyError, validate_table
from aimfa.resources.store import ResourceStore


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FileWrite(_Body):
    content: str = Field(max_length=1_000_000)


class EmailSend(_Body):
    to: str = Field(min_length=3, max_length=254)
    subject: str = Field(max_length=300)
    body: str = Field(max_length=100_000)


class WireRequest(_Body):
    to_account: str = Field(pattern=r"^[A-Za-z0-9-]{3,34}$")
    amount: float = Field(gt=0, le=10_000_000, allow_inf_nan=False)
    memo: str = Field(default="", max_length=200)


def create_app(settings: Settings) -> FastAPI:
    """Build the app. Startup (directories, seed data) is eager so tests need no lifespan."""
    require_strong_secrets(settings)
    store = ResourceStore(settings)
    app = FastAPI(title="AIMFA mock resources")
    install_error_handling(app)

    def require_gateway(
        x_gateway_secret: Annotated[str | None, Header()] = None,
    ) -> None:
        """Rule 9: refuse anything that did not come through the gateway."""
        if not secret_matches(x_gateway_secret, settings.gateway_resource_secret):
            raise ApiError(403, ReasonCode.UNAUTHORIZED, "gateway secret required")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    guarded = APIRouter(dependencies=[Depends(require_gateway)])

    @guarded.get("/files")
    def list_files(dir: Annotated[str, Query(max_length=1024)]) -> dict:  # noqa: A002
        return store.list_dir(dir)

    @guarded.get("/files/{path:path}")
    def read_file(path: str) -> dict:
        return store.read_file("/" + path)

    @guarded.put("/files/{path:path}")
    def write_file(path: str, body: FileWrite) -> dict:
        return store.write_file("/" + path, body.content)

    @guarded.post("/email/send")
    def send_email(body: EmailSend) -> dict:
        return store.send_email(body.to, body.subject, body.body)

    @guarded.post("/bank/wire")
    def wire(body: WireRequest) -> dict:
        return store.wire(body.amount)

    @guarded.get("/db/{table}")
    def read_table(table: str) -> dict:
        return store.read_table(_table(table))

    @guarded.delete("/db/{table}")
    def delete_table(table: str) -> dict:
        return store.delete_table(_table(table))

    @guarded.post("/admin/reset", status_code=204)
    def reset() -> Response:
        store.reset()
        return Response(status_code=204)

    app.include_router(guarded)
    return app


def _table(raw: str) -> str:
    """Table names must be plain identifiers before we even look them up."""
    try:
        return validate_table(raw)
    except PolicyError:
        raise ApiError(400, ReasonCode.INVALID_ARGUMENTS, "invalid table name") from None
