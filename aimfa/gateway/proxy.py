"""Turn an authorized tool call into a request to the mock resources.

``TOOL_ROUTES`` is the ONLY place a tool name becomes a URL. Every path starts with a fixed
prefix (``/files``, ``/email``, ``/bank``, ``/db``), so no tool, and no argument, can
reach ``/admin/*`` on the resources server. Requests are built from the NORMALIZED arguments
the policy engine produced (AGENTS.md rule 7): what was authorized is what is accessed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from aimfa.common.config import Settings
from aimfa.common.http import ApiError
from aimfa.common.models import ReasonCode


@dataclass(frozen=True)
class ResourceRequest:
    method: str
    path: str  # relative to the resources base URL
    params: dict[str, str] | None = None
    json: dict[str, Any] | None = None


def _files_path(args: dict[str, Any]) -> str:
    # The normalized path starts with "/"; quote() keeps "/" and escapes everything else.
    return "/files" + quote(args["path"], safe="/")


def _pick(args: dict[str, Any], *names: str) -> dict[str, Any]:
    return {n: args[n] for n in names}


# tool name -> how to build the resource request from the NORMALIZED args.
TOOL_ROUTES: dict[str, Callable[[dict[str, Any]], ResourceRequest]] = {
    "list_files": lambda a: ResourceRequest("GET", "/files", params={"dir": a["dir"]}),
    "read_file": lambda a: ResourceRequest("GET", _files_path(a)),
    "write_file": lambda a: ResourceRequest("PUT", _files_path(a), json=_pick(a, "content")),
    "send_email": lambda a: ResourceRequest(
        "POST", "/email/send", json=_pick(a, "to", "subject", "body")
    ),
    "wire_transfer": lambda a: ResourceRequest(
        "POST", "/bank/wire", json=_pick(a, "to_account", "amount", "memo")
    ),
    "query_db": lambda a: ResourceRequest("GET", "/db/" + quote(a["table"], safe="")),
    "delete_table": lambda a: ResourceRequest("DELETE", "/db/" + quote(a["table"], safe="")),
}


def build_request(tool: str, normalized_args: dict[str, Any]) -> ResourceRequest:
    """Map a tool to its resource call. A tool with no route is refused (fail closed)."""
    route = TOOL_ROUTES.get(tool)
    if route is None:
        raise ApiError(403, ReasonCode.ACTION_FORBIDDEN, "tool has no resource route")
    try:
        return route(normalized_args)
    except KeyError:
        raise ApiError(422, ReasonCode.INVALID_ARGUMENTS, "missing argument") from None


def send(http: httpx.Client, settings: Settings, request: ResourceRequest) -> dict[str, Any]:
    """Call the resource with ``X-Gateway-Secret`` and return its JSON object.

    Any failure (network, non-2xx, non-JSON) becomes a bare 502 UPSTREAM_ERROR: the
    resource's error body is never echoed to the agent, and neither is our secret.
    """
    headers = {"X-Gateway-Secret": settings.gateway_resource_secret.get_secret_value()}
    try:
        resp = http.request(
            request.method, request.path, params=request.params, json=request.json, headers=headers
        )
        if resp.status_code >= 300:
            raise ApiError(502, ReasonCode.UPSTREAM_ERROR, "resource request failed")
        body = resp.json()
    except httpx.HTTPError:
        raise ApiError(502, ReasonCode.UPSTREAM_ERROR, "resource unavailable") from None
    except ValueError:
        raise ApiError(502, ReasonCode.UPSTREAM_ERROR, "resource sent a bad reply") from None
    if not isinstance(body, dict):
        raise ApiError(502, ReasonCode.UPSTREAM_ERROR, "resource sent a bad reply")
    return body
