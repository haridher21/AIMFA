"""Browser-facing safety for the dashboard: CSRF check, security headers, safe error text.

Why this exists: the dashboard is a normal web app on 127.0.0.1, and a browser happily lets
ANY website you visit send requests to localhost. These checks make sure only our own pages
can press our buttons, that our pages can't be framed or injected into, and that error
messages never echo secrets. Pure functions, so they are unit-testable without a server.
"""

from __future__ import annotations

import hmac
from collections.abc import Iterable
from urllib.parse import urlparse

from aimfa.dashboard.admin_client import AdminApiError, ControlPlaneUnavailable, InvalidTotpCode
from aimfa.dashboard.views import redact

# Hosts the server answers to. Anything else (e.g. evil.example pointed at 127.0.0.1 by
# DNS rebinding) is refused before a route runs.
ALLOWED_HOSTS = ("127.0.0.1", "localhost")

# Only our own files may run or style the page; no framing (clickjacking); no plugins.
CSP = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    )
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def allowed_origins(dashboard_url: str) -> set[str]:
    """The browser origins our own pages have (127.0.0.1 and localhost, same port)."""
    parsed = urlparse(dashboard_url)
    port = f":{parsed.port}" if parsed.port else ""
    return {f"{parsed.scheme}://{host}{port}" for host in ALLOWED_HOSTS}


def csrf_ok(
    token: str | None,
    expected: str,
    origin: str | None,
    fetch_site: str | None,
    origins: Iterable[str],
) -> bool:
    """May this state-changing request run? Fail closed.

    Our pages send a secret token (from a <meta> tag) in the ``X-CSRF-Token`` header. Another
    website can neither read that token nor set a custom header on a cross-site request, so a
    forged "revoke" or "clear quarantine" click fails. When the browser tells us where the
    request came from (``Origin``, ``Sec-Fetch-Site``), that must be us too.
    """
    if not token or not expected:
        return False
    if not hmac.compare_digest(token.encode("utf-8", "surrogatepass"), expected.encode()):
        return False
    if origin is not None and origin not in set(origins):
        return False
    return fetch_site is None or fetch_site == "same-origin"


def describe_error(err: Exception, secrets_: Iterable[str]) -> tuple[str, str]:
    """(kind, text) for showing a failed API call. Never a traceback, header or secret."""
    if isinstance(err, ControlPlaneUnavailable):
        return "warning", "Control plane is not reachable. Is scripts/run_demo.py running?"
    if isinstance(err, AdminApiError):
        msg = f"Control plane refused: {err.reason_code.value} (HTTP {err.status})"
        return "error", redact(msg, secrets_)
    if isinstance(err, InvalidTotpCode):
        return "error", str(err)
    if isinstance(err, ValueError):
        # e.g. a pydantic ValidationError: its text can echo input values, so show none.
        return "error", "Invalid input or configuration; nothing was sent."
    return "error", f"Unexpected error ({type(err).__name__})."
