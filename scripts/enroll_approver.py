"""Enroll a human approver: shows the TOTP secret ONCE as a QR code for their phone.

Run with the control plane up:  python scripts/enroll_approver.py alice-approver
Scan the QR with an authenticator app (Google Authenticator, Aegis, ...). The secret is
never shown again, so treat the terminal output and the PNG as secret. The admin key is
read from settings and is never printed.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import sys
from pathlib import Path

import httpx
import qrcode
from pydantic import SecretStr

from aimfa.common.config import Settings, get_settings
from aimfa.common.models import ApproverEnrollment

QR_BORDER = 2


def render_qr(uri: str) -> str:
    """The QR as text, two characters per module, for a dark-background terminal.

    Light modules are full blocks and dark modules are spaces, so a dark terminal shows the
    code in the polarity phone cameras expect. Pure Python: no network, no image library.
    """
    qr = qrcode.QRCode(border=QR_BORDER, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(uri)
    qr.make(fit=True)
    return "\n".join("".join("  " if dark else "██" for dark in row) for row in qr.get_matrix())


def save_qr_png(uri: str, path: Path | str) -> None:
    """Save the QR as a PNG (owner-only permissions where the OS supports it)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    qrcode.make(uri, border=QR_BORDER).save(str(target))
    with contextlib.suppress(OSError):  # best effort: Windows ignores most mode bits
        os.chmod(target, 0o600)


def _secret_text(value: SecretStr | str) -> str:
    """Settings holds secrets as SecretStr; accept a plain str too (e.g. a test override)."""
    return value.get_secret_value() if isinstance(value, SecretStr) else value


def enroll(http: httpx.Client, settings: Settings, approver_id: str) -> str:
    """Create the approver on the control plane; returns the otpauth provisioning URI."""
    resp = http.post(
        settings.control_plane_url + "/admin/approvers",
        json={"approver_id": approver_id},
        headers={"X-Admin-Key": _secret_text(settings.admin_api_key)},
    )
    if resp.status_code != 201:
        # Only the status: the body and headers are not echoed.
        raise RuntimeError(f"enrollment failed (HTTP {resp.status_code})")
    return ApproverEnrollment.model_validate(resp.json()).provisioning_uri


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enroll an AIMFA approver (TOTP).")
    parser.add_argument("approver_id")
    parser.add_argument("--png", type=Path, help="where to save the QR PNG (default: var/)")
    args = parser.parse_args(argv)

    settings = get_settings()
    png = args.png or settings.data_dir / f"approver-{args.approver_id}.png"
    with httpx.Client(timeout=10.0) as http:
        try:
            uri = enroll(http, settings, args.approver_id)
        except (RuntimeError, httpx.HTTPError, ValueError) as err:
            print(f"error: {type(err).__name__}: {err}" if str(err) else "error", file=sys.stderr)
            return 1
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8")
    print(render_qr(uri))
    print(f"\nManual entry URI (shown once): {uri}")
    save_qr_png(uri, png)
    print(f"QR saved to {png} (secret: delete it after scanning)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
