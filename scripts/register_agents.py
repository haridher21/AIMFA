"""Register the launcher and every manifest'd agent (with its golden measurement).

Uses the control plane admin API. Re-running is safe: HTTP 409 means "already registered".
The admin key is read from settings and only ever sent in the X-Admin-Key header.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx

from aimfa.agents.launcher import (
    LAUNCHER_ID,
    MANIFEST_DIR,
    load_manifest,
    load_or_create_launcher_key,
    measure_agent,
)
from aimfa.common.config import REPO_ROOT, Settings
from aimfa.common.crypto import public_jwk
from aimfa.common.models import AgentRegistration, LauncherRegistration

DEFAULT_APPROVER_ID = "approver"  # shared with run_demo.py so both enroll/register the same human


def _register(http: httpx.Client, path: str, body: dict, headers: dict, label: str) -> bool:
    resp = http.post(path, json=body, headers=headers)
    if resp.status_code == 201:
        print(f"registered {label}")
    elif resp.status_code == 409:
        print(f"already registered: {label}")
    else:
        # Error bodies are ErrorResponse (reason code + message, never secrets): show why.
        try:
            err = resp.json()
            why = f" {err.get('reason_code', '')}: {err.get('message', '')}"
        except (ValueError, AttributeError):
            why = ""
        print(f"FAILED {label}: HTTP {resp.status_code}{why}", file=sys.stderr)
        return False
    return True


def main(
    argv: list[str] | None = None,
    *,
    http: httpx.Client | None = None,
    settings: Settings | None = None,
    root: Path = REPO_ROOT,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approver", default=DEFAULT_APPROVER_ID)
    parser.add_argument("--manifest-dir", type=Path, default=MANIFEST_DIR)
    parser.add_argument("--skip-missing", action="store_true")
    args = parser.parse_args(argv)

    settings = settings or Settings()
    headers = {"X-Admin-Key": settings.admin_api_key.get_secret_value()}
    client = http or httpx.Client(base_url=settings.control_plane_url, timeout=15.0)

    launcher_key = load_or_create_launcher_key(settings)
    launcher = LauncherRegistration(
        launcher_id=LAUNCHER_ID, public_jwk=public_jwk(launcher_key)
    ).model_dump(mode="json")
    ok = _register(client, "/admin/launchers", launcher, headers, f"launcher {LAUNCHER_ID}")

    for path in sorted(args.manifest_dir.glob("*.yaml")):
        manifest = load_manifest(path)
        try:
            golden = measure_agent(manifest, root=root)
        except OSError as exc:
            if not args.skip_missing:
                print(f"FAILED {manifest.agent_id}: code file missing ({exc.filename})")
                ok = False
            else:
                print(f"skipping {manifest.agent_id}: code file not found yet")
            continue
        except ValueError as exc:  # path escapes the repo, or listed twice: a bad manifest
            print(f"FAILED {manifest.agent_id}: bad code_paths ({exc})")
            ok = False
            continue
        body = AgentRegistration(
            agent_id=manifest.agent_id,
            role=manifest.role,
            golden_measurement=golden,
            launcher_id=LAUNCHER_ID,
            approver_id=args.approver,
            description=manifest.description,
        ).model_dump(mode="json")
        ok = _register(client, "/admin/agents", body, headers, f"agent {manifest.agent_id}") and ok
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
