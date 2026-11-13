"""One-command demo runner: starts every service, waits for health, registers agents.

    python scripts/run_demo.py --reset            # fresh demo (wipes var/, keeps keys/)
    python scripts/run_demo.py --mode baseline    # "the old way", for attack comparison

Ctrl+C stops everything. Services always bind 127.0.0.1 so nothing is reachable from the
network the laptop is on. Secrets are checked first and are never printed.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess  # noqa: S404 - launching our own services, list argv, no shell
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:  # so `scripts.*` imports work when run as a script
    sys.path.insert(0, str(REPO_ROOT))

from aimfa.common.config import Settings  # noqa: E402
from scripts import enroll_approver, register_agents  # noqa: E402

HOST = "127.0.0.1"  # hard-coded on purpose: never 0.0.0.0
LOCAL_HOSTS = {"127.0.0.1", "localhost"}
MIN_SECRET_LENGTH = 16
HEALTH_TIMEOUT_SECONDS = 30.0
HEALTH_POLL_SECONDS = 0.5
STOP_WAIT_SECONDS = 5
DASHBOARD_APP = REPO_ROOT / "aimfa" / "dashboard" / "app.py"

Service = tuple[str, list[str], str]  # (name, argv, health_url)


def check_secrets(settings: Settings) -> list[str]:
    """Names of settings still holding a default (``change-me*``) or too-short secret.

    The defaults are public in the repo, so running with them lets anyone call the admin
    API. Returns names only, never values.
    """
    named = {
        "admin_api_key": settings.admin_api_key,
        "internal_service_secret": settings.internal_service_secret,
        "gateway_resource_secret": settings.gateway_resource_secret,
        "baseline_api_key": settings.baseline_api_key,
    }
    bad = []
    for name, secret in named.items():
        value = secret.get_secret_value()
        if value.startswith("change-me") or len(value) < MIN_SECRET_LENGTH:
            bad.append(name)
    return bad


def _urls(settings: Settings) -> dict[str, str]:
    return {
        "control_plane_url": settings.control_plane_url,
        "gateway_url": settings.gateway_url,
        "resources_url": settings.resources_url,
        "dashboard_url": settings.dashboard_url,
    }


def check_localhost(settings: Settings) -> list[str]:
    """Names of service URL settings whose host is not localhost (we refuse to expose)."""
    return [
        name for name, url in _urls(settings).items() if urlparse(url).hostname not in LOCAL_HOSTS
    ]


def _port(url: str) -> int:
    port = urlparse(url).port
    if port is None:
        raise ValueError(f"no port in {url!r}")
    return port


def service_commands(settings: Settings, mode: str) -> list[Service]:
    """The processes to launch. ``mode`` is passed to children via AIMFA_MODE (see main)."""
    del mode  # applied through the child environment, kept here for a uniform signature
    py = sys.executable
    services: list[Service] = []
    for name, module, url in (
        ("control-plane", "aimfa.control_plane.app", settings.control_plane_url),
        ("gateway", "aimfa.gateway.app", settings.gateway_url),
        ("resources", "aimfa.resources.app", settings.resources_url),
    ):
        port = _port(url)
        argv = [py, "-m", "uvicorn", f"{module}:app_factory", "--factory"]
        argv += ["--host", HOST, "--port", str(port)]
        services.append((name, argv, f"http://{HOST}:{port}/health"))
    if DASHBOARD_APP.exists():
        port = _port(settings.dashboard_url)
        argv = [py, "-m", "streamlit", "run", str(DASHBOARD_APP)]
        argv += ["--server.address", HOST, "--server.port", str(port)]
        argv += ["--server.headless", "true", "--browser.gatherUsageStats", "false"]
        services.append(("dashboard", argv, f"http://{HOST}:{port}/_stcore/health"))
    return services


RESETTABLE_DIRS = ("var", "keys")


def safe_reset(path: Path, *, repo_root: Path = REPO_ROOT) -> None:
    """Delete ``<repo>/var`` or ``<repo>/keys``, and nothing else.

    An allow-list of exact paths, not "anything inside the repo": a typo such as
    ``DATA_DIR=aimfa`` or ``DATA_DIR=.git`` must never turn ``--reset`` into ``rm -rf`` of
    source code, and a ``var`` folder elsewhere on disk is not ours to delete. A symlink is
    refused because it could point anywhere.
    """
    root = repo_root.resolve()
    allowed = {root / name for name in RESETTABLE_DIRS}
    if path.is_symlink() or path.resolve() not in allowed:
        raise ValueError(f"refusing to delete {path.resolve()} (only <repo>/var or <repo>/keys)")
    target = path.resolve()
    if target.exists():
        shutil.rmtree(target)


def wait_healthy(url: str, *, timeout: float = HEALTH_TIMEOUT_SECONDS) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(url, timeout=2.0).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(HEALTH_POLL_SECONDS)
    return False


def stop_all(procs: list[subprocess.Popen]) -> None:
    """Terminate, wait, then kill stragglers. Uses no POSIX-only signals (works on Windows)."""
    for proc in procs:
        if proc.poll() is None:
            proc.terminate()
    for proc in procs:
        try:
            proc.wait(timeout=STOP_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            proc.kill()


def _enroll_approver(settings: Settings) -> bool:
    """Enroll the demo approver; 409 means already enrolled. QR is printed once only."""
    with httpx.Client(timeout=10.0) as http:
        try:
            uri = enroll_approver.enroll(http, settings, register_agents.DEFAULT_APPROVER_ID)
        except RuntimeError as err:
            if "HTTP 409" in str(err):
                print("approver already enrolled")
                return True
            print(f"approver enrollment failed: {err}", file=sys.stderr)
            return False
    print(enroll_approver.render_qr(uri))
    print(f"\nManual entry URI (shown once): {uri}")
    return True


def main(argv: list[str] | None = None, *, settings: Settings | None = None) -> int:
    parser = argparse.ArgumentParser(description="Start the whole AIMFA demo.")
    parser.add_argument("--mode", choices=["aimfa", "baseline"], default="aimfa")
    parser.add_argument("--reset", action="store_true", help="wipe var/ before starting")
    parser.add_argument("--reset-keys", action="store_true", help="also wipe keys/")
    args = parser.parse_args(argv)
    settings = settings or Settings()

    bad = check_secrets(settings)
    if bad:
        print("Refusing to start: these settings are default or shorter than 16 chars:")
        for name in bad:
            print(f"  - {name.upper()}")
        print("Generate one with:")
        print('  python -c "import secrets; print(secrets.token_urlsafe(32))"')
        return 2
    not_local = check_localhost(settings)
    if not_local:
        print(f"Refusing to start: non-localhost URL in {', '.join(not_local)}", file=sys.stderr)
        return 2

    # New keys mean a new launcher identity, so the old registrations in var/ must go too;
    # otherwise registration says "already registered" and every attestation then fails.
    if args.reset or args.reset_keys:
        safe_reset(settings.data_dir)
    if args.reset_keys:
        safe_reset(settings.keys_dir)

    if not DASHBOARD_APP.exists():
        print("note: aimfa/dashboard/app.py not found yet (T7.1); skipping Streamlit")
    env = {**os.environ, "AIMFA_MODE": args.mode}
    procs: list[subprocess.Popen] = []
    try:
        for name, cmd, health in service_commands(settings, args.mode):
            print(f"starting {name} ...")
            procs.append(subprocess.Popen(cmd, env=env, cwd=REPO_ROOT))  # noqa: S603 - fixed argv built by service_commands
            if not wait_healthy(health):
                print(f"{name} did not become healthy; stopping", file=sys.stderr)
                return 1
        if args.mode == "aimfa":
            # Approver first: every agent names its approver, and the control plane rejects
            # an agent whose approver does not exist yet (422 "unknown approver").
            if not _enroll_approver(settings):
                return 1
            if register_agents.main(["--skip-missing"], settings=settings) != 0:
                print("registration failed; stopping", file=sys.stderr)
                return 1
        print(f"\nAIMFA demo running ({args.mode}). Dashboard: {settings.dashboard_url}")
        print("Press Ctrl+C to stop.")
        while all(p.poll() is None for p in procs):
            time.sleep(1)
        print("a service exited; stopping", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nstopping ...")
        return 0
    finally:
        stop_all(procs)


if __name__ == "__main__":
    raise SystemExit(main())
