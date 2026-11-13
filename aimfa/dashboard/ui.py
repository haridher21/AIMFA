"""Streamlit glue shared by the pages: setup, client, safe error display, refresh interval.

Kept tiny; all logic worth testing lives in ``admin_client`` and ``views``.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, TypeVar

import streamlit as st

from aimfa.common.config import REPO_ROOT, Settings
from aimfa.dashboard.admin_client import (
    AdminApiError,
    AdminClient,
    ControlPlaneUnavailable,
    InvalidTotpCode,
)
from aimfa.dashboard.views import redact, secret_values

REFRESH_SECONDS = 2.5
T = TypeVar("T")


def ensure_repo_root_on_path() -> None:
    """`streamlit run` puts the script dir on sys.path, not the repo root, so `import attacks`
    would fail. We add our own fixed repo root (never user input), appended so it can't
    shadow an installed package."""
    root = str(REPO_ROOT)
    if root not in sys.path:
        sys.path.append(root)


@st.cache_resource
def get_settings() -> Settings:
    return Settings()


@st.cache_resource
def _client() -> AdminClient:
    return AdminClient(get_settings())


def get_client() -> AdminClient:
    """Stop the page with a generic message on bad config (no pydantic input values shown)."""
    try:
        return _client()
    except ValueError:
        st.error("Dashboard configuration is invalid (check `.env`).")
        st.stop()
        raise  # unreachable: st.stop() raises


def now() -> datetime:
    return datetime.now(UTC)


def safe_text(text: str) -> str:
    return redact(text, secret_values(get_settings()))


def say(kind: str, text: str, sticky: str | None = None) -> None:
    """Show a message. With ``sticky``, keep it in session state so it survives the
    auto-refresh (otherwise a "wrong TOTP" error would vanish within seconds)."""
    if sticky:
        st.session_state[f"_flash_{sticky}"] = (kind, text)
    else:
        getattr(st, kind)(text)


def show_flash(sticky: str) -> None:
    item = st.session_state.get(f"_flash_{sticky}")
    if item:
        getattr(st, item[0])(item[1])


def guarded(fn: Callable[[], T], sticky: str | None = None) -> T | None:
    """Run an API call; show a friendly message (no traceback, no headers) on failure."""
    try:
        return fn()
    except ControlPlaneUnavailable:
        say("warning", "Control plane is not reachable. Is `scripts/run_demo.py` running?", sticky)
    except AdminApiError as err:
        msg = f"Control plane refused: {err.reason_code.value} (HTTP {err.status})"
        say("error", safe_text(msg), sticky)
    except InvalidTotpCode as err:
        say("error", str(err), sticky)
    except ValueError:
        # e.g. a pydantic ValidationError: its text can echo input values, so show none.
        say("error", "Invalid input or configuration; nothing was sent.", sticky)
    return None


def act(fn: Callable[[], Any], success: str, sticky: str) -> None:
    """Run a button action, remember its outcome, and redraw the fragment right away."""
    if guarded(fn, sticky):
        say("success", success, sticky)
    st.rerun(scope="fragment")


def page_setup(title: str) -> None:
    ensure_repo_root_on_path()
    st.set_page_config(page_title=f"AIMFA - {title}", layout="wide")
    st.title(title)


def show_table(rows: list[dict[str, Any]], empty: str = "Nothing to show.") -> None:
    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info(empty)
