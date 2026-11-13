"""T7.1 smoke test: pages render with the control plane unreachable, without leaking the key."""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

import aimfa.dashboard as dashboard

DASH = Path(dashboard.__file__).parent
KEY = "smoke-test-admin-key-should-never-render"


@pytest.fixture
def dead_cp(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", KEY)
    monkeypatch.setenv("CONTROL_PLANE_URL", "http://127.0.0.1:9")  # discard port: refused


@pytest.mark.parametrize(
    "script",
    [
        "app.py",
        "pages/1_Agents.py",
        "pages/2_Tokens.py",
        "pages/3_Risk.py",
        "pages/4_Approvals.py",
        "pages/5_Audit.py",
    ],
)
def test_pages_render_friendly_error_when_cp_down(dead_cp, script):
    at = AppTest.from_file(str(DASH / script), default_timeout=20).run()
    assert not at.exception
    assert any("not reachable" in w.value for w in at.warning)
    rendered = " ".join(str(el.value) for el in [*at.warning, *at.error, *at.markdown, *at.title])
    assert KEY not in rendered


def test_attack_lab_renders_and_states_isolation(dead_cp):
    at = AppTest.from_file(str(DASH / "pages/6_Attack_Lab.py"), default_timeout=20).run()
    assert not at.exception
    assert any("OWN throwaway" in i.value for i in at.info)
    assert len(at.button) == 10  # A1-A9 + Run all
