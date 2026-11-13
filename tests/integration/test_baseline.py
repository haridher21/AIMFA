"""T3.2 baseline mode: static X-API-Key only (intentionally weak). Same stack wiring."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aimfa.common.models import Mode
from tests.integration.conftest import BASELINE_KEY, Harness, Stack, reason_of

SECRETS = {"tool": "read_file", "args": {"path": "/engineering/secrets.env"}}


@pytest.fixture
def base(settings, clock) -> TestClient:
    s = settings.model_copy(update={"aimfa_mode": Mode.BASELINE})
    return Stack(Harness(s, clock), s, clock).gw


def test_health_reports_baseline_mode(base):
    assert base.get("/health").json() == {"status": "ok", "mode": "baseline"}


def test_correct_key_reads_out_of_scope_secret(base):
    r = base.post("/tool", json=SECRETS, headers={"X-API-Key": BASELINE_KEY})
    assert r.status_code == 200, r.text
    assert "FAKE" in r.json()["result"]["content"]


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "wrong-key-value-1"}, {"X-API-Key": ""}])
def test_wrong_or_missing_key_is_401(base, headers):
    r = base.post("/tool", json=SECRETS, headers=headers)
    assert (r.status_code, reason_of(r)) == (401, "BASELINE_API_KEY_INVALID")


def test_api_key_alone_is_not_accepted_in_aimfa_mode(stack):
    r = stack.gw.post("/tool", json=SECRETS, headers={"X-API-Key": BASELINE_KEY})
    assert (r.status_code, reason_of(r)) == (401, "TOKEN_MISSING")
