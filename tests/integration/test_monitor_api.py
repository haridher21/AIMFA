"""T4.1 endpoints: POST /internal/events (X-Internal-Secret) and GET /admin/risk (X-Admin-Key).

ASSUMPTIONS: /internal/events takes a RiskEvent JSON and returns a RiskScore JSON (200). Events for
an agent not in the registry are rejected with a 4xx (fail closed). Event timestamps are set from
the injected clock; decay uses the injected clock.
"""

from __future__ import annotations

import pytest


def event(h, event_type, agent="expense-bot", task="t1", **details):
    return {
        "agent_id": agent, "task_id": task, "event_type": event_type, "tool": "read_file",
        "timestamp": h.clock().isoformat(), "details": details,
    }  # fmt: skip


def post(h, body, headers=None):
    return h.cp.post(
        "/internal/events", json=body, headers=h.internal if headers is None else headers
    )


def risk_of(h, agent="expense-bot") -> dict:
    r = h.cp.get("/admin/risk", headers=h.admin)
    assert r.status_code == 200, r.text
    return next((s for s in r.json() if s["agent_id"] == agent), {"score": 0})


@pytest.mark.parametrize("headers", [{}, {"X-Internal-Secret": "wrong"}])
def test_internal_events_reject_missing_or_bad_secret(h, headers):
    h.onboard()
    r = post(h, event(h, "scope_denied"), headers)
    assert (r.status_code, r.json()["reason_code"]) == (401, "UNAUTHORIZED")
    assert risk_of(h)["score"] == 0


@pytest.mark.parametrize("headers", [{}, {"X-Admin-Key": "wrong"}])
def test_admin_risk_rejects_missing_or_bad_key(h, headers):
    r = h.cp.get("/admin/risk", headers=headers)
    assert (r.status_code, r.json()["reason_code"]) == (401, "UNAUTHORIZED")


def test_event_returns_risk_score_and_admin_risk_lists_it(h):
    h.onboard()
    r = post(h, event(h, "scope_denied"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["agent_id"] == "expense-bot" and body["score"] == 30
    assert body["status"] == "active" and body["step_up_required"] is False
    assert risk_of(h)["score"] == 30


def test_event_with_unknown_field_or_agent_is_rejected(h):
    h.onboard()
    assert post(h, {**event(h, "scope_denied"), "evil": 1}).status_code == 422
    assert post(h, event(h, "scope_denied", agent="ghost-bot")).status_code >= 400


def test_score_decays_with_the_injected_clock(h):
    h.onboard()
    post(h, event(h, "out_of_profile"))
    h.clock.advance(120)
    assert risk_of(h)["score"] == pytest.approx(40)


def test_crossing_80_quarantines_and_blocks_attest_and_token(h):
    key, ident = h.onboard()
    post(h, event(h, "out_of_profile"))
    r = post(h, event(h, "scope_denied"))
    assert r.json()["status"] == "quarantined"

    a = h.attest("expense-bot")
    assert (a.status_code, a.json()["reason_code"]) == (403, "AGENT_QUARANTINED")
    t = h.request_token(key, ident, ["files:read:/expenses/*"])
    assert (t.status_code, t.json()["reason_code"]) == (403, "AGENT_QUARANTINED")
    h.assert_audited("AGENT_QUARANTINED")


def test_clear_quarantine_resets_risk_score_to_zero(h):
    h.onboard()
    post(h, event(h, "out_of_profile"))
    post(h, event(h, "scope_denied"))
    assert risk_of(h)["score"] >= 80
    r = h.cp.post("/admin/agents/expense-bot/clear-quarantine", headers=h.admin)
    assert r.status_code == 200, r.text
    assert risk_of(h)["score"] == 0
    # and the agent is not immediately re-quarantined by one small event
    # CONTRACTS: clear-quarantine sets status -> registered (agent must re-attest)
    assert post(h, event(h, "dpop_failure")).json()["status"] == "registered"
