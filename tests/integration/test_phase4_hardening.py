"""Phase 4 hardening: per-approver lockout, pending-approval cap, bounded monitor."""

from __future__ import annotations

from datetime import timedelta

from aimfa.common.config import Settings
from aimfa.common.db import Database
from aimfa.common.models import AgentStatus, EventType, RiskEvent
from aimfa.common.policy import Policy
from aimfa.control_plane.audit import AuditLog
from aimfa.control_plane.monitor import RiskMonitor
from tests.integration.conftest import FakeClock, invalid_code, valid_code
from tests.integration.test_approval_routes import ARGS, Env
from tests.unit.test_monitor import Rig, ev


def test_wrong_codes_across_two_approvals_lock_the_approver(h):
    env = Env(h)
    a1, a2 = env.new_id(), env.new_id({**ARGS, "to": "other@evil.example"})
    bad = invalid_code(env.seed, h.clock())
    for aid in (a1, a1, a1, a2, a2):  # 5 wrong guesses in total, none reaching 5 on one id
        assert env.decide(aid, code=bad).status_code == 401
    # Even the correct code is refused now, on an approval that never had a wrong guess.
    r = env.decide(a2, code=valid_code(env.seed, h.clock()))
    assert (r.status_code, r.json()["reason_code"]) == (401, "APPROVAL_INVALID_TOTP")
    assert any(rec["event"] == "approval.approver_lockout" for rec in h.audit())
    h.clock.advance(11 * 60)  # window passed (the old approvals expired meanwhile)
    fresh = env.new_id({**ARGS, "to": "third@evil.example"})
    assert env.decide(fresh, code=valid_code(env.seed, h.clock())).status_code == 200


def test_fourth_pending_approval_is_refused_and_audited(h):
    env = Env(h)
    for i in range(3):
        env.new_id({**ARGS, "to": f"u{i}@evil.example"})
    r = env.create({**ARGS, "to": "u9@evil.example"})
    assert (r.status_code, r.json()["reason_code"]) == (429, "RATE_LIMITED")
    assert env.create({**ARGS, "to": "u0@evil.example"}).status_code == 200  # dedupe still works
    h.assert_audited("RATE_LIMITED")


def test_gateway_maps_a_refused_approval_to_403_rate_limited(stack):
    key, access, _ = stack.onboard_task("wire-bot", "finance_ops", ["email:send:external"])
    for i in range(3):
        mail = {"to": f"u{i}@evil.example", "subject": "s", "body": "b"}
        assert stack.call(key, access, "send_email", mail).status_code == 202
    r = stack.call(key, access, "send_email", {"to": "z@evil.example", "subject": "s", "body": "b"})
    assert (r.status_code, r.json()["reason_code"]) == (403, "RATE_LIMITED")


def test_quarantined_agent_events_are_not_stored(tmp_path):
    rig = Rig(tmp_path)
    rig.rec(EventType.OUT_OF_PROFILE)
    rig.rec(EventType.SCOPE_DENIED)  # 80: quarantined
    stored = len(rig.db.list_risk_events("agt1"))
    s = rig.rec(EventType.SCOPE_DENIED)
    assert s.status is AgentStatus.QUARANTINED
    assert len(rig.db.list_risk_events("agt1")) == stored


def test_events_outside_the_decay_horizon_are_ignored(tmp_path):
    settings = Settings(
        _env_file=None, data_dir=tmp_path / "d", keys_dir=tmp_path / "k", risk_decay_per_minute=5
    )
    clock, db = FakeClock(), Database(tmp_path / "other.db")
    rig = Rig(tmp_path)  # reuse its agent setup, but score with our own monitor/db below
    agent = rig.db.get_agent("agt1")
    db.add_agent(agent)
    old = clock() - timedelta(hours=2)  # far past 130 / 5 = 26 minutes
    db.add_risk_event(ev(EventType.OUT_OF_PROFILE, agent="agt1", at=old))
    mon = RiskMonitor(
        db=db,
        policy=Policy.load(settings.policy_dir),
        settings=settings,
        audit_log=AuditLog(db, clock=clock),
        clock=clock,
    )
    assert mon.current("agt1").score == 0
    assert (
        mon.record(
            RiskEvent(**ev(EventType.DPOP_FAILURE, agent="agt1", at=clock()).model_dump())
        ).score
        == 15
    )
