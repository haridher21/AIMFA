"""T4.1 behavioral monitor: pure scoring + stateful RiskMonitor.

ASSUMPTIONS (the implementer must provide exactly these names, in aimfa/control_plane/monitor.py):
* `score_event(event, *, history, profile, rate_limit_per_minute) -> list[RiskContribution]`
  `history` = the agent's EARLIER RiskEvents (not including `event`); `profile` = role profile
  (iterable of category names). Contribution `at` = event.timestamp. Tests check points only,
  not rule names.
* `RiskMonitor(db=, policy=, settings=, audit_log=, clock=)` (keyword args) with
  `record(event) -> RiskScore`, `current(agent_id) -> RiskScore`, `reset(agent_id) -> None`.
  The monitor looks the agent's role up in `db` (`db.get_agent`) to get profile + rate limit
  from `policy.role(role)`. It persists events with `db.add_risk_event`.
* Decay is linear and applied lazily from contribution timestamps vs `clock()`; score never < 0.
* Crossing `risk_revoke_threshold` (>=, inclusive): `db.revoke_all_for_agent`,
  `db.quarantine_agent`, an audit record with reason_code AGENT_QUARANTINED, and the returned
  RiskScore.status is QUARANTINED. A category of None / missing in details adds no
  out-of-profile points.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from aimfa.common.config import Settings
from aimfa.common.db import Database
from aimfa.common.models import (
    ActiveTokenView,
    AgentRecord,
    AgentStatus,
    EventType,
    ReasonCode,
    RiskEvent,
)
from aimfa.common.policy import Policy
from aimfa.control_plane.audit import AuditLog
from aimfa.control_plane.monitor import RiskMonitor, score_event
from tests.integration.conftest import FakeClock

PROFILE = ["expenses", "email_internal"]
ET = EventType
T0 = FakeClock().now


def ev(event_type=ET.TOOL_ALLOWED, *, agent="agt1", task="t1", at=T0, **details) -> RiskEvent:
    return RiskEvent(
        agent_id=agent, task_id=task, event_type=event_type, tool="read_file",
        timestamp=at, details=details,
    )  # fmt: skip


def points(event, history=(), profile=PROFILE, limit=30) -> float:
    contribs = score_event(
        event, history=list(history), profile=profile, rate_limit_per_minute=limit
    )
    return sum(c.points for c in contribs)


# ------------------------------------------------------------------ pure rules


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        (ev(ET.TOOL_ALLOWED, category="expenses"), 0),
        (ev(ET.OUT_OF_PROFILE), 50),
        (ev(ET.TOOL_ALLOWED, category="engineering"), 50),
        (ev(ET.OUT_OF_PROFILE, category="engineering"), 50),  # never double-counted
        (ev(ET.SCOPE_DENIED), 30),
        (ev(ET.ACTION_FORBIDDEN), 30),
        (ev(ET.RATE_EXCEEDED), 20),
        (ev(ET.DPOP_FAILURE), 15),
        (ev(ET.TOKEN_FAILURE), 15),
        (ev(ET.APPROVAL_DENIED), 25),
    ],
)
def test_each_rule_awards_its_points(event, expected):
    assert points(event) == expected


def test_rate_above_role_limit_adds_20_only_when_strictly_above():
    recent = [ev(at=T0 - timedelta(seconds=10 + i)) for i in range(3)]
    assert points(ev(), recent, limit=3) == 20  # 3 earlier + this one = 4 > 3
    assert points(ev(), recent[:2], limit=3) == 0  # exactly at the limit is fine


def test_rate_ignores_events_older_than_60_seconds():
    old = [ev(at=T0 - timedelta(seconds=61 + i)) for i in range(5)]
    assert points(ev(), old, limit=3) == 0


def test_exfil_fires_on_sensitive_read_then_egress_in_same_task():
    history = [ev(ET.SENSITIVE_READ, at=T0 - timedelta(seconds=5))]
    assert points(ev(ET.EXTERNAL_EGRESS), history) == 60


def test_exfil_via_details_flags():
    history = [
        ev(ET.TOOL_ALLOWED, at=T0 - timedelta(seconds=5), category="expenses", sensitive=True)
    ]
    profile = [*PROFILE, "email_external"]
    assert points(ev(ET.TOOL_ALLOWED, category="email_external"), history, profile) == 60


@pytest.mark.parametrize(
    ("history", "egress"),
    [
        ([ev(ET.SENSITIVE_READ, task="other")], ev(ET.EXTERNAL_EGRESS)),  # different task
        ([ev(ET.SENSITIVE_READ, task=None)], ev(ET.EXTERNAL_EGRESS, task=None)),  # no task id
        ([ev(ET.TOOL_ALLOWED, category="expenses")], ev(ET.EXTERNAL_EGRESS)),  # read not sensitive
        ([], ev(ET.EXTERNAL_EGRESS)),  # egress alone
    ],
)
def test_exfil_does_not_fire_without_sensitive_then_egress_in_same_task(history, egress):
    assert points(egress, history) == 0


def test_exfil_requires_sensitive_read_to_come_first():
    history = [ev(ET.EXTERNAL_EGRESS, at=T0 - timedelta(seconds=5))]
    assert points(ev(ET.SENSITIVE_READ), history) == 0


# ------------------------------------------------------------------ stateful monitor


class Rig:
    def __init__(self, tmp_path):
        self.settings = Settings(
            _env_file=None, data_dir=tmp_path / "d", keys_dir=tmp_path / "k",
            risk_step_up_threshold=50, risk_revoke_threshold=80, risk_decay_per_minute=5,
        )  # fmt: skip
        self.clock = FakeClock()
        self.db = Database(tmp_path / "m.db")
        for agent in ("agt1", "agt2"):
            self.db.add_agent(
                AgentRecord(
                    agent_id=agent, role="expense_reader", golden_measurement="0" * 64,
                    launcher_id="lau1", approver_id="app1", status=AgentStatus.ACTIVE,
                    created_at=self.clock(),
                )
            )  # fmt: skip
        self.db.add_token(
            ActiveTokenView(
                jti="jti-1", agent_id="agt1", task_id="t1", scopes=["files:read:/expenses/*"],
                issued_at=self.clock(), expires_at=self.clock() + timedelta(minutes=5),
                revoked=False,
            )
        )  # fmt: skip
        self.mon = RiskMonitor(
            db=self.db,
            policy=Policy.load(self.settings.policy_dir),
            settings=self.settings,
            audit_log=AuditLog(self.db, clock=self.clock),
            clock=self.clock,
        )

    def rec(self, event_type=ET.TOOL_ALLOWED, agent="agt1", **details):
        return self.mon.record(ev(event_type, agent=agent, at=self.clock(), **details))


@pytest.fixture
def rig(tmp_path) -> Rig:
    return Rig(tmp_path)


def test_record_accumulates_and_step_up_flips_at_threshold(rig):
    s = rig.rec(ET.SCOPE_DENIED)
    assert (s.score, s.step_up_required, s.status) == (30, False, AgentStatus.ACTIVE)
    s = rig.rec(ET.APPROVAL_DENIED)  # 55 >= 50
    assert (s.score, s.step_up_required, s.status) == (55, True, AgentStatus.ACTIVE)
    assert rig.mon.current("agt1").score == 55


def test_decay_is_linear_and_never_negative(rig):
    rig.rec(ET.OUT_OF_PROFILE)
    rig.clock.advance(120)  # 2 min * 5/min
    assert rig.mon.current("agt1").score == 40
    rig.clock.advance(60 * 60)
    assert rig.mon.current("agt1").score == 0


def test_decay_applies_between_records(rig):
    rig.rec(ET.SCOPE_DENIED)
    rig.clock.advance(60)
    assert rig.rec(ET.SCOPE_DENIED).score == 55  # 30 - 5 + 30


def test_crossing_revoke_threshold_quarantines_revokes_and_audits(rig):
    s = rig.rec(ET.OUT_OF_PROFILE)
    s = rig.rec(ET.SCOPE_DENIED)  # exactly 80: inclusive
    assert s.score == 80 and s.status is AgentStatus.QUARANTINED
    assert rig.db.get_agent("agt1").status is AgentStatus.QUARANTINED
    assert rig.db.get_token("jti-1").revoked is True
    assert any(r.reason_code is ReasonCode.AGENT_QUARANTINED for r in rig.db.list_audit())


def test_just_below_revoke_threshold_does_not_quarantine(rig):
    rig.rec(ET.OUT_OF_PROFILE)
    assert rig.rec(ET.DPOP_FAILURE).status is AgentStatus.ACTIVE  # 65
    assert rig.db.get_token("jti-1").revoked is False


def test_reset_zeroes_score(rig):
    rig.rec(ET.OUT_OF_PROFILE)
    rig.mon.reset("agt1")
    assert rig.mon.current("agt1").score == 0


def test_scores_are_per_agent(rig):
    rig.rec(ET.OUT_OF_PROFILE, agent="agt1")
    assert rig.mon.current("agt2").score == 0


def test_exfil_sequence_across_record_calls_uses_stored_history(rig):
    rig.rec(ET.SENSITIVE_READ)
    rig.clock.advance(1)
    s = rig.rec(ET.EXTERNAL_EGRESS)
    assert s.score == pytest.approx(60, abs=0.2)
