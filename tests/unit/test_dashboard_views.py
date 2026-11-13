"""T7.1 unit tests: pure dashboard helpers (no streamlit, no server)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aimfa.common.config import Settings
from aimfa.common.models import (
    ActiveTokenView,
    ApprovalRecord,
    ApprovalStatus,
    AuditRecord,
    ReasonCode,
    RiskContribution,
    RiskScore,
)
from aimfa.dashboard import views
from aimfa.dashboard.admin_client import InvalidTotpCode, check_totp_format
from attacks.common import AttackResult

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
H64 = "a" * 64
DASHBOARD_DIR = Path(views.__file__).parent


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        admin_api_key="admin-key-secret-123",
        internal_service_secret="internal-secret-456",
        gateway_resource_secret="gateway-secret-789",
        baseline_api_key="baseline-secret-000",
        risk_step_up_threshold=40,
        risk_revoke_threshold=70,
    )


def _token(expires_in: int, revoked: bool = False) -> ActiveTokenView:
    return ActiveTokenView(
        jti="0123456789abcdef0123",
        agent_id="bot",
        task_id="t1",
        scopes=["files:read:/a/*", "bank:read"],
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=expires_in),
        revoked=revoked,
    )


@pytest.mark.parametrize(
    ("expires_in", "seconds", "label"),
    [(125, 125, "2m 05s"), (9, 9, "9s"), (0, 0, "expired"), (-30, 0, "expired")],
)
def test_ttl_clamped_and_labelled(expires_in, seconds, label):
    left = views.seconds_left(NOW + timedelta(seconds=expires_in), NOW)
    assert left == seconds
    assert views.ttl_label(left) == label


@pytest.mark.parametrize(
    ("tok", "state"),
    [(_token(60), "active"), (_token(-5), "expired"), (_token(60, revoked=True), "revoked")],
)
def test_token_rows_state_and_no_full_jti(tok, state):
    (row,) = views.token_rows([tok], NOW)
    assert row["state"] == state
    assert tok.jti not in " ".join(str(v) for v in row.values())
    assert row["jti"].endswith("...")


def test_risk_chart_uses_settings_thresholds():
    scores = [RiskScore(agent_id="a", score=12.5, status="active", step_up_required=False)]
    chart = views.risk_chart(scores, _settings())
    assert chart == {"scores": {"a": 12.5}, "step_up": 40, "revoke": 70}


def test_rule_hits_newest_first_and_limited():
    c = [RiskContribution(rule=f"r{i}", points=i, at=NOW + timedelta(seconds=i)) for i in range(3)]
    scores = [RiskScore(agent_id="a", score=3, status="active", step_up_required=False, recent=c)]
    hits = views.rule_hits(scores, limit=2)
    assert [h["rule"] for h in hits] == ["r2", "r1"]


def test_approval_rows_fields():
    rec = ApprovalRecord(
        agent_id="bot",
        task_id="t",
        tool="send_email",
        args={"to": "x@y.z"},
        action_hash=H64,
        reason="high_tier",
        risk_score=33,
        approval_id="ap1",
        approver_id="alice",
        status=ApprovalStatus.PENDING,
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=90),
    )
    (row,) = views.approval_rows([rec], NOW)
    assert (row["agent"], row["tool"], row["risk"], row["expires_in"]) == (
        "bot",
        "send_email",
        33,
        "1m 30s",
    )
    assert row["args"] == {"to": "x@y.z"}


def _audit(seq: int) -> AuditRecord:
    return AuditRecord(
        component="gateway",
        actor="bot",
        event="gateway.tool_call",
        outcome="allow",
        seq=seq,
        timestamp=NOW,
        prev_hash=H64,
        hash=H64,
    )


def test_audit_tail_is_incremental_and_ignores_duplicates():
    class FakeClient:
        def __init__(self):
            self.calls, self.data = [], [_audit(0), _audit(1)]

        def audit(self, after_seq, limit):
            self.calls.append(after_seq)
            return [r for r in self.data if r.seq > after_seq]

    client, tail = FakeClient(), views.AuditTail()
    assert tail.poll(client) == 2
    client.data.append(_audit(2))
    assert tail.poll(client) == 1
    assert tail.poll(client) == 0
    # Only fetches from the last seen record (re-checked as an anchor) onward.
    assert client.calls == [-1, 0, 1]
    assert tail.update([_audit(1)]) == 0  # a replayed old record is ignored
    assert [r["seq"] for r in views.audit_rows(tail.records)] == [0, 1, 2]


class _ListClient:
    def __init__(self, data):
        self.data = data

    def audit(self, after_seq, limit):
        return [r for r in self.data if r.seq > after_seq][:limit]


def test_audit_tail_restarts_when_chain_is_reset():
    """After `run_demo.py --reset` the chain restarts at seq 0 with new hashes; the tail must
    notice instead of waiting forever for seq to pass its old position."""
    client, tail = _ListClient([_audit(i) for i in range(5)]), views.AuditTail()
    tail.poll(client)
    client.data = [_audit(0).model_copy(update={"hash": "b" * 64})]
    tail.poll(client)
    assert [r.seq for r in tail.records] == [0] and tail.records[0].hash == "b" * 64


def test_audit_tail_catches_up_on_a_long_log_in_one_poll():
    client, tail = _ListClient([_audit(i) for i in range(25)]), views.AuditTail(max_rows=10)
    assert tail.poll(client, limit=4) == 25
    assert tail.last_seq == 24 and len(tail.records) == 10


def test_attack_card_a9_in_baseline_is_not_applicable():
    a9 = AttackResult("A9 fake approval", True, None, None, "", "baseline")
    a9_aimfa = AttackResult("A9 fake approval", False, "approval", None, "", "aimfa")
    base, aim = views.attack_cards([a9, a9_aimfa])
    assert base["not_applicable"] and not aim["not_applicable"]


def test_audit_tail_caps_memory():
    tail = views.AuditTail(max_rows=3)
    tail.update([_audit(i) for i in range(10)])
    assert [r.seq for r in tail.records] == [7, 8, 9]


def test_attack_cards_blocked_and_succeeded():
    blocked = AttackResult(
        "A1", False, "attestation", ReasonCode.ATTEST_MEASUREMENT_MISMATCH, "e", "aimfa"
    )
    won = AttackResult("A2", True, None, None, "e2", "baseline")
    a, b = views.attack_cards([blocked, won])
    assert (a["verdict"], a["blocked_by"], a["reason_code"]) == (
        "blocked",
        "attestation",
        "ATTEST_MEASUREMENT_MISMATCH",
    )
    assert (b["verdict"], b["blocked_by"], b["mode"]) == ("ATTACK SUCCEEDED", "-", "baseline")


@pytest.mark.parametrize(
    "text", ["key=admin-key-secret-123;", "x internal-secret-456 y", "gateway-secret-789", "none"]
)
def test_redact_removes_every_configured_secret(text):
    out = views.redact(text, views.secret_values(_settings()))
    for secret in views.secret_values(_settings()):
        assert secret not in out


def test_redact_keeps_harmless_text_and_short_values():
    assert views.redact("hello world", ["zz"]) == "hello world"


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "12 456", "١٢٣٤٥٦"])
def test_totp_format_rejects_bad_codes(code):
    with pytest.raises(InvalidTotpCode):
        check_totp_format(code)


def test_totp_format_accepts_six_digits():
    assert check_totp_format("012345") == "012345"


def test_dashboard_never_touches_the_database():
    """The dashboard may only use the admin API, so no db/sqlite imports anywhere."""
    sources = list(DASHBOARD_DIR.rglob("*.py"))
    assert len(sources) >= 8
    for path in sources:
        text = path.read_text(encoding="utf-8")
        assert "aimfa.common.db" not in text, path
        assert "sqlite3" not in text, path


def test_pages_never_render_the_admin_key_setting():
    pages = [DASHBOARD_DIR / "app.py", *(DASHBOARD_DIR / "pages").glob("*.py")]
    assert len(pages) == 7
    for path in pages:  # pages never touch the key; only the client (header) and redact()
        assert "admin_api_key" not in path.read_text(encoding="utf-8"), path
