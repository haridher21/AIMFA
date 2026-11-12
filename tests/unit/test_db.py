"""Tests for T1.5: SQLite storage (aimfa/common/db.py).

These tests define the repository API (see db.py). Key rules: every "only if ..." update
is ONE conditional UPDATE (so concurrent callers cannot both win), duplicates raise
``DuplicateError``, unknown ids return None/False/0, datetimes must be tz-aware, SQL is
parameterized, and the audit table is append-only (no update/delete method).
"""

from __future__ import annotations

import ast
import contextlib
import inspect
import re
import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from aimfa.common import db as db_module
from aimfa.common.db import Database, DuplicateError
from aimfa.common.models import (
    ActiveTokenView,
    AgentRecord,
    AgentStatus,
    ApprovalReason,
    ApprovalRecord,
    ApprovalStatus,
    AuditRecord,
    DecisionOutcome,
    EventType,
    LauncherRegistration,
    PublicJWK,
    ReasonCode,
    RiskEvent,
)

NOW = datetime(2026, 11, 12, 12, 0, 0, 123456, tzinfo=UTC)
SHA = "a" * 64
HASH = "b" * 64  # action_hash used by _approval()
SEED = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"  # fake base32 TOTP seed
SQLI = "x'; DROP TABLE agents;--"
SQLI_OR = "' OR '1'='1"
TABLES = {
    "launchers",
    "agents",
    "approvers",
    "nonces",
    "tokens",
    "approvals",
    "risk_events",
    "audit",
}
RACERS = 16
ONE_WINNER = [False] * (RACERS - 1) + [True]


@pytest.fixture
def db(tmp_path: Path) -> Database:
    return Database(tmp_path / "aimfa.db")


def _launcher(launcher_id: str = "launcher-1", x: str = "A" * 43) -> LauncherRegistration:
    return LauncherRegistration(launcher_id=launcher_id, public_jwk=PublicJWK(x=x, kid="k1"))


def _agent(agent_id: str = "expense-bot", **kw: Any) -> AgentRecord:
    fields: dict[str, Any] = {
        "agent_id": agent_id,
        "role": "expense_reader",
        "golden_measurement": SHA,
        "launcher_id": "launcher-1",
        "approver_id": "alice",
        "description": "reads expenses",
        "created_at": NOW,
    }
    fields.update(kw)
    return AgentRecord(**fields)


def _seed_registry(db: Database) -> None:
    db.add_launcher(_launcher())
    db.add_approver("alice", display_name="Alice", totp_seed=SEED)


def _token(jti: str, agent_id: str = "expense-bot", task_id: str = "task-1") -> ActiveTokenView:
    return ActiveTokenView(
        jti=jti,
        agent_id=agent_id,
        task_id=task_id,
        scopes=["files:read:/expenses/*", "email:send:internal"],
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
        revoked=False,
    )


def _approval(approval_id: str = "appr-1", **kw: Any) -> ApprovalRecord:
    fields: dict[str, Any] = {
        "approval_id": approval_id,
        "agent_id": "wire-bot",
        "task_id": "task-9",
        "tool": "wire_transfer",
        "args": {"to_account": "ACME-001", "amount": 1250.5, "memo": "Q3 vendor"},
        "action_hash": HASH,
        "reason": ApprovalReason.HIGH_TIER,
        "risk_score": 12.5,
        "approver_id": "alice",
        "status": ApprovalStatus.PENDING,
        "created_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    fields.update(kw)
    return ApprovalRecord(**fields)


def _approved(db: Database, **kw: Any) -> ApprovalRecord:
    rec = _approval(status=ApprovalStatus.APPROVED, decided_at=NOW, **kw)
    db.add_approval(rec)
    return rec


def _consume(db: Database, *, agent_id: str = "wire-bot", action_hash: str = HASH, now=NOW):
    return db.consume_approval("appr-1", agent_id=agent_id, action_hash=action_hash, now=now)


def _event(agent_id: str = "expense-bot", at: datetime = NOW, **kw: Any) -> RiskEvent:
    fields: dict[str, Any] = {
        "agent_id": agent_id,
        "task_id": "task-1",
        "event_type": EventType.SENSITIVE_READ,
        "tool": "read_file",
        "target": "/engineering/secrets.env",
        "timestamp": at,
        "details": {},
    }
    fields.update(kw)
    return RiskEvent(**fields)


def _audit(seq: int, **kw: Any) -> AuditRecord:
    fields: dict[str, Any] = {
        "seq": seq,
        "timestamp": NOW + timedelta(seconds=seq),
        "prev_hash": "0" * 64 if seq == 0 else f"{seq - 1:064x}",
        "hash": f"{seq:064x}",
        "component": "gateway",
        "actor": "expense-bot",
        "event": "gateway.tool_call",
        "outcome": DecisionOutcome.DENY,
        "reason_code": ReasonCode.SCOPE_DENIED,
        "details": {"jti": "jti-1", "tool": "read_file"},
    }
    fields.update(kw)
    return AuditRecord(**fields)


def _race(fn: Callable[[], Any], n: int = RACERS) -> tuple[list[Any], list[Exception]]:
    """Run fn in n threads released at the same instant. Returns (results, errors)."""
    barrier = threading.Barrier(n)
    results: list[Any] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        try:
            r = fn()
        except Exception as e:  # collected and asserted on below
            with lock:
                errors.append(e)
        else:
            with lock:
                results.append(r)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not any(t.is_alive() for t in threads), "a worker hung (deadlock / lock wait?)"
    return results, errors


def _tables(db: Database) -> set[str]:
    with db.connect() as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r[0] for r in rows}


# ---------------------------------------------------------------- schema + connections


def test_schema_dirs_and_reopen_keep_data(tmp_path: Path):
    path = tmp_path / "does" / "not" / "exist" / "aimfa.db"
    first = Database(path)
    assert TABLES <= _tables(first)
    first.add_launcher(_launcher())
    assert Database(path).get_launcher("launcher-1") == _launcher()  # idempotent init
    with contextlib.closing(sqlite3.connect(path)) as raw:
        assert str(raw.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal"


def test_connect_commits_on_success_rolls_back_on_error_and_closes(db: Database):
    db.insert_audit(_audit(0))
    with db.connect() as c1:
        c1.execute("UPDATE audit SET actor = ? WHERE seq = ?", ("mallory", 0))
    assert db.list_audit()[0].actor == "mallory"
    with pytest.raises(RuntimeError), db.connect() as conn:
        conn.execute("DELETE FROM audit")
        raise RuntimeError("boom")
    assert [r.seq for r in db.list_audit()] == [0]
    with pytest.raises(sqlite3.ProgrammingError):
        c1.execute("SELECT 1")


# ---------------------------------------------------------------- launchers + agents


def test_launcher_crud_and_duplicate_keeps_original_key(db: Database):
    db.add_launcher(_launcher(x="A" * 43))
    assert db.get_launcher("nobody") is None
    with pytest.raises(DuplicateError):
        db.add_launcher(_launcher(x="Z" * 43))
    assert db.get_launcher("launcher-1").public_jwk.x == "A" * 43
    db.add_launcher(_launcher("launcher-2", x="B" * 43))
    assert len(db.list_launchers()) == 2
    assert db.delete_launcher("launcher-2") is True
    assert db.delete_launcher("launcher-2") is False


def test_agent_crud_and_duplicate_keeps_golden_measurement(db: Database):
    _seed_registry(db)
    rec = _agent(description="Spesen-Prüfer 中文 " + "x" * 10_000)
    db.add_agent(rec)
    got = db.get_agent("expense-bot")
    assert got == rec and got.status is AgentStatus.REGISTERED
    with pytest.raises(DuplicateError):  # must not overwrite golden measurement
        db.add_agent(_agent(golden_measurement="f" * 64))
    assert db.get_agent("expense-bot").golden_measurement == SHA
    db.add_agent(_agent("wire-bot"))
    assert len(db.list_agents()) == 2
    assert db.delete_agent("wire-bot") is True
    assert db.delete_agent("wire-bot") is False


def test_sql_injection_in_ids_and_text_fields_is_treated_as_data(db: Database):
    _seed_registry(db)
    db.add_agent(_agent(description=SQLI))
    assert db.get_agent("expense-bot").description == SQLI
    assert db.get_agent(SQLI_OR) is None
    assert db.get_agent(SQLI) is None
    assert TABLES <= _tables(db)


def test_activate_agent_and_stale_activation_cannot_undo_quarantine(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    assert db.activate_agent("expense-bot") is True
    assert db.get_agent("expense-bot").status is AgentStatus.ACTIVE
    q_at = NOW + timedelta(minutes=1)
    db.set_agent_status("expense-bot", AgentStatus.QUARANTINED, quarantined_at=q_at)
    assert db.activate_agent("expense-bot") is False  # stale /attest after quarantine
    got = db.get_agent("expense-bot")
    assert got.status is AgentStatus.QUARANTINED and got.quarantined_at == q_at
    assert db.activate_agent("ghost-bot") is False
    assert db.set_agent_status("ghost-bot", AgentStatus.ACTIVE) is False


def test_quarantine_agent_revokes_only_its_unrevoked_tokens(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    db.add_agent(_agent("wire-bot"))
    for jti, task in (("a1", "t1"), ("a2", "t2"), ("a3", "t3")):
        db.add_token(_token(jti, task_id=task))
    db.revoke_token("a3")  # already revoked: not counted
    db.add_token(_token("b1", agent_id="wire-bot", task_id="t9"))
    q_at = NOW + timedelta(minutes=2)

    assert db.quarantine_agent("expense-bot", at=q_at) == 2

    got = db.get_agent("expense-bot")
    assert got.status is AgentStatus.QUARANTINED and got.quarantined_at == q_at
    assert db.get_token("a1").revoked and db.get_token("a2").revoked
    assert db.get_token("b1").revoked is False
    assert db.get_agent("wire-bot").status is AgentStatus.REGISTERED


def test_clear_quarantine_resets_status_but_keeps_tokens_revoked(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    db.add_token(_token("a1"))
    assert db.clear_quarantine("expense-bot") is False  # not quarantined
    db.quarantine_agent("expense-bot", at=NOW)
    assert db.clear_quarantine("expense-bot") is True
    got = db.get_agent("expense-bot")
    assert got.status is AgentStatus.REGISTERED and got.quarantined_at is None
    assert db.get_token("a1").revoked is True
    assert db.clear_quarantine("ghost-bot") is False


def test_delete_agent_revokes_tokens_and_nonces_so_reregistering_cannot_resurrect(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    db.add_agent(_agent("wire-bot"))
    db.add_token(_token("a1"))
    db.add_token(_token("b1", agent_id="wire-bot", task_id="t9"))
    db.add_nonce("e" * 32, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    db.add_nonce("w" * 32, "wire-bot", expires_at=NOW + timedelta(seconds=60))

    assert db.delete_agent("expense-bot") is True
    assert db.get_token("a1").revoked is True
    assert db.get_nonce("e" * 32) is None
    assert db.get_token("b1").revoked is False
    assert db.get_nonce("w" * 32) is not None

    db.add_agent(_agent())  # same agent_id registered again
    assert db.get_token("a1").revoked is True
    assert db.consume_nonce("e" * 32, "expense-bot", now=NOW) is False


# ---------------------------------------------------------------- approvers + TOTP steps


def test_approver_crud_secret_hidden_and_duplicate_keeps_seed(db: Database):
    db.add_approver("alice", display_name="Alice", totp_seed=SEED)
    got = db.get_approver("alice")
    assert got.totp_seed.get_secret_value() == SEED and got.last_used_step is None
    assert SEED not in repr(got) and SEED not in str(got)
    with pytest.raises(DuplicateError):  # re-enrolling must not replace the human's seed
        db.add_approver("alice", display_name="Mallory", totp_seed="MALLORYSEEDMALLORYSEED")
    assert db.get_approver("alice").totp_seed.get_secret_value() == SEED
    assert db.get_approver("nobody") is None
    assert len(db.list_approvers()) == 1
    assert db.delete_approver("alice") is True
    assert db.delete_approver("alice") is False


def test_totp_step_is_single_use_monotonic_and_per_approver(db: Database):
    db.add_approver("alice", display_name="Alice", totp_seed=SEED)
    db.add_approver("bob", display_name="Bob", totp_seed=SEED)
    assert db.mark_totp_step_used("alice", 100) is True
    assert db.mark_totp_step_used("alice", 100) is False  # replayed code
    assert db.mark_totp_step_used("alice", 99) is False  # older step must not roll back
    assert db.get_approver("alice").last_used_step == 100
    assert db.mark_totp_step_used("alice", 101) is True
    assert db.mark_totp_step_used("bob", 100) is True
    assert db.mark_totp_step_used("ghost", 1) is False


def test_concurrent_use_of_same_totp_step_has_exactly_one_winner(db: Database):
    db.add_approver("alice", display_name="Alice", totp_seed=SEED)
    results, errors = _race(lambda: db.mark_totp_step_used("alice", 777))
    assert errors == [] and sorted(results) == ONE_WINNER


# ---------------------------------------------------------------- nonces


def test_nonce_consume_once_and_binding(db: Database):
    exp = NOW + timedelta(seconds=60)
    db.add_nonce("n" * 32, "expense-bot", expires_at=exp)
    row = db.get_nonce("n" * 32)
    assert (row.agent_id, row.expires_at, bool(row.used)) == ("expense-bot", exp, False)
    assert db.consume_nonce("n" * 32, "wire-bot", now=NOW) is False  # other agent
    assert db.consume_nonce("unknown-nonce-value", "expense-bot", now=NOW) is False
    assert db.consume_nonce(SQLI_OR, "expense-bot", now=NOW) is False
    assert db.consume_nonce("n" * 32, "expense-bot", now=NOW) is True
    assert db.consume_nonce("n" * 32, "expense-bot", now=NOW) is False  # replay
    assert bool(db.get_nonce("n" * 32).used) is True


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        (timedelta(seconds=60) - timedelta(microseconds=1), True),
        (timedelta(seconds=60), False),  # exactly at expiry is expired
        (timedelta(seconds=61), False),
    ],
)
def test_nonce_expiry_boundary(db: Database, offset: timedelta, expected: bool):
    db.add_nonce("n" * 32, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    assert db.consume_nonce("n" * 32, "expense-bot", now=NOW + offset) is expected


def test_nonce_expiry_compares_instants_not_strings(db: Database):
    db.add_nonce("n" * 32, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    expired_but_sorts_early = (NOW + timedelta(seconds=90)).astimezone(
        timezone(timedelta(hours=-5))
    )
    assert db.consume_nonce("n" * 32, "expense-bot", now=expired_but_sorts_early) is False
    valid_but_sorts_late = (NOW + timedelta(seconds=30)).astimezone(timezone(timedelta(hours=9)))
    assert db.consume_nonce("n" * 32, "expense-bot", now=valid_but_sorts_late) is True


def test_nonce_input_validation_and_duplicates(db: Database):
    exp = NOW + timedelta(seconds=60)
    with pytest.raises(ValueError):
        db.add_nonce("x" * 15, "expense-bot", expires_at=exp)  # too short
    with pytest.raises(ValueError):
        db.add_nonce("n" * 32, "expense-bot", expires_at=datetime(2026, 11, 12, 12, 1))  # naive
    assert db.get_nonce("n" * 32) is None
    db.add_nonce("x" * 16, "expense-bot", expires_at=exp)  # boundary: 16 is fine
    with pytest.raises(DuplicateError):
        db.add_nonce("x" * 16, "wire-bot", expires_at=exp)
    with pytest.raises(ValueError):
        db.consume_nonce("x" * 16, "expense-bot", now=datetime(2026, 11, 12, 12, 0))
    assert not db.get_nonce("x" * 16).used


def test_concurrent_nonce_consume_has_exactly_one_winner(db: Database):
    db.add_nonce("r" * 32, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    results, errors = _race(lambda: db.consume_nonce("r" * 32, "expense-bot", now=NOW))
    assert errors == [] and sorted(results) == ONE_WINNER


# ---------------------------------------------------------------- tokens + revocation


def test_token_crud_revoke_and_duplicate_jti(db: Database):
    tok = _token("jti-1")
    db.add_token(tok)
    assert db.get_token("jti-1") == tok
    db.add_token(_token("jti-2", agent_id="wire-bot"))
    assert {t.jti for t in db.list_tokens(agent_id="wire-bot")} == {"jti-2"}
    with pytest.raises(DuplicateError):
        db.add_token(_token("jti-1", agent_id="wire-bot"))
    assert db.get_token("jti-1").agent_id == "expense-bot"
    assert db.revoke_token("jti-1") is True
    assert db.get_token("jti-2").revoked is False
    assert db.get_token("nope") is None
    assert db.revoke_token("nope") is False
    assert db.revoke_token(SQLI_OR) is False


def test_revoke_all_for_agent_is_scoped_and_counts_newly_revoked(db: Database):
    for jti, agent, task in (("a1", "expense-bot", "t1"), ("a2", "expense-bot", "t2")):
        db.add_token(_token(jti, agent_id=agent, task_id=task))
    db.add_token(_token("b1", agent_id="wire-bot", task_id="t3"))
    db.revoke_token("a1")
    assert db.revoke_all_for_agent("expense-bot") == 1
    assert db.revoke_all_for_agent("expense-bot") == 0
    assert db.get_token("b1").revoked is False
    assert db.revoke_all_for_agent(SQLI_OR) == 0
    assert db.revoke_all_for_agent("%") == 0  # no LIKE-style wildcard matching


def test_revoke_task_tokens_is_scoped_to_task_and_owning_agent(db: Database):
    db.add_token(_token("a1", task_id="t1"))
    db.add_token(_token("a2", task_id="t2"))
    assert db.revoke_task_tokens("wire-bot", "t1") == 0  # cross-agent tampering
    assert db.get_token("a1").revoked is False
    assert db.revoke_task_tokens("expense-bot", "t1") == 1
    assert db.get_token("a2").revoked is False


# ---------------------------------------------------------------- approvals


def test_approval_crud_and_duplicate_keeps_original(db: Database):
    args = {"to": SQLI, "body": "line1\nline2", "nested": {"list": [1, 2.5, None, True]}}
    rec = _approval(args=args)
    db.add_approval(rec)
    assert db.get_approval("appr-1") == rec
    with pytest.raises(DuplicateError):
        db.add_approval(_approval(action_hash="c" * 64))
    assert db.get_approval("appr-1").action_hash == HASH
    db.add_approval(_approval("appr-2", status=ApprovalStatus.DENIED, decided_at=NOW))
    assert [a.approval_id for a in db.list_approvals(status=ApprovalStatus.PENDING)] == ["appr-1"]
    assert db.get_approval("nope") is None
    assert db.get_approval(SQLI_OR) is None


def test_approval_transition_lifecycle_and_double_decide(db: Database):
    db.add_approval(_approval())
    decided = NOW + timedelta(seconds=30)
    assert db.transition_approval(
        "appr-1", ApprovalStatus.PENDING, ApprovalStatus.APPROVED, decided_at=decided
    )
    assert not db.transition_approval("appr-1", ApprovalStatus.PENDING, ApprovalStatus.DENIED)
    assert db.transition_approval("appr-1", ApprovalStatus.APPROVED, ApprovalStatus.USED)
    assert db.transition_approval("appr-1", ApprovalStatus.APPROVED, ApprovalStatus.USED) is False
    got = db.get_approval("appr-1")
    assert got.status is ApprovalStatus.USED and got.decided_at == decided
    assert db.transition_approval("nope", ApprovalStatus.PENDING, ApprovalStatus.APPROVED) is False


@pytest.mark.parametrize(
    ("current", "new"),
    [
        (ApprovalStatus.DENIED, ApprovalStatus.APPROVED),
        (ApprovalStatus.PENDING, ApprovalStatus.USED),
    ],
)
def test_illegal_approval_transition_raises_and_leaves_row_unchanged(
    db: Database, current: ApprovalStatus, new: ApprovalStatus
):
    rec = _approval(status=current, decided_at=None if current is ApprovalStatus.PENDING else NOW)
    db.add_approval(rec)
    with pytest.raises(ValueError):
        db.transition_approval("appr-1", current, new, decided_at=NOW + timedelta(seconds=9))
    assert db.get_approval("appr-1") == rec


def test_decide_approval_approve_deny_and_refusals(db: Database):
    db.add_approval(_approval())
    assert db.decide_approval("appr-1", approver_id="mallory", approve=True, now=NOW) is False
    assert db.decide_approval("appr-1", approver_id=SQLI_OR, approve=True, now=NOW) is False
    assert db.get_approval("appr-1").status is ApprovalStatus.PENDING
    assert db.decide_approval("appr-1", approver_id="alice", approve=False, now=NOW) is True
    got = db.get_approval("appr-1")
    assert got.status is ApprovalStatus.DENIED and got.decided_at == NOW
    assert db.decide_approval("appr-1", approver_id="alice", approve=True, now=NOW) is False
    assert db.decide_approval("nope", approver_id="alice", approve=True, now=NOW) is False


@pytest.mark.parametrize("after_expiry", [timedelta(0), timedelta(seconds=1)])
def test_decide_and_consume_at_or_after_expiry_are_refused(db: Database, after_expiry: timedelta):
    rec = _approval()
    db.add_approval(rec)
    now = rec.expires_at + after_expiry
    assert db.decide_approval("appr-1", approver_id="alice", approve=True, now=now) is False
    assert db.get_approval("appr-1").status is ApprovalStatus.PENDING
    db.transition_approval(
        "appr-1", ApprovalStatus.PENDING, ApprovalStatus.APPROVED, decided_at=NOW
    )
    assert _consume(db, now=now) is False
    assert db.get_approval("appr-1").status is ApprovalStatus.APPROVED


def test_consume_approval_is_bound_to_agent_and_exact_action(db: Database):
    _approved(db)
    assert _consume(db, action_hash="c" * 64) is False  # different args must not ride on it
    assert _consume(db, agent_id="expense-bot") is False
    assert _consume(db, agent_id=SQLI_OR) is False
    assert db.get_approval("appr-1").status is ApprovalStatus.APPROVED
    assert _consume(db) is True
    assert db.get_approval("appr-1").status is ApprovalStatus.USED
    assert _consume(db) is False  # single use
    assert db.consume_approval("nope", agent_id="wire-bot", action_hash=HASH, now=NOW) is False


@pytest.mark.parametrize("status", [ApprovalStatus.PENDING, ApprovalStatus.DENIED])
def test_consume_approval_that_is_not_approved_is_refused(db: Database, status: ApprovalStatus):
    db.add_approval(_approval(status=status, decided_at=None if status.value == "pending" else NOW))
    assert _consume(db) is False
    assert db.get_approval("appr-1").status is status


def test_concurrent_decide_and_consume_have_exactly_one_winner(db: Database):
    db.add_approval(_approval("d1"))
    results, errors = _race(
        lambda: db.decide_approval("d1", approver_id="alice", approve=True, now=NOW)
    )
    assert errors == [] and sorted(results) == ONE_WINNER
    _approved(db)
    results, errors = _race(lambda: _consume(db))
    assert errors == [] and sorted(results) == ONE_WINNER


# ---------------------------------------------------------------- risk events


def test_risk_events_ordering_since_isolation_and_delete(db: Database):
    late = _event(at=NOW + timedelta(seconds=1))
    early = _event(at=NOW - timedelta(seconds=1), task_id=None, tool=None, target=None)
    mid = _event(at=NOW, details={"contributions": [{"rule": "sensitive", "points": 0}]})
    for e in (late, early, mid, _event("wire-bot")):
        db.add_risk_event(e)
    assert db.list_risk_events("expense-bot") == [early, mid, late]
    assert db.list_risk_events("expense-bot", since=NOW) == [mid, late]  # inclusive
    assert db.delete_risk_events("expense-bot") == 3
    assert len(db.list_risk_events("wire-bot")) == 1


# ---------------------------------------------------------------- audit


def test_audit_round_trip_is_byte_exact_and_last_audit(db: Database):
    assert db.last_audit() is None
    recs = [_audit(i) for i in range(3)]
    recs.append(_audit(3, outcome="info", reason_code=ReasonCode.OK, details={"b": "é" * 50_000}))
    for r in recs:
        db.insert_audit(r)
    assert [g.model_dump_json() for g in db.list_audit()] == [r.model_dump_json() for r in recs]
    assert db.last_audit() == recs[-1]


def test_list_audit_paging_and_negative_limit(db: Database):
    for i in range(10):
        db.insert_audit(_audit(i))
    assert [r.seq for r in db.list_audit(after_seq=4, limit=3)] == [5, 6, 7]
    assert db.list_audit(after_seq=9, limit=100) == []
    with pytest.raises(ValueError):
        db.list_audit(limit=-1)


def test_duplicate_audit_seq_raises_and_concurrent_insert_has_one_winner(db: Database):
    db.insert_audit(_audit(0))
    with pytest.raises(DuplicateError):
        db.insert_audit(_audit(0, actor="mallory"))
    assert db.list_audit()[0].actor == "expense-bot"
    results, errors = _race(lambda: db.insert_audit(_audit(1)))
    assert len(results) == 1
    assert all(isinstance(e, DuplicateError) for e in errors), errors


def test_audit_has_no_update_or_delete_repository_method():
    names = [n for n in dir(Database) if not n.startswith("_") and "audit" in n.lower()]
    assert [n for n in names if re.match(r"(update|delete|remove|set|edit|clear)", n)] == []


# ---------------------------------------------------------------- parameterized SQL

_SQL_WORDS = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|PRAGMA|WHERE|VALUES|FROM)\b"
)


def _literal_text(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(_literal_text(v) for v in node.values)
    return ""


def test_sql_is_never_built_with_string_formatting():
    """Backstop for rule 8: flags f-strings, .format(), % and + mixing SQL with values."""
    tree = ast.parse(inspect.getsource(db_module))
    offenders: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            has_value = any(isinstance(v, ast.FormattedValue) for v in node.values)
            if has_value and _SQL_WORDS.search(_literal_text(node)):
                offenders.append(node.lineno)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and _SQL_WORDS.search(_literal_text(node.func.value))
        ):
            offenders.append(node.lineno)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod | ast.Add):
            sides = (_literal_text(node.left), _literal_text(node.right))
            both_const = all(
                isinstance(s, ast.Constant) and isinstance(s.value, str)
                for s in (node.left, node.right)
            )
            if not both_const and any(_SQL_WORDS.search(s) for s in sides):
                offenders.append(node.lineno)
    assert offenders == [], f"SQL built by string formatting at db.py lines {offenders}"
