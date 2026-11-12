"""Tests for T1.5: SQLite storage (aimfa/common/db.py).

ROADMAP leaves the repository API open, so these tests DEFINE it. The implementer builds
exactly this interface; downstream tasks (T1.3 audit, T2.1 registry, T2.2 attestation,
T2.3 STS/revocation, T4.1 monitor, T4.3 approvals) consume it.

Chosen interface (assumptions)
------------------------------
``from aimfa.common.db import Database, DuplicateError``

* ``Database(path: Path)``: ``path`` is the SQLite file (normally ``settings.db_path``).
  The constructor creates missing parent directories and the schema (idempotent: opening
  an existing file keeps its data). The object holds no open connection, so one instance
  is safe to share between threads.
* ``db.connect()``: context manager yielding a NEW ``sqlite3.Connection`` (WAL mode,
  busy timeout so concurrent writers wait instead of failing). It commits on normal exit,
  rolls back on exception, and always closes the connection. It is the escape hatch for
  raw SQL (T1.3 tamper tests use it).
* ``DuplicateError(Exception)``: raised by every ``add_*``/``insert_*`` on a primary-key
  clash. Raw ``sqlite3.IntegrityError`` must not leak to callers.
* Table names are exactly: launchers, agents, approvers, nonces, tokens, approvals,
  risk_events, audit. The ``audit`` table has one column per ``AuditRecord`` field, with
  the same names (``details`` stored as JSON text).
* Every lookup of an unknown id returns ``None`` (``get_*``) or ``False``/``0``
  (updates). No exceptions for "not found".
* All datetimes passed in are timezone-aware; a naive datetime raises ``ValueError``
  (checked at least in add_nonce/consume_nonce). Datetimes read back are timezone-aware
  and denote the same instant. Time comparisons are by instant, not by string.
* Every "only if ..." update below is ONE conditional UPDATE (the condition lives in the
  WHERE clause), so two concurrent callers can never both win.

Repository methods (Database instance methods)
----------------------------------------------
launchers:
  add_launcher(reg: LauncherRegistration) -> None
  get_launcher(launcher_id) -> LauncherRegistration | None
  list_launchers() -> list[LauncherRegistration]
  delete_launcher(launcher_id) -> bool
agents:
  add_agent(rec: AgentRecord) -> None
  get_agent(agent_id) -> AgentRecord | None
  list_agents() -> list[AgentRecord]
  set_agent_status(agent_id, status: AgentStatus, *, quarantined_at=None,
                   expected: AgentStatus | None = None) -> bool
      Writes both status and quarantined_at exactly as given. Returns True if a row
      changed. With ``expected`` it is a compare-and-set: if the current status differs,
      returns False and changes nothing.
  activate_agent(agent_id) -> bool
      Status -> ACTIVE unless currently QUARANTINED (single conditional UPDATE). A stale
      /attest that finishes after a quarantine must not un-quarantine the agent. False
      (and nothing changed) when quarantined or unknown.
  quarantine_agent(agent_id, *, at: datetime) -> int
      In ONE transaction: status -> QUARANTINED, quarantined_at = at, and revoke every
      unrevoked token of that agent. Returns the number of tokens newly revoked. Unknown
      agent -> 0 and no rows changed.
  clear_quarantine(agent_id) -> bool
      QUARANTINED -> REGISTERED and quarantined_at -> None. False if not quarantined or
      unknown. Revoked tokens stay revoked.
  delete_agent(agent_id) -> bool
      In the same transaction also revokes the agent's tokens and deletes its nonces, so
      re-registering the same agent_id cannot resurrect old credentials.
approvers:
  add_approver(approver_id, display_name, totp_seed: str) -> None
  get_approver(approver_id) -> row | None
      row has .approver_id, .display_name, .totp_seed (pydantic SecretStr, so the seed
      never shows up in repr/logs), .last_used_step (int | None, None until first use)
  list_approvers() -> list[row]
  delete_approver(approver_id) -> bool
  mark_totp_step_used(approver_id, step: int) -> bool
      Atomic and monotonic: True only if step > last_used_step (or none yet). This is
      the "a TOTP code can be used only once per approver" rule from CONTRACTS.md.
nonces:
  add_nonce(nonce, agent_id, *, expires_at) -> None
      ValueError if len(nonce) < 16 (AttestationChallenge.nonce min_length) or
      expires_at is naive.
  get_nonce(nonce) -> row | None        (row has .nonce, .agent_id, .expires_at, .used)
  consume_nonce(nonce, agent_id, *, now) -> bool
      Atomic single statement: True only if the nonce exists, belongs to agent_id, is
      unused and now < expires_at. Exactly at expires_at counts as expired.
  delete_expired_nonces(*, now) -> int  (deletes rows with expires_at <= now)
tokens (row type = ActiveTokenView):
  add_token(view: ActiveTokenView) -> None
  get_token(jti) -> ActiveTokenView | None
  list_tokens(agent_id: str | None = None) -> list[ActiveTokenView]
  revoke_token(jti) -> bool             (False if the jti is unknown)
  revoke_task_tokens(agent_id, task_id) -> int   (newly revoked; scoped to the agent)
  revoke_all_for_agent(agent_id) -> int          (newly revoked; the kill switch)
approvals (row type = ApprovalRecord):
  add_approval(rec: ApprovalRecord) -> None
  get_approval(approval_id) -> ApprovalRecord | None
  list_approvals(status: ApprovalStatus | None = None) -> list[ApprovalRecord]
  transition_approval(approval_id, expected, new, *, decided_at=None) -> bool
      Atomic compare-and-set on status. decided_at is written only when not None.
      Illegal moves raise ValueError and leave the row unchanged. Legal moves:
      PENDING -> APPROVED | DENIED | EXPIRED, APPROVED -> USED. Tested illegal ones:
      DENIED -> APPROVED, USED -> APPROVED, PENDING -> USED, EXPIRED -> APPROVED.
  decide_approval(approval_id, *, approver_id, approve: bool, now) -> bool
      Single UPDATE: PENDING -> APPROVED (approve) / DENIED, decided_at = now, only if
      approver_id matches the assigned approver and now < expires_at.
  consume_approval(approval_id, *, agent_id, action_hash, now) -> bool
      Single UPDATE: APPROVED -> USED only if agent_id and action_hash match and
      now < expires_at. Exactly at expires_at counts as expired.
risk_events (row type = RiskEvent; the monitor may keep per-rule points in .details):
  add_risk_event(event: RiskEvent) -> None
  list_risk_events(agent_id, *, since=None) -> list[RiskEvent]
      ordered by timestamp ascending; ``since`` is inclusive.
  delete_risk_events(agent_id) -> int
audit (row type = AuditRecord; append-only, so no update/delete method exists):
  insert_audit(rec: AuditRecord) -> None   (DuplicateError on an existing seq)
  last_audit() -> AuditRecord | None       (highest seq)
  list_audit(after_seq: int = -1, limit: int = 100) -> list[AuditRecord]
      seq > after_seq, ascending by seq, at most ``limit`` rows. ValueError if
      limit < 0 (SQLite treats LIMIT -1 as "no limit").
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

# ---------------------------------------------------------------- helpers

NOW = datetime(2026, 11, 12, 12, 0, 0, 123456, tzinfo=UTC)
SHA = "a" * 64
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
    """Launcher + approver first, so a schema with foreign keys is also satisfied."""
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
        "action_hash": "b" * 64,
        "reason": ApprovalReason.HIGH_TIER,
        "risk_score": 12.5,
        "approver_id": "alice",
        "status": ApprovalStatus.PENDING,
        "created_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    fields.update(kw)
    return ApprovalRecord(**fields)


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


def _tables(path: Path) -> set[str]:
    with contextlib.closing(sqlite3.connect(path)) as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r[0] for r in rows}


def db_path_of(db: Database) -> Path:
    """Locate the db file from a raw connection (avoids assuming an attribute name)."""
    with db.connect() as conn:
        return Path(conn.execute("PRAGMA database_list").fetchone()[2])


# ---------------------------------------------------------------- schema + connections


def test_schema_creates_every_table(tmp_path: Path):
    path = tmp_path / "aimfa.db"
    Database(path)
    assert TABLES <= _tables(path)


def test_missing_data_dir_is_created(tmp_path: Path):
    path = tmp_path / "does" / "not" / "exist" / "aimfa.db"
    Database(path)
    assert path.is_file()


def test_reopening_existing_db_keeps_data_and_schema_init_is_idempotent(tmp_path: Path):
    path = tmp_path / "aimfa.db"
    first = Database(path)
    first.add_launcher(_launcher())
    second = Database(path)  # simulates a service restart
    assert second.get_launcher("launcher-1") == _launcher()


def test_connections_use_wal_mode(db: Database):
    with db.connect() as conn:
        assert str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal"


def test_wal_mode_is_persisted_in_the_file(tmp_path: Path):
    path = tmp_path / "aimfa.db"
    Database(path)
    with contextlib.closing(sqlite3.connect(path)) as raw:
        assert str(raw.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal"


def test_connect_returns_a_fresh_connection_that_is_closed_on_exit(db: Database):
    with db.connect() as c1:
        pass
    with db.connect() as c2:
        assert c2 is not c1
    with pytest.raises(sqlite3.ProgrammingError):  # closed, not merely committed
        c1.execute("SELECT 1")


def test_connect_commits_raw_sql_on_success(db: Database):
    """T1.3 tamper tests rely on this: a raw UPDATE through connect() must persist."""
    db.insert_audit(_audit(0))
    with db.connect() as conn:
        conn.execute("UPDATE audit SET actor = ? WHERE seq = ?", ("mallory", 0))
    assert db.list_audit()[0].actor == "mallory"


def test_connect_rolls_back_on_exception(db: Database):
    db.insert_audit(_audit(0))
    with pytest.raises(RuntimeError), db.connect() as conn:
        conn.execute("DELETE FROM audit")
        raise RuntimeError("boom")
    assert [r.seq for r in db.list_audit()] == [0]


def test_audit_table_columns_mirror_audit_record_fields(db: Database):
    with db.connect() as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(audit)").fetchall()}
    assert set(AuditRecord.model_fields) <= cols


def test_database_object_can_be_shared_across_threads(db: Database):
    """check_same_thread-safe usage: no connection is pinned to the creating thread."""
    _seed_registry(db)
    box: dict[str, Any] = {}

    def worker() -> None:
        try:
            db.add_agent(_agent())
            box["got"] = db.get_agent("expense-bot")
        except Exception as e:
            box["err"] = e

    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout=10)
    assert "err" not in box, box.get("err")
    assert box["got"] == _agent()


# ---------------------------------------------------------------- launchers


def test_launcher_crud(db: Database):
    reg = _launcher()
    db.add_launcher(reg)
    assert db.get_launcher("launcher-1") == reg
    db.add_launcher(_launcher("launcher-2", x="B" * 43))
    assert {launcher.launcher_id for launcher in db.list_launchers()} == {
        "launcher-1",
        "launcher-2",
    }
    assert db.delete_launcher("launcher-2") is True
    assert db.get_launcher("launcher-2") is None
    assert db.delete_launcher("launcher-2") is False


def test_unknown_launcher_is_none(db: Database):
    assert db.get_launcher("nobody") is None


def test_duplicate_launcher_raises_duplicate_error_and_keeps_original_key(db: Database):
    """Re-registering a launcher id must not silently swap in an attacker's key."""
    db.add_launcher(_launcher(x="A" * 43))
    with pytest.raises(DuplicateError):
        db.add_launcher(_launcher(x="Z" * 43))
    assert db.get_launcher("launcher-1").public_jwk.x == "A" * 43


# ---------------------------------------------------------------- agents


def test_agent_crud(db: Database):
    _seed_registry(db)
    rec = _agent()
    db.add_agent(rec)
    got = db.get_agent("expense-bot")
    assert got == rec
    assert isinstance(got.status, AgentStatus) and got.status is AgentStatus.REGISTERED
    assert got.created_at.tzinfo is not None
    db.add_agent(_agent("wire-bot", role="finance_ops"))
    assert {a.agent_id for a in db.list_agents()} == {"expense-bot", "wire-bot"}
    assert db.delete_agent("wire-bot") is True
    assert db.get_agent("wire-bot") is None
    assert db.delete_agent("wire-bot") is False


def test_duplicate_agent_raises_duplicate_error_and_keeps_golden_measurement(db: Database):
    """Re-registering must not overwrite the golden measurement (attestation bypass)."""
    _seed_registry(db)
    db.add_agent(_agent())
    with pytest.raises(DuplicateError):
        db.add_agent(_agent(golden_measurement="f" * 64))
    assert db.get_agent("expense-bot").golden_measurement == SHA


def test_quarantine_and_clear_update_status_and_timestamp(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    q_at = NOW + timedelta(minutes=3)
    assert db.set_agent_status("expense-bot", AgentStatus.QUARANTINED, quarantined_at=q_at)
    got = db.get_agent("expense-bot")
    assert got.status is AgentStatus.QUARANTINED
    assert got.quarantined_at == q_at
    assert db.set_agent_status("expense-bot", AgentStatus.REGISTERED, quarantined_at=None)
    got = db.get_agent("expense-bot")
    assert got.status is AgentStatus.REGISTERED and got.quarantined_at is None


def test_set_status_of_unknown_agent_returns_false(db: Database):
    assert db.set_agent_status("ghost-bot", AgentStatus.ACTIVE) is False
    assert db.get_agent("ghost-bot") is None


def test_status_change_affects_only_that_agent(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    db.add_agent(_agent("wire-bot"))
    db.set_agent_status("wire-bot", AgentStatus.QUARANTINED, quarantined_at=NOW)
    assert db.get_agent("expense-bot").status is AgentStatus.REGISTERED


def test_agent_unicode_and_large_description_round_trip(db: Database):
    _seed_registry(db)
    desc = "Spesen-Prüfer é中文 \U0001f916 " + "x" * 100_000
    db.add_agent(_agent(description=desc))
    assert db.get_agent("expense-bot").description == desc


def test_sql_injection_in_lookup_id_matches_nothing(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    assert db.get_agent(SQLI_OR) is None
    assert db.get_agent(SQLI) is None
    assert TABLES <= _tables(db_path_of(db))


def test_sql_injection_payload_in_text_field_round_trips_as_data(db: Database):
    _seed_registry(db)
    db.add_agent(_agent(description=SQLI))
    db.add_agent(_agent("wire-bot", description="Robert'); DROP TABLE agents;--"))
    assert db.get_agent("expense-bot").description == SQLI
    assert {a.agent_id for a in db.list_agents()} == {"expense-bot", "wire-bot"}


# ---------------------------------------------------------------- approvers + TOTP steps


def test_approver_crud(db: Database):
    db.add_approver("alice", display_name="Alice", totp_seed=SEED)
    got = db.get_approver("alice")
    assert got.approver_id == "alice"
    assert got.display_name == "Alice"
    assert got.totp_seed.get_secret_value() == SEED
    assert got.last_used_step is None
    db.add_approver("bob", display_name="Bob", totp_seed=SEED[::-1])
    assert {a.approver_id for a in db.list_approvers()} == {"alice", "bob"}
    assert db.delete_approver("bob") is True
    assert db.get_approver("bob") is None
    assert db.delete_approver("bob") is False


def test_approver_seed_never_appears_in_repr_or_str(db: Database):
    db.add_approver("alice", display_name="Alice", totp_seed=SEED)
    got = db.get_approver("alice")
    assert SEED not in repr(got)
    assert SEED not in str(got)
    for row in db.list_approvers():
        assert SEED not in repr(row)


def test_duplicate_approver_raises_and_keeps_original_seed(db: Database):
    """Re-enrolling must not let someone replace the human's TOTP seed with their own."""
    db.add_approver("alice", display_name="Alice", totp_seed=SEED)
    with pytest.raises(DuplicateError):
        db.add_approver("alice", display_name="Mallory", totp_seed="MALLORYSEEDMALLORYSEED")
    assert db.get_approver("alice").totp_seed.get_secret_value() == SEED


def test_unknown_approver_is_none(db: Database):
    assert db.get_approver("nobody") is None


def test_totp_step_can_be_used_once_then_replay_is_refused(db: Database):
    db.add_approver("alice", display_name="Alice", totp_seed=SEED)
    step = 59_000_000
    assert db.mark_totp_step_used("alice", step) is True
    assert db.get_approver("alice").last_used_step == step
    assert db.mark_totp_step_used("alice", step) is False  # replayed code


def test_totp_last_used_step_is_monotonic(db: Database):
    """valid_window=1 accepts the previous step too, so an older code must not roll back."""
    db.add_approver("alice", display_name="Alice", totp_seed=SEED)
    assert db.mark_totp_step_used("alice", 100) is True
    assert db.mark_totp_step_used("alice", 99) is False
    assert db.get_approver("alice").last_used_step == 100
    assert db.mark_totp_step_used("alice", 101) is True
    assert db.get_approver("alice").last_used_step == 101


def test_totp_step_for_unknown_approver_is_refused(db: Database):
    assert db.mark_totp_step_used("ghost", 1) is False
    assert db.mark_totp_step_used(SQLI_OR, 1) is False


def test_totp_steps_are_tracked_per_approver(db: Database):
    db.add_approver("alice", display_name="Alice", totp_seed=SEED)
    db.add_approver("bob", display_name="Bob", totp_seed=SEED)
    assert db.mark_totp_step_used("alice", 500) is True
    assert db.mark_totp_step_used("bob", 500) is True
    assert db.get_approver("bob").last_used_step == 500


def test_concurrent_use_of_same_totp_step_has_exactly_one_winner(db: Database):
    db.add_approver("alice", display_name="Alice", totp_seed=SEED)
    results, errors = _race(lambda: db.mark_totp_step_used("alice", 777))
    assert errors == []
    assert sorted(results) == [False] * (RACERS - 1) + [True]


def test_approver_display_name_injection_round_trips(db: Database):
    db.add_approver("alice", display_name=SQLI, totp_seed=SEED)
    assert db.get_approver("alice").display_name == SQLI
    assert TABLES <= _tables(db_path_of(db))


# ---------------------------------------------------------------- nonces


def test_nonce_crud(db: Database):
    exp = NOW + timedelta(seconds=60)
    db.add_nonce("n" * 32, "expense-bot", expires_at=exp)
    row = db.get_nonce("n" * 32)
    assert row.nonce == "n" * 32
    assert row.agent_id == "expense-bot"
    assert row.expires_at == exp
    assert not row.used
    assert db.get_nonce("unknown-nonce-value") is None


def test_nonce_consume_succeeds_once_and_second_consume_fails(db: Database):
    db.add_nonce("n" * 32, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    assert db.consume_nonce("n" * 32, "expense-bot", now=NOW) is True
    assert db.consume_nonce("n" * 32, "expense-bot", now=NOW) is False
    assert bool(db.get_nonce("n" * 32).used) is True


def test_nonce_issued_for_another_agent_is_refused(db: Database):
    db.add_nonce("n" * 32, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    assert db.consume_nonce("n" * 32, "wire-bot", now=NOW) is False


def test_expired_nonce_is_refused(db: Database):
    db.add_nonce("n" * 32, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    assert db.consume_nonce("n" * 32, "expense-bot", now=NOW + timedelta(seconds=61)) is False


def test_nonce_exactly_at_expiry_is_refused(db: Database):
    exp = NOW + timedelta(seconds=60)
    db.add_nonce("n" * 32, "expense-bot", expires_at=exp)
    assert db.consume_nonce("n" * 32, "expense-bot", now=exp) is False


def test_nonce_one_microsecond_before_expiry_is_accepted(db: Database):
    exp = NOW + timedelta(seconds=60)
    db.add_nonce("n" * 32, "expense-bot", expires_at=exp)
    assert db.consume_nonce("n" * 32, "expense-bot", now=exp - timedelta(microseconds=1))


def test_unknown_or_injected_nonce_is_refused_and_real_nonce_stays_unused(db: Database):
    db.add_nonce("n" * 32, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    assert db.consume_nonce("unknown-nonce-value", "expense-bot", now=NOW) is False
    assert db.consume_nonce(SQLI_OR, "expense-bot", now=NOW) is False
    assert db.consume_nonce("n" * 32, SQLI_OR, now=NOW) is False
    assert db.consume_nonce("", "expense-bot", now=NOW) is False
    assert not db.get_nonce("n" * 32).used


@pytest.mark.parametrize(
    ("now_offset", "now_tz", "expected"),
    [
        # Still valid, but written in +09:00 it sorts AFTER the UTC expiry as a string.
        (timedelta(seconds=30), timezone(timedelta(hours=9)), True),
        # Already expired, but written in -05:00 it sorts BEFORE the UTC expiry as a string.
        (timedelta(seconds=90), timezone(timedelta(hours=-5)), False),
    ],
    ids=["valid-in-plus9", "expired-in-minus5"],
)
def test_nonce_expiry_compares_instants_not_strings(
    db: Database, now_offset: timedelta, now_tz: timezone, expected: bool
):
    db.add_nonce("n" * 32, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    now = (NOW + now_offset).astimezone(now_tz)
    assert db.consume_nonce("n" * 32, "expense-bot", now=now) is expected


def test_duplicate_nonce_raises_duplicate_error(db: Database):
    db.add_nonce("n" * 32, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    with pytest.raises(DuplicateError):
        db.add_nonce("n" * 32, "wire-bot", expires_at=NOW + timedelta(hours=1))
    assert db.get_nonce("n" * 32).agent_id == "expense-bot"


def test_concurrent_nonce_consume_has_exactly_one_winner(db: Database):
    db.add_nonce("r" * 32, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    results, errors = _race(lambda: db.consume_nonce("r" * 32, "expense-bot", now=NOW))
    assert errors == []
    assert sorted(results) == [False] * (RACERS - 1) + [True]


def test_delete_expired_nonces_keeps_fresh_ones(db: Database):
    db.add_nonce("old" + "o" * 29, "expense-bot", expires_at=NOW - timedelta(seconds=1))
    db.add_nonce("edge" + "e" * 28, "expense-bot", expires_at=NOW)
    db.add_nonce("new" + "n" * 29, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    assert db.delete_expired_nonces(now=NOW) == 2
    assert db.get_nonce("old" + "o" * 29) is None
    assert db.get_nonce("edge" + "e" * 28) is None
    assert db.get_nonce("new" + "n" * 29) is not None


# ---------------------------------------------------------------- tokens + revocation


def test_token_crud(db: Database):
    tok = _token("jti-1")
    db.add_token(tok)
    got = db.get_token("jti-1")
    assert got == tok
    assert got.scopes == tok.scopes  # order preserved
    db.add_token(_token("jti-2", agent_id="wire-bot"))
    assert {t.jti for t in db.list_tokens()} == {"jti-1", "jti-2"}
    assert {t.jti for t in db.list_tokens(agent_id="wire-bot")} == {"jti-2"}
    assert db.revoke_token("jti-1") is True
    assert db.get_token("jti-1").revoked is True
    assert db.get_token("jti-2").revoked is False


def test_unknown_token_is_none_and_revoking_it_returns_false(db: Database):
    assert db.get_token("nope") is None
    assert db.revoke_token("nope") is False
    assert db.revoke_token(SQLI_OR) is False


def test_duplicate_jti_raises_duplicate_error(db: Database):
    db.add_token(_token("jti-1"))
    with pytest.raises(DuplicateError):
        db.add_token(_token("jti-1", agent_id="wire-bot"))
    assert db.get_token("jti-1").agent_id == "expense-bot"


def test_revoke_all_for_agent_revokes_every_token_of_that_agent_only(db: Database):
    db.add_token(_token("a1", agent_id="expense-bot", task_id="t1"))
    db.add_token(_token("a2", agent_id="expense-bot", task_id="t2"))
    db.add_token(_token("b1", agent_id="wire-bot", task_id="t3"))
    assert db.revoke_all_for_agent("expense-bot") == 2
    assert db.get_token("a1").revoked is True
    assert db.get_token("a2").revoked is True
    assert db.get_token("b1").revoked is False


def test_revoke_all_for_agent_counts_only_newly_revoked(db: Database):
    db.add_token(_token("a1"))
    db.add_token(_token("a2"))
    db.revoke_token("a1")
    assert db.revoke_all_for_agent("expense-bot") == 1
    assert db.revoke_all_for_agent("expense-bot") == 0


def test_revoke_all_for_unknown_or_injected_agent_revokes_nothing(db: Database):
    db.add_token(_token("a1"))
    assert db.revoke_all_for_agent("ghost-bot") == 0
    assert db.revoke_all_for_agent(SQLI_OR) == 0
    assert db.revoke_all_for_agent("%") == 0  # no LIKE-style wildcard matching
    assert db.get_token("a1").revoked is False


def test_revoke_task_tokens_revokes_only_that_task(db: Database):
    db.add_token(_token("a1", task_id="t1"))
    db.add_token(_token("a2", task_id="t2"))
    assert db.revoke_task_tokens("expense-bot", "t1") == 1
    assert db.get_token("a1").revoked is True
    assert db.get_token("a2").revoked is False


def test_revoke_task_tokens_is_scoped_to_the_owning_agent(db: Database):
    """Another agent naming my task_id must not revoke my token (cross-agent tampering)."""
    db.add_token(_token("a1", agent_id="expense-bot", task_id="t1"))
    assert db.revoke_task_tokens("wire-bot", "t1") == 0
    assert db.get_token("a1").revoked is False


def test_token_ids_with_quotes_and_unicode_round_trip(db: Database):
    tok = _token(jti="j'\"; DROP TABLE tokens;--☃", task_id=SQLI)
    db.add_token(tok)
    assert db.get_token(tok.jti) == tok
    assert TABLES <= _tables(db_path_of(db))


# ---------------------------------------------------------------- approvals


def test_approval_crud(db: Database):
    rec = _approval()
    db.add_approval(rec)
    got = db.get_approval("appr-1")
    assert got == rec
    assert got.args == rec.args and isinstance(got.args["amount"], float)
    db.add_approval(_approval("appr-2", status=ApprovalStatus.DENIED, decided_at=NOW))
    assert {a.approval_id for a in db.list_approvals()} == {"appr-1", "appr-2"}
    pending = db.list_approvals(status=ApprovalStatus.PENDING)
    assert [a.approval_id for a in pending] == ["appr-1"]


def test_unknown_approval_is_none(db: Database):
    assert db.get_approval("nope") is None
    assert db.get_approval(SQLI_OR) is None


def test_duplicate_approval_id_raises_duplicate_error(db: Database):
    db.add_approval(_approval())
    with pytest.raises(DuplicateError):
        db.add_approval(_approval(action_hash="c" * 64))
    assert db.get_approval("appr-1").action_hash == "b" * 64


def test_approval_decide_then_consume_lifecycle(db: Database):
    db.add_approval(_approval())
    decided = NOW + timedelta(seconds=30)
    assert db.transition_approval(
        "appr-1", ApprovalStatus.PENDING, ApprovalStatus.APPROVED, decided_at=decided
    )
    got = db.get_approval("appr-1")
    assert got.status is ApprovalStatus.APPROVED and got.decided_at == decided
    assert db.transition_approval("appr-1", ApprovalStatus.APPROVED, ApprovalStatus.USED)
    got = db.get_approval("appr-1")
    assert got.status is ApprovalStatus.USED
    assert got.decided_at == decided  # not cleared when decided_at is omitted


def test_approval_cannot_be_decided_twice(db: Database):
    db.add_approval(_approval())
    assert db.transition_approval(
        "appr-1", ApprovalStatus.PENDING, ApprovalStatus.DENIED, decided_at=NOW
    )
    assert (
        db.transition_approval(
            "appr-1", ApprovalStatus.PENDING, ApprovalStatus.APPROVED, decided_at=NOW
        )
        is False
    )
    assert db.get_approval("appr-1").status is ApprovalStatus.DENIED


def test_used_approval_cannot_be_consumed_again(db: Database):
    db.add_approval(_approval(status=ApprovalStatus.APPROVED, decided_at=NOW))
    assert db.transition_approval("appr-1", ApprovalStatus.APPROVED, ApprovalStatus.USED)
    assert db.transition_approval("appr-1", ApprovalStatus.APPROVED, ApprovalStatus.USED) is False


def test_transition_of_unknown_approval_returns_false(db: Database):
    assert db.transition_approval("nope", ApprovalStatus.PENDING, ApprovalStatus.APPROVED) is False


def test_transition_affects_only_the_named_approval(db: Database):
    db.add_approval(_approval("appr-1"))
    db.add_approval(_approval("appr-2"))
    db.transition_approval("appr-1", ApprovalStatus.PENDING, ApprovalStatus.EXPIRED)
    assert db.get_approval("appr-2").status is ApprovalStatus.PENDING


def test_concurrent_approval_consume_has_exactly_one_winner(db: Database):
    db.add_approval(_approval(status=ApprovalStatus.APPROVED, decided_at=NOW))
    results, errors = _race(
        lambda: db.transition_approval("appr-1", ApprovalStatus.APPROVED, ApprovalStatus.USED)
    )
    assert errors == []
    assert sorted(results) == [False] * (RACERS - 1) + [True]


def test_approval_args_with_injection_unicode_and_nesting_round_trip(db: Database):
    args = {
        "to": SQLI,
        "subject": "über \U0001f4b8",
        "body": "line1\nline2\x00tail",
        "nested": {"list": [1, 2.5, None, True, "x"]},
    }
    db.add_approval(_approval(tool="send_email", args=args))
    assert db.get_approval("appr-1").args == args


# ---------------------------------------------------------------- risk events


def test_risk_event_crud(db: Database):
    e1 = _event(at=NOW, details={"contributions": [{"rule": "sensitive", "points": 0}]})
    e2 = _event(
        at=NOW + timedelta(seconds=5),
        event_type=EventType.EXTERNAL_EGRESS,
        tool="send_email",
        target="external",
        details={"to_domain": "evil.example"},
    )
    db.add_risk_event(e1)
    db.add_risk_event(e2)
    assert db.list_risk_events("expense-bot") == [e1, e2]
    assert db.delete_risk_events("expense-bot") == 2
    assert db.list_risk_events("expense-bot") == []


def test_risk_events_optional_fields_round_trip_as_none(db: Database):
    e = _event(task_id=None, tool=None, target=None, event_type=EventType.TOKEN_FAILURE)
    db.add_risk_event(e)
    assert db.list_risk_events("expense-bot") == [e]


def test_risk_events_are_returned_in_timestamp_order(db: Database):
    late = _event(at=NOW + timedelta(minutes=2))
    early = _event(at=NOW)
    mid = _event(at=NOW + timedelta(minutes=1))
    for e in (late, early, mid):
        db.add_risk_event(e)
    assert [e.timestamp for e in db.list_risk_events("expense-bot")] == [
        early.timestamp,
        mid.timestamp,
        late.timestamp,
    ]


def test_risk_events_since_filter_is_inclusive(db: Database):
    db.add_risk_event(_event(at=NOW - timedelta(seconds=1)))
    db.add_risk_event(_event(at=NOW))
    db.add_risk_event(_event(at=NOW + timedelta(seconds=1)))
    got = db.list_risk_events("expense-bot", since=NOW)
    assert [e.timestamp for e in got] == [NOW, NOW + timedelta(seconds=1)]


def test_risk_events_are_isolated_per_agent(db: Database):
    db.add_risk_event(_event("expense-bot"))
    db.add_risk_event(_event("wire-bot"))
    assert [e.agent_id for e in db.list_risk_events("expense-bot")] == ["expense-bot"]
    assert db.delete_risk_events("expense-bot") == 1
    assert len(db.list_risk_events("wire-bot")) == 1


def test_risk_event_with_injection_agent_id_round_trips_as_data(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    db.add_risk_event(_event(SQLI))
    assert [e.agent_id for e in db.list_risk_events(SQLI)] == [SQLI]
    assert db.list_risk_events(SQLI_OR) == []
    assert db.get_agent("expense-bot") is not None  # agents table survived


# ---------------------------------------------------------------- audit


def test_audit_insert_and_list_round_trip_exactly(db: Database):
    """The audit chain hashes serialized records, so the round trip must be byte-exact."""
    recs = [_audit(i) for i in range(3)]
    for r in recs:
        db.insert_audit(r)
    got = db.list_audit()
    assert [g.model_dump_json() for g in got] == [r.model_dump_json() for r in recs]
    assert all(isinstance(g.reason_code, ReasonCode) for g in got)


def test_audit_info_outcome_and_unicode_details_round_trip(db: Database):
    rec = _audit(
        0,
        outcome="info",
        reason_code=ReasonCode.OK,
        actor="approver:alice",
        details={"msg": SQLI + " ✓", "n": [1, 2, {"k": None}]},
    )
    db.insert_audit(rec)
    assert db.list_audit()[0].model_dump_json() == rec.model_dump_json()


def test_last_audit_is_none_when_empty_and_highest_seq_otherwise(db: Database):
    assert db.last_audit() is None
    for i in range(4):
        db.insert_audit(_audit(i))
    assert db.last_audit() == _audit(3)


def test_list_audit_after_seq_and_limit(db: Database):
    for i in range(10):
        db.insert_audit(_audit(i))
    assert [r.seq for r in db.list_audit()] == list(range(10))  # default includes seq 0
    assert [r.seq for r in db.list_audit(after_seq=4, limit=3)] == [5, 6, 7]
    assert [r.seq for r in db.list_audit(after_seq=8, limit=100)] == [9]
    assert db.list_audit(after_seq=9, limit=100) == []


def test_duplicate_audit_seq_raises_duplicate_error(db: Database):
    db.insert_audit(_audit(0))
    with pytest.raises(DuplicateError):
        db.insert_audit(_audit(0, actor="mallory"))
    assert db.list_audit()[0].actor == "expense-bot"


def test_concurrent_inserts_of_same_audit_seq_have_exactly_one_winner(db: Database):
    results, errors = _race(lambda: db.insert_audit(_audit(0)))
    assert len(results) == 1
    assert len(errors) == RACERS - 1
    assert all(isinstance(e, DuplicateError) for e in errors), errors
    assert [r.seq for r in db.list_audit()] == [0]


def test_audit_has_no_update_or_delete_repository_method():
    """Append-only by design. Tampering is only possible through raw SQL, which T1.3 detects."""
    names = [n for n in dir(Database) if not n.startswith("_") and "audit" in n.lower()]
    forbidden = [n for n in names if re.match(r"(update|delete|remove|set|edit|clear)", n)]
    assert forbidden == []


def test_large_audit_details_round_trip(db: Database):
    rec = _audit(0, details={"blob": "é" * 200_000})
    db.insert_audit(rec)
    assert db.list_audit()[0].details == rec.details


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
    """Automated backstop for the 'all queries are parameterized' review check (rule 8).

    Flags f-strings, .format(), % and + that mix SQL keywords with non-constant values.
    Values must go through ``?`` placeholders instead.
    """
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


# ================================================================ security-review follow-up
# Guarded status changes, atomic quarantine, bound approval decide/consume, cascading
# agent delete, and missing negative tests. Interface documented in the module docstring.


def _quarantined_agent(db: Database, at: datetime = NOW) -> None:
    _seed_registry(db)
    db.add_agent(_agent())
    db.set_agent_status("expense-bot", AgentStatus.QUARANTINED, quarantined_at=at)


# ---------------------------------------------------------------- guarded status


def test_activate_agent_sets_active_for_registered_agent(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    assert db.activate_agent("expense-bot") is True
    assert db.get_agent("expense-bot").status is AgentStatus.ACTIVE


def test_stale_activation_cannot_overwrite_quarantine(db: Database):
    """A /attest that started before the monitor quarantined the agent must not undo it."""
    q_at = NOW + timedelta(minutes=1)
    _quarantined_agent(db, at=q_at)
    assert db.activate_agent("expense-bot") is False
    got = db.get_agent("expense-bot")
    assert got.status is AgentStatus.QUARANTINED
    assert got.quarantined_at == q_at


def test_activate_unknown_agent_returns_false(db: Database):
    assert db.activate_agent("ghost-bot") is False
    assert db.activate_agent(SQLI_OR) is False
    assert db.get_agent("ghost-bot") is None


def test_set_agent_status_without_expected_returns_bool(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    assert db.set_agent_status("expense-bot", AgentStatus.ACTIVE) is True
    assert db.set_agent_status("ghost-bot", AgentStatus.ACTIVE) is False


def test_set_agent_status_with_matching_expected_succeeds(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    ok = db.set_agent_status("expense-bot", AgentStatus.ACTIVE, expected=AgentStatus.REGISTERED)
    assert ok is True
    assert db.get_agent("expense-bot").status is AgentStatus.ACTIVE


def test_set_agent_status_with_mismatched_expected_changes_nothing(db: Database):
    q_at = NOW + timedelta(minutes=1)
    _quarantined_agent(db, at=q_at)
    ok = db.set_agent_status(
        "expense-bot", AgentStatus.ACTIVE, quarantined_at=None, expected=AgentStatus.REGISTERED
    )
    assert ok is False
    got = db.get_agent("expense-bot")
    assert got.status is AgentStatus.QUARANTINED
    assert got.quarantined_at == q_at


# ---------------------------------------------------------------- atomic quarantine


def test_quarantine_agent_sets_status_and_revokes_tokens(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    db.add_agent(_agent("wire-bot"))
    db.add_token(_token("a1", task_id="t1"))
    db.add_token(_token("a2", task_id="t2"))
    db.add_token(_token("a3", task_id="t3"))
    db.revoke_token("a3")  # already revoked: not counted
    db.add_token(_token("b1", agent_id="wire-bot", task_id="t9"))
    q_at = NOW + timedelta(minutes=2)

    assert db.quarantine_agent("expense-bot", at=q_at) == 2

    got = db.get_agent("expense-bot")
    assert got.status is AgentStatus.QUARANTINED and got.quarantined_at == q_at
    assert db.get_token("a1").revoked is True
    assert db.get_token("a2").revoked is True
    assert db.get_token("b1").revoked is False
    assert db.get_agent("wire-bot").status is AgentStatus.REGISTERED


def test_quarantine_agent_with_no_tokens_still_quarantines(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    assert db.quarantine_agent("expense-bot", at=NOW) == 0
    assert db.get_agent("expense-bot").status is AgentStatus.QUARANTINED


def test_quarantine_unknown_agent_changes_nothing(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    db.add_token(_token("a1"))
    assert db.quarantine_agent("ghost-bot", at=NOW) == 0
    assert db.quarantine_agent(SQLI_OR, at=NOW) == 0
    assert db.get_token("a1").revoked is False
    assert db.get_agent("expense-bot").status is AgentStatus.REGISTERED
    assert db.get_agent("ghost-bot") is None


def test_clear_quarantine_resets_to_registered_and_keeps_tokens_revoked(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    db.add_token(_token("a1"))
    db.quarantine_agent("expense-bot", at=NOW)
    assert db.clear_quarantine("expense-bot") is True
    got = db.get_agent("expense-bot")
    assert got.status is AgentStatus.REGISTERED and got.quarantined_at is None
    assert db.get_token("a1").revoked is True  # clearing never un-revokes


def test_clear_quarantine_on_non_quarantined_or_unknown_agent_returns_false(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    db.activate_agent("expense-bot")
    assert db.clear_quarantine("expense-bot") is False
    assert db.get_agent("expense-bot").status is AgentStatus.ACTIVE
    assert db.clear_quarantine("ghost-bot") is False


# ---------------------------------------------------------------- decide_approval


def test_decide_approval_approve_sets_status_and_decided_at(db: Database):
    db.add_approval(_approval())
    now = NOW + timedelta(seconds=30)
    assert db.decide_approval("appr-1", approver_id="alice", approve=True, now=now) is True
    got = db.get_approval("appr-1")
    assert got.status is ApprovalStatus.APPROVED and got.decided_at == now


def test_decide_approval_deny_sets_denied(db: Database):
    db.add_approval(_approval())
    assert db.decide_approval("appr-1", approver_id="alice", approve=False, now=NOW) is True
    got = db.get_approval("appr-1")
    assert got.status is ApprovalStatus.DENIED and got.decided_at == NOW


def test_decide_approval_by_wrong_approver_is_refused(db: Database):
    db.add_approval(_approval())
    assert db.decide_approval("appr-1", approver_id="mallory", approve=True, now=NOW) is False
    assert db.decide_approval("appr-1", approver_id=SQLI_OR, approve=True, now=NOW) is False
    got = db.get_approval("appr-1")
    assert got.status is ApprovalStatus.PENDING and got.decided_at is None


@pytest.mark.parametrize(
    "after_expiry", [timedelta(0), timedelta(seconds=1)], ids=["exactly-at", "after"]
)
def test_decide_approval_at_or_after_expiry_is_refused(db: Database, after_expiry: timedelta):
    rec = _approval()
    db.add_approval(rec)
    now = rec.expires_at + after_expiry
    assert db.decide_approval("appr-1", approver_id="alice", approve=True, now=now) is False
    assert db.get_approval("appr-1").status is ApprovalStatus.PENDING


def test_decide_approval_twice_is_refused(db: Database):
    db.add_approval(_approval())
    assert db.decide_approval("appr-1", approver_id="alice", approve=False, now=NOW)
    assert db.decide_approval("appr-1", approver_id="alice", approve=True, now=NOW) is False
    assert db.get_approval("appr-1").status is ApprovalStatus.DENIED


def test_decide_unknown_approval_returns_false(db: Database):
    assert db.decide_approval("nope", approver_id="alice", approve=True, now=NOW) is False


def test_concurrent_decide_approval_has_exactly_one_winner(db: Database):
    db.add_approval(_approval())
    results, errors = _race(
        lambda: db.decide_approval("appr-1", approver_id="alice", approve=True, now=NOW)
    )
    assert errors == []
    assert sorted(results) == [False] * (RACERS - 1) + [True]


# ---------------------------------------------------------------- consume_approval

HASH = "b" * 64  # action_hash used by _approval()


def _approved(db: Database, **kw: Any) -> ApprovalRecord:
    rec = _approval(status=ApprovalStatus.APPROVED, decided_at=NOW, **kw)
    db.add_approval(rec)
    return rec


def _consume(db: Database, *, agent_id: str = "wire-bot", action_hash: str = HASH, now=NOW):
    return db.consume_approval("appr-1", agent_id=agent_id, action_hash=action_hash, now=now)


def test_consume_approval_happy_path_marks_used(db: Database):
    _approved(db)
    assert _consume(db) is True
    got = db.get_approval("appr-1")
    assert got.status is ApprovalStatus.USED
    assert got.decided_at == NOW


def test_consume_approval_with_different_action_hash_is_refused(db: Database):
    """The approval was for one exact action; different args must not ride on it."""
    _approved(db)
    assert _consume(db, action_hash="c" * 64) is False
    assert db.get_approval("appr-1").status is ApprovalStatus.APPROVED


def test_consume_approval_by_another_agent_is_refused(db: Database):
    _approved(db)
    assert _consume(db, agent_id="expense-bot") is False
    assert _consume(db, agent_id=SQLI_OR) is False
    assert db.get_approval("appr-1").status is ApprovalStatus.APPROVED


@pytest.mark.parametrize(
    "after_expiry", [timedelta(0), timedelta(seconds=1)], ids=["exactly-at", "after"]
)
def test_consume_approval_at_or_after_expiry_is_refused(db: Database, after_expiry: timedelta):
    rec = _approved(db)
    assert _consume(db, now=rec.expires_at + after_expiry) is False
    assert db.get_approval("appr-1").status is ApprovalStatus.APPROVED


@pytest.mark.parametrize("status", [ApprovalStatus.PENDING, ApprovalStatus.DENIED])
def test_consume_approval_that_is_not_approved_is_refused(db: Database, status: ApprovalStatus):
    decided = None if status is ApprovalStatus.PENDING else NOW
    db.add_approval(_approval(status=status, decided_at=decided))
    assert _consume(db) is False
    assert db.get_approval("appr-1").status is status


def test_second_consume_approval_is_refused(db: Database):
    _approved(db)
    assert _consume(db) is True
    assert _consume(db) is False
    assert db.get_approval("appr-1").status is ApprovalStatus.USED


def test_consume_unknown_approval_returns_false(db: Database):
    assert db.consume_approval("nope", agent_id="wire-bot", action_hash=HASH, now=NOW) is False


def test_concurrent_consume_approval_has_exactly_one_winner(db: Database):
    _approved(db)
    results, errors = _race(lambda: _consume(db))
    assert errors == []
    assert sorted(results) == [False] * (RACERS - 1) + [True]


# ---------------------------------------------------------------- cascading agent delete


def test_delete_agent_revokes_tokens_and_deletes_nonces(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    db.add_agent(_agent("wire-bot"))
    db.add_token(_token("a1", task_id="t1"))
    db.add_token(_token("a2", task_id="t2"))
    db.add_token(_token("b1", agent_id="wire-bot", task_id="t9"))
    db.add_nonce("e" * 32, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    db.add_nonce("w" * 32, "wire-bot", expires_at=NOW + timedelta(seconds=60))

    assert db.delete_agent("expense-bot") is True

    assert db.get_token("a1").revoked is True
    assert db.get_token("a2").revoked is True
    assert db.get_nonce("e" * 32) is None
    assert db.get_token("b1").revoked is False
    assert db.get_nonce("w" * 32) is not None


def test_re_registering_deleted_agent_does_not_resurrect_tokens_or_nonces(db: Database):
    _seed_registry(db)
    db.add_agent(_agent())
    db.add_token(_token("a1"))
    db.add_nonce("e" * 32, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    db.delete_agent("expense-bot")

    db.add_agent(_agent())  # same agent_id registered again

    assert db.get_token("a1").revoked is True
    assert db.consume_nonce("e" * 32, "expense-bot", now=NOW) is False


# ---------------------------------------------------------------- missing negative tests


def test_add_nonce_with_naive_expiry_is_rejected(db: Database):
    with pytest.raises(ValueError):
        db.add_nonce("n" * 32, "expense-bot", expires_at=datetime(2026, 11, 12, 12, 1))
    assert db.get_nonce("n" * 32) is None


def test_consume_nonce_with_naive_now_is_rejected(db: Database):
    db.add_nonce("n" * 32, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    with pytest.raises(ValueError):
        db.consume_nonce("n" * 32, "expense-bot", now=datetime(2026, 11, 12, 12, 0))
    assert not db.get_nonce("n" * 32).used


@pytest.mark.parametrize("nonce", ["", "a", "x" * 15], ids=["empty", "one-char", "15-chars"])
def test_add_nonce_shorter_than_16_chars_is_rejected(db: Database, nonce: str):
    with pytest.raises(ValueError):
        db.add_nonce(nonce, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    assert db.get_nonce(nonce) is None


def test_add_nonce_of_exactly_16_chars_is_accepted(db: Database):
    db.add_nonce("x" * 16, "expense-bot", expires_at=NOW + timedelta(seconds=60))
    assert db.get_nonce("x" * 16) is not None


@pytest.mark.parametrize(
    ("current", "new"),
    [
        (ApprovalStatus.DENIED, ApprovalStatus.APPROVED),
        (ApprovalStatus.USED, ApprovalStatus.APPROVED),
        (ApprovalStatus.PENDING, ApprovalStatus.USED),
        (ApprovalStatus.EXPIRED, ApprovalStatus.APPROVED),
    ],
    ids=["denied-to-approved", "used-to-approved", "pending-to-used", "expired-to-approved"],
)
def test_illegal_approval_transition_raises_and_leaves_row_unchanged(
    db: Database, current: ApprovalStatus, new: ApprovalStatus
):
    decided = None if current is ApprovalStatus.PENDING else NOW
    rec = _approval(status=current, decided_at=decided)
    db.add_approval(rec)
    with pytest.raises(ValueError):
        db.transition_approval("appr-1", current, new, decided_at=NOW + timedelta(seconds=9))
    assert db.get_approval("appr-1") == rec


def test_list_audit_with_negative_limit_is_rejected(db: Database):
    for i in range(3):
        db.insert_audit(_audit(i))
    with pytest.raises(ValueError):
        db.list_audit(limit=-1)
