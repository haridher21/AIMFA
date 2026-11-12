"""Tests for T1.3: audit hash chain (aimfa/control_plane/audit.py).

Hash rule: seq starts at 0, genesis prev_hash is "0"*64, and
hash = sha256(prev_hash + canonical_json(record minus hash)). verify() returns
ok=False / AUDIT_CHAIN_BROKEN with first_bad_seq = first failing row in seq order.
Tampering is done with raw SQL through ``Database.connect()``.

Known limitations (strict xfails): a keyless chain cannot detect truncation of the newest
rows or a full rewrite with recomputed hashes; both need an external anchor.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aimfa.common.db import Database
from aimfa.common.models import (
    AuditAppend,
    AuditRecord,
    AuditVerifyResult,
    DecisionOutcome,
    ReasonCode,
)
from aimfa.control_plane import audit as audit_module

AuditLog = audit_module.AuditLog

GENESIS = "0" * 64
T0 = datetime(2026, 11, 12, 12, 0, 0, 123456, tzinfo=UTC)
CHAIN_LEN = 5
MIDDLE = 2


class FakeClock:
    """Deterministic, thread-safe clock: T0, T0+1s, T0+2s, ..."""

    def __init__(self, start: datetime = T0) -> None:
        self._lock = threading.Lock()
        self._next = start

    def __call__(self) -> datetime:
        with self._lock:
            t = self._next
            self._next = t + timedelta(seconds=1)
            return t


def expected_hash(rec: AuditRecord) -> str:
    body = rec.model_dump(mode="json", exclude={"hash"})
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(rec.prev_hash.encode() + canon.encode()).hexdigest()


def _entry(i: int = 0, **kw: Any) -> AuditAppend:
    fields: dict[str, Any] = {
        "component": "gateway",
        "actor": "expense-bot",
        "event": "gateway.tool_call",
        "outcome": DecisionOutcome.DENY,
        "reason_code": ReasonCode.SCOPE_DENIED,
        "details": {"jti": f"jti-{i}", "tool": "read_file", "n": i},
    }
    fields.update(kw)
    return AuditAppend(**fields)


def _fill(log: AuditLog, n: int = CHAIN_LEN) -> list[AuditRecord]:
    return [log.append(_entry(i)) for i in range(n)]


def _exec(db: Database, sql: str, params: tuple[Any, ...] = ()) -> None:
    with db.connect() as conn:
        conn.execute(sql, params)


_UPDATE_SQL: dict[str, str] = {
    "prev_hash": "UPDATE audit SET prev_hash = ? WHERE seq = ?",
    "hash": "UPDATE audit SET hash = ? WHERE seq = ?",
    "actor": "UPDATE audit SET actor = ? WHERE seq = ?",
    "outcome": "UPDATE audit SET outcome = ? WHERE seq = ?",
    "seq": "UPDATE audit SET seq = ? WHERE seq = ?",
    "details": "UPDATE audit SET details = ? WHERE seq = ?",
    "timestamp": "UPDATE audit SET timestamp = ? WHERE seq = ?",
}


def _set(db: Database, column: str, value: Any, seq: int) -> None:
    _exec(db, _UPDATE_SQL[column], (value, seq))


def _assert_broken_at(result: AuditVerifyResult, seq: int) -> None:
    assert result.ok is False
    assert result.reason_code is ReasonCode.AUDIT_CHAIN_BROKEN
    assert result.first_bad_seq == seq


def _assert_ok(result: AuditVerifyResult, n: int) -> None:
    assert result.ok is True
    assert result.reason_code is ReasonCode.OK
    assert result.first_bad_seq is None
    assert result.records_checked == n


@pytest.fixture
def db(tmp_path: Path) -> Database:
    return Database(tmp_path / "aimfa.db")


@pytest.fixture
def log(db: Database) -> AuditLog:
    return AuditLog(db, clock=FakeClock())


# ---------------------------------------------------------------- append + hash rule


def test_empty_chain_verifies_ok(log: AuditLog):
    _assert_ok(log.verify(), 0)


def test_records_link_and_follow_the_documented_hash_rule(db: Database, log: AuditLog):
    recs = _fill(log, CHAIN_LEN)
    assert [r.seq for r in recs] == list(range(CHAIN_LEN))
    assert recs[0].prev_hash == GENESIS
    assert recs[0].timestamp == T0
    for prev, cur in zip(recs, recs[1:], strict=False):
        assert cur.prev_hash == prev.hash
    assert all(r.hash == expected_hash(r) for r in recs)
    assert [r.model_dump_json() for r in db.list_audit()] == [r.model_dump_json() for r in recs]
    _assert_ok(log.verify(), CHAIN_LEN)


def test_caller_supplied_seq_timestamp_and_hashes_are_ignored(log: AuditLog):
    forged = AuditRecord(
        **_entry(0).model_dump(),
        seq=999,
        timestamp=datetime(2000, 1, 1, tzinfo=UTC),
        prev_hash="f" * 64,
        hash="e" * 64,
    )
    rec = log.append(forged)
    assert (rec.seq, rec.prev_hash, rec.timestamp) == (0, GENESIS, T0)
    assert rec.hash == expected_hash(rec)
    _assert_ok(log.verify(), 1)


def test_verify_walks_past_the_first_page_of_rows(db: Database, log: AuditLog):
    _fill(log, 250)
    _assert_ok(log.verify(), 250)
    _set(db, "actor", "mallory", 230)
    _assert_broken_at(log.verify(), 230)


# ---------------------------------------------------------------- tampering


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("actor", "mallory"),
        ("prev_hash", "f" * 64),
        ("hash", "e" * 64),
        ("details", '{"jti":"jti-2","n":2.0,"tool":"read_file"}'),  # int -> float
    ],
)
def test_changing_a_field_of_a_middle_row_breaks_the_chain_at_that_row(
    db: Database, log: AuditLog, column: str, value: str
):
    _fill(log)
    _set(db, column, value, MIDDLE)
    _assert_broken_at(log.verify(), MIDDLE)


@pytest.mark.parametrize("seq", [0, CHAIN_LEN - 1])
def test_changing_the_first_or_last_row_is_detected(db: Database, log: AuditLog, seq: int):
    _fill(log)
    _set(db, "actor", "mallory", seq)
    _assert_broken_at(log.verify(), seq)


def test_changing_the_seq_of_a_middle_row_is_detected(db: Database, log: AuditLog):
    _fill(log)
    _set(db, "seq", 99, MIDDLE)
    _assert_broken_at(log.verify(), MIDDLE + 1)


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("outcome", "maybe"),
        ("hash", "A" * 64),  # uppercase hex is not the contract format
        ("details", "{not json"),
    ],
)
def test_row_that_fails_model_validation_is_reported_broken_not_raised(
    db: Database, log: AuditLog, column: str, value: str
):
    """Fail closed: corrupt data yields ok=false, never an exception."""
    _fill(log)
    _set(db, column, value, MIDDLE)
    _assert_broken_at(log.verify(), MIDDLE)


def test_deleting_a_middle_row_is_detected(db: Database, log: AuditLog):
    _fill(log)
    _exec(db, "DELETE FROM audit WHERE seq = ?", (MIDDLE,))
    _assert_broken_at(log.verify(), MIDDLE + 1)


def test_deleting_the_genesis_row_is_detected(db: Database, log: AuditLog):
    _fill(log)
    _exec(db, "DELETE FROM audit WHERE seq = ?", (0,))
    _assert_broken_at(log.verify(), 1)


def test_swapping_two_rows_is_detected_at_the_earlier_position(db: Database, log: AuditLog):
    _fill(log)
    with db.connect() as conn:
        conn.execute("UPDATE audit SET seq = ? WHERE seq = ?", (-1_000, 1))
        conn.execute("UPDATE audit SET seq = ? WHERE seq = ?", (1, 3))
        conn.execute("UPDATE audit SET seq = ? WHERE seq = ?", (3, -1_000))
    _assert_broken_at(log.verify(), 1)


def test_forged_row_with_valid_hash_after_a_seq_gap_is_detected(db: Database, log: AuditLog):
    recs = _fill(log)
    forged = AuditRecord(
        **_entry(0, actor="mallory").model_dump(),
        seq=10,
        timestamp=T0 + timedelta(hours=1),
        prev_hash=recs[-1].hash,
        hash="0" * 64,
    )
    db.insert_audit(forged.model_copy(update={"hash": expected_hash(forged)}))
    _assert_broken_at(log.verify(), 10)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known limitation: a keyless hash chain cannot detect truncation of the newest "
        "rows. Needs an external anchor (e.g. signed/published head hash). Not in T1.3."
    ),
)
def test_deleting_the_newest_row_is_detected(db: Database, log: AuditLog):
    _fill(log)
    _exec(db, "DELETE FROM audit WHERE seq = ?", (CHAIN_LEN - 1,))
    assert log.verify().ok is False


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known limitation: the hash rule is public and keyless, so an attacker with DB "
        "write access can edit a row and recompute every later hash. Needs an anchor/HMAC."
    ),
)
def test_editing_a_row_and_recomputing_all_later_hashes_is_detected(db: Database, log: AuditLog):
    recs = _fill(log)
    prev = recs[MIDDLE - 1].hash
    rewritten: list[AuditRecord] = []
    for rec in recs[MIDDLE:]:
        update: dict[str, Any] = {"prev_hash": prev}
        if rec.seq == MIDDLE:
            update["actor"] = "mallory"
        new = rec.model_copy(update=update)
        new = new.model_copy(update={"hash": expected_hash(new)})
        rewritten.append(new)
        prev = new.hash
    _exec(db, "DELETE FROM audit WHERE seq >= ?", (MIDDLE,))
    for new in rewritten:
        db.insert_audit(new)
    assert log.verify().ok is False


# ---------------------------------------------------------------- concurrency, list, conventions


def _run_threads(fns: list[Callable[[], Any]]) -> tuple[list[Any], list[Exception]]:
    barrier = threading.Barrier(len(fns))
    results: list[Any] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def worker(fn: Callable[[], Any]) -> None:
        barrier.wait()
        try:
            r = fn()
        except Exception as e:  # collected and asserted on below
            with lock:
                errors.append(e)
        else:
            with lock:
                results.extend(r)

    threads = [threading.Thread(target=worker, args=(fn,)) for fn in fns]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not any(t.is_alive() for t in threads), "a worker hung (deadlock?)"
    return results, errors


def test_concurrent_appends_from_two_log_instances_stay_a_single_chain(tmp_path: Path):
    """Serialization must be at the database level, not just an in-process lock."""
    path = tmp_path / "aimfa.db"
    clock = FakeClock()
    logs = [AuditLog(Database(path), clock=clock) for _ in range(2)]
    fns = [
        (lambda lg=logs[w % 2], w=w: [lg.append(_entry(w * 100 + j)) for j in range(5)])
        for w in range(16)
    ]
    results, errors = _run_threads(fns)
    assert errors == []
    assert sorted(r.seq for r in results) == list(range(80))
    _assert_ok(logs[0].verify(), 80)


def test_hash_comparisons_use_constant_time_compare():
    """AGENTS.md rule 3: hashes are compared with hmac.compare_digest, never ==."""
    assert "compare_digest" in inspect.getsource(audit_module)
