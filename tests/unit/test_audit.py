"""Tests for T1.3: audit hash chain (aimfa/control_plane/audit.py).

Written from ROADMAP + CONTRACTS before the implementation exists. Tampering is done
with raw SQL through ``Database.connect()`` (T1.5), because the repository has no
update/delete method for audit rows on purpose.

Chosen interface (assumptions)
------------------------------
``from aimfa.control_plane.audit import AuditLog``

* ``AuditLog(db: Database, *, clock: Callable[[], datetime] | None = None)``.
  ``clock`` is a zero-argument callable returning a timezone-aware datetime; it is the
  record's ``timestamp``. When omitted, the log uses the current UTC time.
* ``append(entry: AuditAppend) -> AuditRecord`` assigns ``seq``, ``timestamp``,
  ``prev_hash`` and ``hash`` itself, stores the record, and returns it. If the caller
  passes an ``AuditRecord`` (a subclass of ``AuditAppend``), its seq/timestamp/hashes
  are ignored and recomputed.
* ``verify() -> AuditVerifyResult`` never raises because of stored data. It walks ALL
  rows (not just the first page of ``db.list_audit``) in ascending ``seq`` order.
* ``list(after_seq: int, limit: int) -> list[AuditRecord]``: rows with seq > after_seq,
  ascending, at most ``limit`` (same semantics as ``Database.list_audit``).

Hash rule (precise reading of ROADMAP)
--------------------------------------
* ``seq`` starts at **0**; the genesis record's ``prev_hash`` is ``"0" * 64``.
* ``body = record.model_dump(mode="json", exclude={"hash"})`` -- every field except
  ``hash``, INCLUDING ``prev_hash``, ``seq`` and ``timestamp``.
* ``hash = sha256(prev_hash.encode("utf-8") + canonical_json(body)).hexdigest()``
  where ``canonical_json`` is the CONTRACTS.md rule (sort_keys, ``(",", ":")``
  separators, ``ensure_ascii=False``, UTF-8). The tests recompute this with hashlib and
  json directly so they do not depend on T1.1's crypto module.

Verification rule
-----------------
A chain is valid iff the rows are seq 0, 1, 2, ... with no gaps, every row passes
``AuditRecord`` validation, row 0 has the genesis prev_hash, every other row's
prev_hash equals the previous row's hash, and every row's stored hash equals the
recomputed hash. On failure: ``ok=False``, ``reason_code=AUDIT_CHAIN_BROKEN`` and
``first_bad_seq`` is the **stored seq of the first row, in ascending seq order, that
fails any check**. So deleting row 2 reports 3 (the first survivor whose link is
broken). On success: ``ok=True``, ``reason_code=OK``, ``first_bad_seq=None`` and
``records_checked`` equals the number of rows.

Known limitation (documented with strict xfails below)
------------------------------------------------------
A keyless hash chain cannot detect (a) deleting the newest rows or (b) an attacker who
rewrites a row and then recomputes every hash after it. Detecting those needs an
external anchor (e.g. a signed/published head hash), which is outside T1.3.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
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

# ---------------------------------------------------------------- helpers

GENESIS = "0" * 64
T0 = datetime(2026, 11, 12, 12, 0, 0, 123456, tzinfo=UTC)
CHAIN_LEN = 5
MIDDLE = 2


class FakeClock:
    """Deterministic, thread-safe clock: T0, T0+1s, T0+2s, ..."""

    def __init__(self, start: datetime = T0, step: timedelta = timedelta(seconds=1)) -> None:
        self._lock = threading.Lock()
        self._next = start
        self._step = step

    def __call__(self) -> datetime:
        with self._lock:
            t = self._next
            self._next = t + self._step
            return t


def canonical_json(obj: Any) -> bytes:
    """CONTRACTS.md canonical JSON, re-implemented here to stay independent of T1.1."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def expected_hash(rec: AuditRecord) -> str:
    body = rec.model_dump(mode="json", exclude={"hash"})
    return hashlib.sha256(rec.prev_hash.encode("utf-8") + canonical_json(body)).hexdigest()


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
    """Raw SQL as an attacker with file access would do it (committed on exit)."""
    with db.connect() as conn:
        conn.execute(sql, params)


# Constant SQL per column (no string formatting in SQL, even in tests).
_UPDATE_SQL: dict[str, str] = {
    "seq": "UPDATE audit SET seq = ? WHERE seq = ?",
    "timestamp": "UPDATE audit SET timestamp = ? WHERE seq = ?",
    "prev_hash": "UPDATE audit SET prev_hash = ? WHERE seq = ?",
    "hash": "UPDATE audit SET hash = ? WHERE seq = ?",
    "component": "UPDATE audit SET component = ? WHERE seq = ?",
    "actor": "UPDATE audit SET actor = ? WHERE seq = ?",
    "event": "UPDATE audit SET event = ? WHERE seq = ?",
    "outcome": "UPDATE audit SET outcome = ? WHERE seq = ?",
    "reason_code": "UPDATE audit SET reason_code = ? WHERE seq = ?",
    "details": "UPDATE audit SET details = ? WHERE seq = ?",
}


def _set(db: Database, column: str, value: Any, seq: int) -> None:
    _exec(db, _UPDATE_SQL[column], (value, seq))


def _swap_seq(db: Database, a: int, b: int) -> None:
    """Exchange two rows' positions in the chain by swapping their seq numbers."""
    with db.connect() as conn:
        conn.execute("UPDATE audit SET seq = ? WHERE seq = ?", (-1_000, a))
        conn.execute("UPDATE audit SET seq = ? WHERE seq = ?", (a, b))
        conn.execute("UPDATE audit SET seq = ? WHERE seq = ?", (b, -1_000))


def _raw_seqs(db: Database) -> list[int]:
    with db.connect() as conn:
        return [r[0] for r in conn.execute("SELECT seq FROM audit ORDER BY seq").fetchall()]


def _assert_broken_at(result: AuditVerifyResult, seq: int) -> None:
    assert isinstance(result, AuditVerifyResult)
    assert result.ok is False
    assert result.reason_code is ReasonCode.AUDIT_CHAIN_BROKEN
    assert result.first_bad_seq == seq


def _assert_ok(result: AuditVerifyResult, n: int) -> None:
    assert isinstance(result, AuditVerifyResult)
    assert result.ok is True
    assert result.reason_code is ReasonCode.OK
    assert result.first_bad_seq is None
    assert result.records_checked == n


@pytest.fixture
def db(tmp_path: Path) -> Database:
    return Database(tmp_path / "aimfa.db")


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def log(db: Database, clock: FakeClock) -> AuditLog:
    return AuditLog(db, clock=clock)


# ---------------------------------------------------------------- append + hash rule


def test_empty_chain_verifies_ok(log: AuditLog):
    _assert_ok(log.verify(), 0)


def test_first_record_has_seq_zero_and_genesis_prev_hash(log: AuditLog):
    rec = log.append(_entry(0))
    assert rec.seq == 0
    assert rec.prev_hash == GENESIS


def test_append_copies_the_entry_and_stamps_the_injected_clock(log: AuditLog):
    entry = _entry(7, outcome="info", reason_code=ReasonCode.OK, actor="approver:alice")
    rec = log.append(entry)
    assert isinstance(rec, AuditRecord)
    assert rec.model_dump(include=set(AuditAppend.model_fields)) == entry.model_dump()
    assert rec.timestamp == T0


def test_record_hash_follows_the_documented_rule(log: AuditLog):
    for rec in _fill(log, 3):
        assert rec.hash == expected_hash(rec)


def test_each_record_links_to_the_previous_hash_and_seq_increments(log: AuditLog):
    recs = _fill(log, CHAIN_LEN)
    assert [r.seq for r in recs] == list(range(CHAIN_LEN))
    assert recs[0].prev_hash == GENESIS
    for prev, cur in zip(recs, recs[1:], strict=False):
        assert cur.prev_hash == prev.hash
    assert len({r.hash for r in recs}) == CHAIN_LEN


def test_appended_records_are_persisted_exactly(db: Database, log: AuditLog):
    recs = _fill(log, 3)
    assert [r.model_dump_json() for r in db.list_audit()] == [r.model_dump_json() for r in recs]


def test_hash_rule_holds_for_mixed_components_outcomes_and_unicode(log: AuditLog):
    entries = [
        _entry(
            0,
            component="control_plane",
            actor="admin",
            outcome="info",
            reason_code=ReasonCode.OK,
            event="registry.agent_added",
        ),
        _entry(
            1,
            component="launcher",
            actor="system",
            outcome=DecisionOutcome.ALLOW,
            reason_code=ReasonCode.OK,
        ),
        _entry(
            2,
            component="dashboard",
            actor="approver:alice",
            outcome=DecisionOutcome.PENDING,
            reason_code=ReasonCode.PENDING_APPROVAL,
        ),
        _entry(
            3,
            details={
                "msg": "Spesen-Prüfer 中文 \U0001f916",
                "nested": [1, 2.5, None, True, {"k": "x'; DROP TABLE audit;--"}],
            },
        ),
        _entry(4, details={}),
        _entry(5, details={"blob": "é" * 200_000}),
    ]
    recs = [log.append(e) for e in entries]
    for rec in recs:
        assert rec.hash == expected_hash(rec)
    _assert_ok(log.verify(), len(entries))


def test_caller_supplied_seq_timestamp_and_hashes_are_ignored(log: AuditLog):
    """An AuditRecord IS-A AuditAppend; a caller must not be able to pick its own seq,
    backdate the timestamp, or plant a hash that breaks/forks the chain."""
    forged = AuditRecord(
        **_entry(0).model_dump(),
        seq=999,
        timestamp=datetime(2000, 1, 1, tzinfo=UTC),
        prev_hash="f" * 64,
        hash="e" * 64,
    )
    rec = log.append(forged)
    assert rec.seq == 0
    assert rec.prev_hash == GENESIS
    assert rec.timestamp == T0
    assert rec.hash == expected_hash(rec)
    _assert_ok(log.verify(), 1)


def test_default_clock_is_timezone_aware_current_utc_time(db: Database):
    log = AuditLog(db)
    before = datetime.now(UTC)
    rec = log.append(_entry())
    after = datetime.now(UTC)
    assert rec.timestamp.tzinfo is not None
    assert before - timedelta(seconds=1) <= rec.timestamp <= after + timedelta(seconds=1)
    _assert_ok(log.verify(), 1)


def test_non_utc_clock_still_produces_a_verifiable_chain(db: Database):
    tokyo = timezone(timedelta(hours=9))
    log = AuditLog(db, clock=FakeClock(start=T0.astimezone(tokyo)))
    _fill(log, 3)
    _assert_ok(log.verify(), 3)


# ---------------------------------------------------------------- verify: intact chains


def test_intact_chain_verifies_ok_and_counts_records(log: AuditLog):
    _fill(log, CHAIN_LEN)
    _assert_ok(log.verify(), CHAIN_LEN)


def test_verify_walks_past_the_first_page_of_rows(db: Database, log: AuditLog):
    """db.list_audit defaults to 100 rows; verify must check the whole chain."""
    _fill(log, 250)
    _assert_ok(log.verify(), 250)
    _set(db, "actor", "mallory", 230)
    _assert_broken_at(log.verify(), 230)


def test_new_log_instance_continues_an_existing_chain(tmp_path: Path):
    """Simulates a control-plane restart: seq and prev_hash pick up where they left off."""
    path = tmp_path / "aimfa.db"
    first = AuditLog(Database(path), clock=FakeClock())
    recs = _fill(first, 3)
    second = AuditLog(Database(path), clock=FakeClock(start=T0 + timedelta(hours=1)))
    rec = second.append(_entry(3))
    assert rec.seq == 3
    assert rec.prev_hash == recs[-1].hash
    _assert_ok(second.verify(), 4)


# ---------------------------------------------------------------- tampering: field edits


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("timestamp", "2020-01-01T00:00:00Z"),
        ("prev_hash", "f" * 64),
        ("hash", "e" * 64),
        ("component", "control_plane"),
        ("actor", "mallory"),
        ("actor", "expense-bоt"),  # Cyrillic 'o' homoglyph
        ("actor", "expense-bot "),  # trailing space
        ("event", "admin.cover_up"),
        ("outcome", "allow"),
        ("reason_code", "OK"),
        ("details", '{"jti":"jti-999","n":2,"tool":"read_file"}'),
        ("details", '{"jti":"jti-2","n":2}'),  # a key removed
        ("details", '{"jti":"jti-2","n":2.0,"tool":"read_file"}'),  # int -> float
        ("details", "{}"),
    ],
    ids=[
        "timestamp",
        "prev_hash",
        "hash",
        "component",
        "actor",
        "actor-homoglyph",
        "actor-trailing-space",
        "event",
        "outcome",
        "reason_code",
        "details-value",
        "details-key-removed",
        "details-int-to-float",
        "details-emptied",
    ],
)
def test_changing_any_field_of_a_middle_row_breaks_the_chain_at_that_row(
    db: Database, log: AuditLog, column: str, value: str
):
    _fill(log, CHAIN_LEN)
    _set(db, column, value, MIDDLE)
    _assert_broken_at(log.verify(), MIDDLE)


@pytest.mark.parametrize("column", ["actor", "hash", "prev_hash"])
def test_changing_the_genesis_row_is_detected_at_seq_zero(db: Database, log: AuditLog, column: str):
    _fill(log, CHAIN_LEN)
    value = {"actor": "mallory", "hash": "e" * 64, "prev_hash": "1" * 64}[column]
    _set(db, column, value, 0)
    _assert_broken_at(log.verify(), 0)


@pytest.mark.parametrize("column", ["actor", "hash", "details"])
def test_changing_the_newest_row_is_detected_at_that_row(db: Database, log: AuditLog, column: str):
    _fill(log, CHAIN_LEN)
    value = {"actor": "mallory", "hash": "e" * 64, "details": "{}"}[column]
    _set(db, column, value, CHAIN_LEN - 1)
    _assert_broken_at(log.verify(), CHAIN_LEN - 1)


def test_changing_the_seq_of_the_newest_row_is_detected(db: Database, log: AuditLog):
    _fill(log, CHAIN_LEN)
    _set(db, "seq", 9, CHAIN_LEN - 1)
    _assert_broken_at(log.verify(), 9)


def test_changing_the_seq_of_a_middle_row_is_detected(db: Database, log: AuditLog):
    """Row 2 moves to seq 99, so the first row that fails (ascending) is row 3: its
    prev_hash no longer matches row 1's hash."""
    _fill(log, CHAIN_LEN)
    _set(db, "seq", 99, MIDDLE)
    _assert_broken_at(log.verify(), MIDDLE + 1)


def test_two_tampered_rows_report_the_earliest(db: Database, log: AuditLog):
    _fill(log, CHAIN_LEN)
    _set(db, "actor", "mallory", 3)
    _set(db, "actor", "mallory", 1)
    _assert_broken_at(log.verify(), 1)


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("outcome", "maybe"),
        ("reason_code", "NOT_A_REASON"),
        ("component", "attacker"),
        ("prev_hash", "not-hex"),
        ("hash", "A" * 64),  # uppercase hex is not the contract format
        ("hash", ""),
        ("timestamp", "not-a-time"),
        ("details", "{not json"),
        ("details", "[1, 2, 3]"),
        ("details", "null"),
    ],
    ids=[
        "outcome",
        "reason_code",
        "component",
        "prev_hash-not-hex",
        "hash-uppercase",
        "hash-empty",
        "timestamp",
        "details-not-json",
        "details-list",
        "details-null",
    ],
)
def test_row_that_fails_model_validation_is_reported_broken_not_raised(
    db: Database, log: AuditLog, column: str, value: str
):
    """Fail closed: corrupt data must produce ok=false, never an unhandled exception."""
    _fill(log, CHAIN_LEN)
    _set(db, column, value, MIDDLE)
    _assert_broken_at(log.verify(), MIDDLE)


# ---------------------------------------------------------------- tampering: delete / swap


def test_deleting_a_middle_row_is_detected(db: Database, log: AuditLog):
    _fill(log, CHAIN_LEN)
    _exec(db, "DELETE FROM audit WHERE seq = ?", (MIDDLE,))
    _assert_broken_at(log.verify(), MIDDLE + 1)


def test_deleting_several_middle_rows_is_detected(db: Database, log: AuditLog):
    _fill(log, CHAIN_LEN)
    _exec(db, "DELETE FROM audit WHERE seq BETWEEN ? AND ?", (1, 3))
    _assert_broken_at(log.verify(), 4)


def test_deleting_the_genesis_row_is_detected(db: Database, log: AuditLog):
    _fill(log, CHAIN_LEN)
    _exec(db, "DELETE FROM audit WHERE seq = ?", (0,))
    _assert_broken_at(log.verify(), 1)


@pytest.mark.parametrize(
    ("a", "b"),
    [(MIDDLE, MIDDLE + 1), (1, 3), (0, 1), (0, CHAIN_LEN - 1)],
    ids=["adjacent", "non-adjacent", "with-genesis", "first-and-last"],
)
def test_swapping_two_rows_is_detected_at_the_earlier_position(
    db: Database, log: AuditLog, a: int, b: int
):
    _fill(log, CHAIN_LEN)
    _swap_seq(db, a, b)
    _assert_broken_at(log.verify(), a)


def test_forged_row_appended_after_a_seq_gap_is_detected(db: Database, log: AuditLog):
    """Even with a correctly computed hash and link, seq must be contiguous."""
    recs = _fill(log, CHAIN_LEN)
    forged = AuditRecord(
        **_entry(0, actor="mallory").model_dump(),
        seq=10,
        timestamp=T0 + timedelta(hours=1),
        prev_hash=recs[-1].hash,
        hash="0" * 64,
    )
    forged = forged.model_copy(update={"hash": expected_hash(forged)})
    db.insert_audit(forged)
    _assert_broken_at(log.verify(), 10)


def test_verify_is_read_only_and_repeatable(db: Database, log: AuditLog):
    _fill(log, CHAIN_LEN)
    _set(db, "actor", "mallory", MIDDLE)
    first = log.verify()
    second = log.verify()
    assert first == second
    _assert_broken_at(second, MIDDLE)
    assert _raw_seqs(db) == list(range(CHAIN_LEN))
    assert db.list_audit()[MIDDLE].actor == "mallory"  # verify does not "repair"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known limitation: a keyless hash chain cannot detect truncation of the newest "
        "rows. Needs an external anchor (e.g. signed/published head hash). Not in T1.3."
    ),
)
def test_deleting_the_newest_row_is_detected(db: Database, log: AuditLog):
    _fill(log, CHAIN_LEN)
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
    recs = _fill(log, CHAIN_LEN)
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


# ---------------------------------------------------------------- concurrency


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


def _appender(log: AuditLog, worker: int, per_thread: int) -> Callable[[], list[AuditRecord]]:
    return lambda: [log.append(_entry(worker * 1000 + j)) for j in range(per_thread)]


def test_concurrent_appends_on_one_log_produce_unique_contiguous_seqs(db: Database, log: AuditLog):
    threads, per_thread = 16, 5
    total = threads * per_thread
    results, errors = _run_threads([_appender(log, w, per_thread) for w in range(threads)])
    assert errors == []
    assert sorted(r.seq for r in results) == list(range(total))
    assert _raw_seqs(db) == list(range(total))
    _assert_ok(log.verify(), total)


def test_concurrent_appends_from_two_log_instances_on_one_file_stay_a_single_chain(
    tmp_path: Path,
):
    """Two AuditLog objects (e.g. two app instances) share the file: an in-process lock
    alone is not enough; appends must be serialized at the database level."""
    path = tmp_path / "aimfa.db"
    clock = FakeClock()
    log_a = AuditLog(Database(path), clock=clock)
    log_b = AuditLog(Database(path), clock=clock)
    per_side, per_thread = 8, 5
    total = 2 * per_side * per_thread
    fns = [_appender(log_a, w, per_thread) for w in range(per_side)] + [
        _appender(log_b, per_side + w, per_thread) for w in range(per_side)
    ]
    results, errors = _run_threads(fns)
    assert errors == []
    assert sorted(r.seq for r in results) == list(range(total))
    _assert_ok(log_a.verify(), total)
    _assert_ok(log_b.verify(), total)


# ---------------------------------------------------------------- list


def test_list_returns_records_in_seq_order_with_paging(log: AuditLog):
    recs = _fill(log, 10)
    assert log.list(after_seq=-1, limit=100) == recs
    assert [r.seq for r in log.list(after_seq=4, limit=3)] == [5, 6, 7]
    assert [r.seq for r in log.list(after_seq=8, limit=100)] == [9]
    assert log.list(after_seq=9, limit=100) == []
    assert log.list(after_seq=-1, limit=0) == []


def test_list_on_empty_log_is_empty(log: AuditLog):
    assert log.list(after_seq=-1, limit=100) == []


# ---------------------------------------------------------------- security conventions


def test_hash_comparisons_use_constant_time_compare():
    """AGENTS.md rule 3: hashes are compared with hmac.compare_digest, never ==."""
    assert "compare_digest" in inspect.getsource(audit_module)
