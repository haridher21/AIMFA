"""Tamper-evident, append-only audit log (ROADMAP T1.3).

Every allow / deny / pending decision is written here (AGENTS.md rule 10). Each record
stores the hash of the record before it, so the records form a *hash chain*:

    hash = sha256_hex(prev_hash + canonical_json(record fields except "hash"))

The first record (seq 0) links to ``GENESIS_HASH`` ("0" * 64).

What the chain detects: editing any field of a stored row, deleting or reordering rows
in the middle, gaps in ``seq``, and rows that no longer parse. Changing one row changes
its hash, which no longer matches the ``prev_hash`` stored in the next row.

What it can NOT detect on its own (accepted limits, see docs/LEARNING.md):

* **Tail truncation.** Deleting the newest rows leaves a shorter chain that is still
  perfectly valid.
* **Full recompute.** The hash rule is public and uses no key, so someone with write
  access to the database can edit a row and recompute every later hash.

Both need an *external anchor* (e.g. periodically signing or publishing the head hash
somewhere the attacker cannot write), which is outside T1.3.
"""

from __future__ import annotations

import builtins
import hmac
import json
import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from aimfa.common.crypto import canonical_json, sha256_hex
from aimfa.common.db import Database
from aimfa.common.models import AuditAppend, AuditRecord, AuditVerifyResult, ReasonCode

__all__ = ["GENESIS_HASH", "AuditLog", "compute_record_hash", "verify_rows"]

GENESIS_HASH = "0" * 64

_APPEND_FIELDS = frozenset(AuditAppend.model_fields)

# Constant SQL only (AGENTS.md rule 8): every value goes through a ``?`` placeholder.
_SELECT_HEAD_SQL = "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1"
_SELECT_ALL_SQL = (
    "SELECT seq, timestamp, prev_hash, hash, component, actor, event, outcome, "
    "reason_code, details FROM audit ORDER BY seq"
)
_INSERT_SQL = (
    "INSERT INTO audit (seq, timestamp, prev_hash, hash, component, actor, event, "
    "outcome, reason_code, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

# Errors that bad *stored data* can cause while parsing or hashing a row. They mean
# "this row is broken", never "skip it". (pydantic.ValidationError and
# json.JSONDecodeError are both ValueError subclasses; absurdly deep JSON nesting
# raises RecursionError.)
_ROW_ERRORS = (ValueError, TypeError, KeyError, RecursionError)


# ------------------------------------------------------------------ pure functions


def _utc_now() -> datetime:
    return datetime.now(UTC)


def compute_record_hash(record: AuditRecord) -> str:
    """Hash of ``record`` per the chain rule.

    Every field except ``hash`` is covered, including ``seq``, ``timestamp`` and
    ``prev_hash``: so a row cannot be moved to another position, backdated, or relinked
    without its hash changing. Canonical JSON makes the bytes independent of key order.
    """
    body = record.model_dump(mode="json", exclude={"hash"})
    return sha256_hex(record.prev_hash.encode("utf-8") + canonical_json(body))


def _details_text(details: dict[str, Any]) -> str:
    """JSON text for the ``details`` column (same encoding as ``Database.insert_audit``).

    Key order is preserved so the row reads back identical to what ``append`` returned.
    NaN/Infinity are refused: they are not valid JSON and would not round-trip.
    """
    return json.dumps(details, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _parse_row(row: sqlite3.Row) -> AuditRecord:
    """Turn a raw stored row into a validated record, or raise one of ``_ROW_ERRORS``.

    We parse raw rows ourselves (instead of ``Database.list_audit``) so a tampered row
    becomes a reportable "broken at seq N" instead of an exception that aborts verify.
    """
    return AuditRecord.model_validate(
        {
            "seq": row["seq"],
            "timestamp": row["timestamp"],
            "prev_hash": row["prev_hash"],
            "hash": row["hash"],
            "component": row["component"],
            "actor": row["actor"],
            "event": row["event"],
            "outcome": row["outcome"],
            "reason_code": row["reason_code"],
            "details": json.loads(row["details"]),
        }
    )


def _row_hash_if_valid(row: sqlite3.Row, expected_seq: int, expected_prev: str) -> str | None:
    """Return the row's hash if it is a valid next link of the chain, else ``None``.

    A row is valid only if (1) it sits at the expected position (no gaps, so a deleted
    row is noticed), (2) it still fits the ``AuditRecord`` contract, (3) it points at
    the previous row's hash (no deletes / swaps), and (4) its stored hash matches the
    recomputed one (no edits). Any parsing error counts as invalid: fail closed.
    """
    try:
        if row["seq"] != expected_seq:
            return None
        rec = _parse_row(row)
        if not hmac.compare_digest(rec.prev_hash, expected_prev):
            return None
        if not hmac.compare_digest(compute_record_hash(rec), rec.hash):
            return None
        return rec.hash
    except _ROW_ERRORS:
        return None


def _stored_seq(row: sqlite3.Row) -> int | None:
    """The row's stored seq for error reports (``None`` only if it is not an int)."""
    try:
        seq = row["seq"]
    except _ROW_ERRORS:
        return None
    return seq if isinstance(seq, int) and not isinstance(seq, bool) else None


def verify_rows(rows: Any) -> AuditVerifyResult:
    """Walk raw audit rows (ascending ``seq``) and check the whole chain.

    Stops at the first bad row and reports its stored seq. On failure
    ``records_checked`` is the number of rows that verified before it (the trustworthy
    prefix). Never raises because of the data itself.
    """
    expected_prev = GENESIS_HASH
    checked = 0
    for row in rows:
        row_hash = _row_hash_if_valid(row, checked, expected_prev)
        if row_hash is None:
            return AuditVerifyResult(
                ok=False,
                records_checked=checked,
                first_bad_seq=_stored_seq(row),
                reason_code=ReasonCode.AUDIT_CHAIN_BROKEN,
            )
        expected_prev = row_hash
        checked += 1
    return AuditVerifyResult(ok=True, records_checked=checked, reason_code=ReasonCode.OK)


# ------------------------------------------------------------------ the log


class AuditLog:
    """Hash-chained audit log stored in the ``audit`` table of ``db``.

    ``clock`` returns the (timezone-aware) time stamped on each record; inject one in
    tests. The log itself holds no state besides a lock, so several instances (or a
    restarted process) can share one database file and continue the same chain.
    """

    def __init__(self, db: Database, *, clock: Callable[[], datetime] | None = None) -> None:
        self._db = db
        self._clock = clock if clock is not None else _utc_now
        # Only reduces contention between threads of THIS instance; the real
        # serialization is the database write lock taken in ``append``.
        self._lock = threading.Lock()

    def _now(self) -> datetime:
        """Refuse naive times: an audit timestamp without a zone is ambiguous."""
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("audit clock must return a timezone-aware datetime")
        return now

    def append(self, entry: AuditAppend) -> AuditRecord:
        """Add ``entry`` as the next record and return the stored record.

        seq, timestamp, prev_hash and hash are always assigned here, even if the caller
        passes an ``AuditRecord``: a caller must not be able to choose its position,
        backdate itself, or plant a hash that forks the chain.

        Read-head, compute and insert happen in ONE ``BEGIN IMMEDIATE`` transaction.
        Otherwise two writers (threads or processes) could both read the same head and
        both write "seq N", forking the chain.
        """
        if not isinstance(entry, AuditAppend):
            raise TypeError("append expects an AuditAppend")
        # Re-validate from a JSON-mode dump: catches fields mutated after construction
        # and makes the returned record exactly what is stored and hashed.
        fields = entry.model_dump(mode="json", include=set(_APPEND_FIELDS))

        with self._lock, self._db.connect(immediate=True) as conn:
            head = conn.execute(_SELECT_HEAD_SQL).fetchone()
            if head is None:
                seq, prev_hash = 0, GENESIS_HASH
            else:
                seq, prev_hash = head["seq"] + 1, head["hash"]
            draft = AuditRecord.model_validate(
                {
                    **fields,
                    "seq": seq,
                    "timestamp": self._now(),
                    "prev_hash": prev_hash,
                    "hash": GENESIS_HASH,  # placeholder; excluded from the hash itself
                }
            )
            record = draft.model_copy(update={"hash": compute_record_hash(draft)})
            data = record.model_dump(mode="json")
            conn.execute(
                _INSERT_SQL,
                (
                    record.seq,
                    data["timestamp"],
                    record.prev_hash,
                    record.hash,
                    data["component"],
                    record.actor,
                    record.event,
                    data["outcome"],
                    data["reason_code"],
                    _details_text(data["details"]),
                ),
            )
        return record

    def verify(self) -> AuditVerifyResult:
        """Check the entire chain (all rows, not one page). Read-only.

        Runs inside one read transaction, so it sees a consistent snapshot even while
        other writers append.
        """
        with self._db.connect() as conn:
            return verify_rows(conn.execute(_SELECT_ALL_SQL))

    def list(self, after_seq: int = -1, limit: int = 100) -> builtins.list[AuditRecord]:
        """Records with seq > ``after_seq``, ascending, at most ``limit``."""
        return self._db.list_audit(after_seq=after_seq, limit=limit)
