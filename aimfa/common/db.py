"""SQLite storage: schema + small repository methods (ROADMAP T1.5).

Design notes (why it looks like this):

* **One connection per call.** ``Database`` holds only a file path, never an open
  connection, so one instance can be shared by FastAPI worker threads safely.
* **WAL mode + busy timeout.** Readers don't block writers, and concurrent writers wait
  for the lock instead of failing with "database is locked".
* **Parameterized SQL only** (AGENTS.md rule 8). Every value goes through a ``?``
  placeholder; no query text is ever built from data. Variants of a query (e.g. "with
  or without an agent filter") are separate constant strings.
* **Security decisions are single atomic statements.** "Consume a nonce", "use a TOTP
  step" and "move an approval from APPROVED to USED" are each ONE conditional
  ``UPDATE ... WHERE <expected state>``; the caller wins only if ``rowcount == 1``. A
  read-then-write would let two concurrent requests both see "unused" and both win.
* **Times are stored as integer microseconds since the Unix epoch (UTC).** Comparing
  ISO strings is wrong across time zones ("13:00+09:00" sorts after "05:00Z" although
  it is earlier). Integers compare by instant. The audit table is the one exception:
  it stores the timestamp text verbatim, because the hash chain (T1.3) hashes the
  record exactly as written and never compares audit times.
* **Duplicate primary keys raise ``DuplicateError``** and never overwrite. Silently
  replacing a row would let someone swap a launcher key, an agent's golden measurement
  or a human's TOTP seed for their own.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, SecretStr

from aimfa.common.models import (
    PRINCIPAL_ID_PATTERN,
    ActiveTokenView,
    AgentRecord,
    AgentStatus,
    ApprovalRecord,
    ApprovalStatus,
    AuditRecord,
    LauncherRegistration,
    PublicJWK,
    RiskEvent,
)

# Seconds a connection waits for another writer's lock before giving up.
BUSY_TIMEOUT_SECONDS = 10.0
# Matches AttestationChallenge.nonce (models.py): short nonces are guessable.
MIN_NONCE_LENGTH = 16

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_ONE_US = timedelta(microseconds=1)

# Approvals only move forward. Terminal states (denied, expired, used) can never be
# left, so a bug elsewhere cannot "resurrect" a denied or already-used approval.
_APPROVAL_TRANSITIONS: dict[ApprovalStatus, frozenset[ApprovalStatus]] = {
    ApprovalStatus.PENDING: frozenset(
        {ApprovalStatus.APPROVED, ApprovalStatus.DENIED, ApprovalStatus.EXPIRED}
    ),
    ApprovalStatus.APPROVED: frozenset({ApprovalStatus.USED, ApprovalStatus.EXPIRED}),
}

_DUPLICATE_ERRORS = frozenset({"SQLITE_CONSTRAINT_PRIMARYKEY", "SQLITE_CONSTRAINT_UNIQUE"})

_SCHEMA = """
BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS launchers (
    launcher_id TEXT PRIMARY KEY,
    public_jwk  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
    agent_id           TEXT PRIMARY KEY,
    role               TEXT NOT NULL,
    golden_measurement TEXT NOT NULL,
    launcher_id        TEXT NOT NULL,
    approver_id        TEXT NOT NULL,
    description        TEXT NOT NULL,
    status             TEXT NOT NULL,
    created_at         INTEGER NOT NULL,
    quarantined_at     INTEGER,
    identity_not_before INTEGER
);
CREATE TABLE IF NOT EXISTS approvers (
    approver_id    TEXT PRIMARY KEY,
    display_name   TEXT NOT NULL,
    totp_seed      TEXT NOT NULL,
    last_used_step INTEGER
);
CREATE TABLE IF NOT EXISTS nonces (
    nonce      TEXT PRIMARY KEY,
    agent_id   TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tokens (
    jti        TEXT PRIMARY KEY,
    agent_id   TEXT NOT NULL,
    task_id    TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    issued_at  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS tokens_by_agent ON tokens (agent_id, task_id);
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    task_id     TEXT NOT NULL,
    tool        TEXT NOT NULL,
    args        TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    reason      TEXT NOT NULL,
    risk_score  REAL NOT NULL,
    approver_id TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    decided_at  INTEGER
);
CREATE INDEX IF NOT EXISTS approvals_by_status ON approvals (status);
CREATE TABLE IF NOT EXISTS risk_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id   TEXT NOT NULL,
    task_id    TEXT,
    event_type TEXT NOT NULL,
    tool       TEXT,
    target     TEXT,
    timestamp  INTEGER NOT NULL,
    details    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS risk_events_by_agent ON risk_events (agent_id, timestamp);
CREATE TABLE IF NOT EXISTS audit (
    seq         INTEGER PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL,
    component   TEXT NOT NULL,
    actor       TEXT NOT NULL,
    event       TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    details     TEXT NOT NULL
);
COMMIT;
"""


class DuplicateError(Exception):
    """A row with this primary key already exists. Nothing was overwritten."""


class ApproverRow(BaseModel):
    """A stored approver. ``totp_seed`` is a SecretStr so it never appears in repr/logs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approver_id: str
    display_name: str
    totp_seed: SecretStr
    last_used_step: int | None = None


class NonceRow(BaseModel):
    """A stored attestation nonce."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    nonce: str
    agent_id: str
    expires_at: datetime
    used: bool


# ------------------------------------------------------------------ pure helpers


def to_epoch_us(dt: datetime) -> int:
    """Timezone-aware datetime -> integer microseconds since the epoch (exact, UTC).

    Naive datetimes are refused: guessing their zone could make an expired nonce or
    token look valid for hours.
    """
    if not isinstance(dt, datetime) or dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return (dt - _EPOCH) // _ONE_US


def from_epoch_us(us: int) -> datetime:
    """Inverse of ``to_epoch_us``; always returns an aware UTC datetime."""
    return _EPOCH + timedelta(microseconds=us)


def _opt_epoch_us(dt: datetime | None) -> int | None:
    return None if dt is None else to_epoch_us(dt)


def _opt_from_epoch_us(us: int | None) -> datetime | None:
    return None if us is None else from_epoch_us(us)


def _dump_json(value: Any) -> str:
    """JSON text for dict/list columns. NaN/Infinity are refused (not valid JSON)."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _is_duplicate(err: sqlite3.IntegrityError) -> bool:
    return getattr(err, "sqlite_errorname", "") in _DUPLICATE_ERRORS


def _check_step(step: int) -> int:
    """TOTP steps are non-negative ints (unix time // 30). Anything else is a bug."""
    if isinstance(step, bool) or not isinstance(step, int) or step < 0:
        raise ValueError("TOTP step must be a non-negative int")
    return step


def check_approval_transition(expected: ApprovalStatus, new: ApprovalStatus) -> None:
    """Refuse transitions out of terminal states or that skip the human decision."""
    expected, new = ApprovalStatus(expected), ApprovalStatus(new)
    if new not in _APPROVAL_TRANSITIONS.get(expected, frozenset()):
        raise ValueError(f"illegal approval transition {expected.value} -> {new.value}")


def _launcher_from_row(row: sqlite3.Row) -> LauncherRegistration:
    return LauncherRegistration(
        launcher_id=row["launcher_id"],
        public_jwk=PublicJWK.model_validate_json(row["public_jwk"]),
    )


def _agent_from_row(row: sqlite3.Row) -> AgentRecord:
    return AgentRecord(
        agent_id=row["agent_id"],
        role=row["role"],
        golden_measurement=row["golden_measurement"],
        launcher_id=row["launcher_id"],
        approver_id=row["approver_id"],
        description=row["description"],
        status=AgentStatus(row["status"]),
        created_at=from_epoch_us(row["created_at"]),
        quarantined_at=_opt_from_epoch_us(row["quarantined_at"]),
    )


def _approver_from_row(row: sqlite3.Row) -> ApproverRow:
    return ApproverRow(
        approver_id=row["approver_id"],
        display_name=row["display_name"],
        totp_seed=SecretStr(row["totp_seed"]),
        last_used_step=row["last_used_step"],
    )


def _nonce_from_row(row: sqlite3.Row) -> NonceRow:
    return NonceRow(
        nonce=row["nonce"],
        agent_id=row["agent_id"],
        expires_at=from_epoch_us(row["expires_at"]),
        used=bool(row["used"]),
    )


def _token_from_row(row: sqlite3.Row) -> ActiveTokenView:
    return ActiveTokenView(
        jti=row["jti"],
        agent_id=row["agent_id"],
        task_id=row["task_id"],
        scopes=json.loads(row["scopes"]),
        issued_at=from_epoch_us(row["issued_at"]),
        expires_at=from_epoch_us(row["expires_at"]),
        revoked=bool(row["revoked"]),
    )


def _approval_from_row(row: sqlite3.Row) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=row["approval_id"],
        agent_id=row["agent_id"],
        task_id=row["task_id"],
        tool=row["tool"],
        args=json.loads(row["args"]),
        action_hash=row["action_hash"],
        reason=row["reason"],
        risk_score=row["risk_score"],
        approver_id=row["approver_id"],
        status=ApprovalStatus(row["status"]),
        created_at=from_epoch_us(row["created_at"]),
        expires_at=from_epoch_us(row["expires_at"]),
        decided_at=_opt_from_epoch_us(row["decided_at"]),
    )


def _risk_event_from_row(row: sqlite3.Row) -> RiskEvent:
    return RiskEvent(
        agent_id=row["agent_id"],
        task_id=row["task_id"],
        event_type=row["event_type"],
        tool=row["tool"],
        target=row["target"],
        timestamp=from_epoch_us(row["timestamp"]),
        details=json.loads(row["details"]),
    )


def _audit_from_row(row: sqlite3.Row) -> AuditRecord:
    """Validate a stored audit row. A tampered row that no longer fits the model raises
    pydantic.ValidationError; the audit verifier must treat that as a broken chain."""
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


# ------------------------------------------------------------------ database


class Database:
    """Repository over one SQLite file. Holds a path, never an open connection."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @property
    def path(self) -> Path:
        return self._path

    def _open(self) -> sqlite3.Connection:
        # isolation_level=None: we issue BEGIN/COMMIT ourselves so a whole `with` block
        # is exactly one transaction. check_same_thread=False is safe because each
        # connection lives only inside one call on one thread.
        conn = sqlite3.connect(
            self._path,
            timeout=BUSY_TIMEOUT_SECONDS,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        """Enable WAL (persisted in the file) and create tables. Idempotent."""
        conn = self._open()
        try:
            mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                # Fail closed: without WAL, concurrent readers/writers would error out.
                raise RuntimeError("could not enable SQLite WAL mode")
            conn.executescript(_SCHEMA)
            # Older database files predate this column; add it in place.
            columns = {r["name"] for r in conn.execute("PRAGMA table_info(agents)")}
            if "identity_not_before" not in columns:
                conn.execute("ALTER TABLE agents ADD COLUMN identity_not_before INTEGER")
        finally:
            conn.close()

    @contextmanager
    def connect(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """Yield a NEW connection running one transaction; commit on success, roll back
        on any exception, always close.

        ``immediate=True`` takes the write lock up front (BEGIN IMMEDIATE). Use it for
        read-then-write sequences (e.g. "read last audit row, then append") so two
        writers cannot both read the same state.
        """
        conn = self._open()
        try:
            conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    # -------------------------------------------------------------- small helpers

    def _insert(self, sql: str, params: tuple[Any, ...], what: str) -> None:
        """INSERT one row; a primary-key clash becomes DuplicateError (never overwrite)."""
        try:
            with self.connect() as conn:
                conn.execute(sql, params)
        except sqlite3.IntegrityError as e:
            if _is_duplicate(e):
                raise DuplicateError(f"{what} already exists") from None
            raise

    def _write(self, sql: str, params: tuple[Any, ...]) -> int:
        """Run one write statement; return the number of rows it changed."""
        with self.connect() as conn:
            return conn.execute(sql, params).rowcount

    def _one(self, sql: str, params: tuple[Any, ...]) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(sql, params).fetchone()

    def _all(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(sql, params).fetchall()

    # -------------------------------------------------------------- launchers

    def add_launcher(self, reg: LauncherRegistration) -> None:
        self._insert(
            "INSERT INTO launchers (launcher_id, public_jwk) VALUES (?, ?)",
            (reg.launcher_id, reg.public_jwk.model_dump_json()),
            "launcher",
        )

    def get_launcher(self, launcher_id: str) -> LauncherRegistration | None:
        row = self._one(
            "SELECT launcher_id, public_jwk FROM launchers WHERE launcher_id = ?",
            (launcher_id,),
        )
        return None if row is None else _launcher_from_row(row)

    def list_launchers(self) -> list[LauncherRegistration]:
        rows = self._all("SELECT launcher_id, public_jwk FROM launchers ORDER BY launcher_id")
        return [_launcher_from_row(r) for r in rows]

    def delete_launcher(self, launcher_id: str) -> bool:
        return self._write("DELETE FROM launchers WHERE launcher_id = ?", (launcher_id,)) == 1

    # -------------------------------------------------------------- agents

    def add_agent(self, rec: AgentRecord) -> None:
        self._insert(
            "INSERT INTO agents (agent_id, role, golden_measurement, launcher_id, "
            "approver_id, description, status, created_at, quarantined_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rec.agent_id,
                rec.role,
                rec.golden_measurement,
                rec.launcher_id,
                rec.approver_id,
                rec.description,
                AgentStatus(rec.status).value,
                to_epoch_us(rec.created_at),
                _opt_epoch_us(rec.quarantined_at),
            ),
            "agent",
        )

    def get_agent(self, agent_id: str) -> AgentRecord | None:
        row = self._one("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))
        return None if row is None else _agent_from_row(row)

    def list_agents(self) -> list[AgentRecord]:
        return [_agent_from_row(r) for r in self._all("SELECT * FROM agents ORDER BY agent_id")]

    def set_agent_status(
        self,
        agent_id: str,
        status: AgentStatus,
        *,
        quarantined_at: datetime | None = None,
        expected: AgentStatus | None = None,
    ) -> bool:
        """Write status AND quarantined_at exactly as given (None clears it).

        With ``expected`` this is a compare-and-set: the row changes only if its status
        is still ``expected``. Use it whenever the new status depends on the old one, so
        a concurrent quarantine can't be silently overwritten.

        Low-level / admin+test use. Services should use the safe purpose-built methods:
        ``activate_agent`` (attestation), ``quarantine_agent`` (monitor) and
        ``clear_quarantine`` (admin).
        """
        new_status = AgentStatus(status).value
        q_at = _opt_epoch_us(quarantined_at)
        if expected is None:
            changed = self._write(
                "UPDATE agents SET status = ?, quarantined_at = ? WHERE agent_id = ?",
                (new_status, q_at, agent_id),
            )
        else:
            changed = self._write(
                "UPDATE agents SET status = ?, quarantined_at = ? "
                "WHERE agent_id = ? AND status = ?",
                (new_status, q_at, agent_id, AgentStatus(expected).value),
            )
        return changed == 1

    def activate_agent(self, agent_id: str) -> bool:
        """Mark an agent ACTIVE after a successful attestation, unless it is quarantined.

        Why: an /attest call that started before the monitor quarantined the agent may
        finish afterwards. The "not quarantined" check is in the same UPDATE, so that
        stale call can never undo the quarantine.
        """
        return (
            self._write(
                "UPDATE agents SET status = ? WHERE agent_id = ? AND status != ?",
                (AgentStatus.ACTIVE.value, agent_id, AgentStatus.QUARANTINED.value),
            )
            == 1
        )

    def quarantine_agent(self, agent_id: str, *, at: datetime) -> int:
        """Quarantine an agent AND revoke all its live tokens in one transaction.

        Why one transaction: if these were two calls, a crash in between could leave a
        quarantined agent holding a working token. Tokens are revoked by agent_id even if
        the agent row is missing (fail closed); no agent row is ever created. Returns the
        number of tokens newly revoked.

        This does NOT stop a token service that read the old status a moment earlier
        from inserting a token just after this commits. That is why introspection must
        also check the agent's status (AGENT_QUARANTINED) and treat a missing agent as
        inactive, not only the token's ``revoked`` flag.
        """
        q_at = to_epoch_us(at)
        with self.connect(immediate=True) as conn:
            conn.execute(
                "UPDATE agents SET status = ?, quarantined_at = ? WHERE agent_id = ?",
                (AgentStatus.QUARANTINED.value, q_at, agent_id),
            )
            return conn.execute(
                "UPDATE tokens SET revoked = 1 WHERE agent_id = ? AND revoked = 0", (agent_id,)
            ).rowcount

    def revoke_agent_identity(self, agent_id: str, *, not_before: int) -> int:
        """Kill switch, in one transaction: revoke all tokens, drop the agent back to
        REGISTERED (a QUARANTINED agent stays quarantined) and refuse any identity
        credential issued before ``not_before`` (Unix seconds). Without the last part the
        agent could mint fresh access tokens from its still-valid identity credential.
        Returns the number of tokens newly revoked."""
        with self.connect(immediate=True) as conn:
            revoked = conn.execute(
                "UPDATE tokens SET revoked = 1 WHERE agent_id = ? AND revoked = 0", (agent_id,)
            ).rowcount
            conn.execute(
                "UPDATE agents SET identity_not_before = ?, status = CASE WHEN status = ? "
                "THEN status ELSE ? END WHERE agent_id = ?",
                (
                    not_before,
                    AgentStatus.QUARANTINED.value,
                    AgentStatus.REGISTERED.value,
                    agent_id,
                ),
            )
            return revoked

    def get_identity_not_before(self, agent_id: str) -> int | None:
        row = self._one("SELECT identity_not_before FROM agents WHERE agent_id = ?", (agent_id,))
        return None if row is None else row["identity_not_before"]

    def clear_quarantine(self, agent_id: str) -> bool:
        """Admin action: QUARANTINED -> REGISTERED. The agent must re-attest to become
        ACTIVE again. Revoked tokens are never un-revoked; it must request new ones."""
        return (
            self._write(
                "UPDATE agents SET status = ?, quarantined_at = NULL "
                "WHERE agent_id = ? AND status = ?",
                (AgentStatus.REGISTERED.value, agent_id, AgentStatus.QUARANTINED.value),
            )
            == 1
        )

    def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent and, in the same transaction, revoke its tokens and delete its
        nonces. Otherwise re-registering the same agent_id would bring back credentials
        issued to the old agent. Cleanup runs even if the agent row is already gone."""
        with self.connect(immediate=True) as conn:
            deleted = conn.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,)).rowcount
            conn.execute(
                "UPDATE tokens SET revoked = 1 WHERE agent_id = ? AND revoked = 0", (agent_id,)
            )
            conn.execute("DELETE FROM nonces WHERE agent_id = ?", (agent_id,))
        return deleted == 1

    # -------------------------------------------------------------- approvers

    def add_approver(self, approver_id: str, display_name: str, totp_seed: str | SecretStr) -> None:
        """Enroll an approver. Re-enrolling an existing id raises DuplicateError, so
        nobody can replace a human's TOTP seed with one they control."""
        if not re.fullmatch(PRINCIPAL_ID_PATTERN, approver_id):
            raise ValueError("invalid approver_id")
        seed = totp_seed.get_secret_value() if isinstance(totp_seed, SecretStr) else totp_seed
        if not seed:
            raise ValueError("empty TOTP seed")
        self._insert(
            "INSERT INTO approvers (approver_id, display_name, totp_seed, last_used_step) "
            "VALUES (?, ?, ?, NULL)",
            (approver_id, display_name, seed),
            "approver",
        )

    def get_approver(self, approver_id: str) -> ApproverRow | None:
        row = self._one("SELECT * FROM approvers WHERE approver_id = ?", (approver_id,))
        return None if row is None else _approver_from_row(row)

    def list_approvers(self) -> list[ApproverRow]:
        rows = self._all("SELECT * FROM approvers ORDER BY approver_id")
        return [_approver_from_row(r) for r in rows]

    def delete_approver(self, approver_id: str) -> bool:
        return self._write("DELETE FROM approvers WHERE approver_id = ?", (approver_id,)) == 1

    def mark_totp_step_used(self, approver_id: str, step: int) -> bool:
        """Record that a TOTP code (time step) was used. True only if ``step`` is newer
        than the last used one.

        Why: an observed code stays valid for ~30-60 s; without this, anyone who saw it
        could replay it. Monotonic (``<``, not ``!=``) because valid_window=1 also accepts
        the previous step, which must not roll the counter back. One atomic UPDATE, so
        two concurrent uses of the same code cannot both succeed.
        """
        return (
            self._write(
                "UPDATE approvers SET last_used_step = ? WHERE approver_id = ? "
                "AND (last_used_step IS NULL OR last_used_step < ?)",
                (_check_step(step), approver_id, step),
            )
            == 1
        )

    # -------------------------------------------------------------- nonces

    def add_nonce(self, nonce: str, agent_id: str, *, expires_at: datetime) -> None:
        if not isinstance(nonce, str) or len(nonce) < MIN_NONCE_LENGTH:
            raise ValueError("nonce too short")
        self._insert(
            "INSERT INTO nonces (nonce, agent_id, expires_at, used) VALUES (?, ?, ?, 0)",
            (nonce, agent_id, to_epoch_us(expires_at)),
            "nonce",
        )

    def get_nonce(self, nonce: str) -> NonceRow | None:
        row = self._one("SELECT * FROM nonces WHERE nonce = ?", (nonce,))
        return None if row is None else _nonce_from_row(row)

    def consume_nonce(self, nonce: str, agent_id: str, *, now: datetime) -> bool:
        """Use a nonce exactly once. True only if it exists, was issued to ``agent_id``,
        is unused, and ``now < expires_at``.

        Why: the nonce proves the attestation evidence is fresh. All four conditions are
        in ONE UPDATE, so replays and concurrent double-spends both get rowcount 0.
        """
        return (
            self._write(
                "UPDATE nonces SET used = 1 "
                "WHERE nonce = ? AND agent_id = ? AND used = 0 AND expires_at > ?",
                (nonce, agent_id, to_epoch_us(now)),
            )
            == 1
        )

    def count_live_nonces(self, agent_id: str, *, now: datetime) -> int:
        """Unused, unexpired nonces outstanding for one agent (used to cap challenges)."""
        row = self._one(
            "SELECT COUNT(*) AS n FROM nonces WHERE agent_id = ? AND used = 0 AND expires_at > ?",
            (agent_id, to_epoch_us(now)),
        )
        return int(row["n"])

    def delete_expired_nonces(self, *, now: datetime) -> int:
        return self._write("DELETE FROM nonces WHERE expires_at <= ?", (to_epoch_us(now),))

    # -------------------------------------------------------------- tokens

    def add_token(self, view: ActiveTokenView) -> None:
        """Record an issued token by jti (never the token itself)."""
        self._insert(
            "INSERT INTO tokens (jti, agent_id, task_id, scopes, issued_at, expires_at, "
            "revoked) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                view.jti,
                view.agent_id,
                view.task_id,
                _dump_json(list(view.scopes)),
                to_epoch_us(view.issued_at),
                to_epoch_us(view.expires_at),
                1 if view.revoked else 0,
            ),
            "token",
        )

    def get_token(self, jti: str) -> ActiveTokenView | None:
        row = self._one("SELECT * FROM tokens WHERE jti = ?", (jti,))
        return None if row is None else _token_from_row(row)

    def list_tokens(self, agent_id: str | None = None) -> list[ActiveTokenView]:
        if agent_id is None:
            rows = self._all("SELECT * FROM tokens ORDER BY issued_at, jti")
        else:
            rows = self._all(
                "SELECT * FROM tokens WHERE agent_id = ? ORDER BY issued_at, jti", (agent_id,)
            )
        return [_token_from_row(r) for r in rows]

    def revoke_token(self, jti: str) -> bool:
        """Mark one token revoked. False only if the jti is unknown (idempotent)."""
        return self._write("UPDATE tokens SET revoked = 1 WHERE jti = ?", (jti,)) == 1

    def revoke_task_tokens(self, agent_id: str, task_id: str) -> int:
        """Revoke a task's tokens. Scoped to the owning agent, so another agent naming
        the same task_id cannot revoke someone else's tokens."""
        return self._write(
            "UPDATE tokens SET revoked = 1 WHERE agent_id = ? AND task_id = ? AND revoked = 0",
            (agent_id, task_id),
        )

    def revoke_all_for_agent(self, agent_id: str) -> int:
        """The kill switch: revoke every token of one agent. Exact match (``=``, never
        LIKE) so ids containing ``%`` cannot widen the blast radius."""
        return self._write(
            "UPDATE tokens SET revoked = 1 WHERE agent_id = ? AND revoked = 0", (agent_id,)
        )

    # -------------------------------------------------------------- approvals

    def add_approval(self, rec: ApprovalRecord) -> None:
        data = rec.model_dump(mode="json")
        self._insert(
            "INSERT INTO approvals (approval_id, agent_id, task_id, tool, args, action_hash, "
            "reason, risk_score, approver_id, status, created_at, expires_at, decided_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rec.approval_id,
                rec.agent_id,
                rec.task_id,
                rec.tool,
                _dump_json(data["args"]),
                rec.action_hash,
                data["reason"],
                float(rec.risk_score),
                rec.approver_id,
                ApprovalStatus(rec.status).value,
                to_epoch_us(rec.created_at),
                to_epoch_us(rec.expires_at),
                _opt_epoch_us(rec.decided_at),
            ),
            "approval",
        )

    def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        row = self._one("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,))
        return None if row is None else _approval_from_row(row)

    def list_approvals(self, status: ApprovalStatus | None = None) -> list[ApprovalRecord]:
        if status is None:
            rows = self._all("SELECT * FROM approvals ORDER BY created_at, approval_id")
        else:
            rows = self._all(
                "SELECT * FROM approvals WHERE status = ? ORDER BY created_at, approval_id",
                (ApprovalStatus(status).value,),
            )
        return [_approval_from_row(r) for r in rows]

    def transition_approval(
        self,
        approval_id: str,
        expected: ApprovalStatus,
        new: ApprovalStatus,
        *,
        decided_at: datetime | None = None,
    ) -> bool:
        """Atomic compare-and-set: move ``expected`` -> ``new`` only if the row is still
        in ``expected``. True for exactly one caller.

        Why: an approval must be decided once and consumed by exactly one tool call; two
        concurrent retries must not both execute a wire transfer. ``decided_at`` is only
        written when given, so consuming an approval keeps the decision time.

        Low-level: this checks status only. Services must use ``decide_approval`` and
        ``consume_approval``, which also bind the approver / agent / action hash and
        enforce expiry inside the same UPDATE.
        """
        check_approval_transition(expected, new)
        return (
            self._write(
                "UPDATE approvals SET status = ?, decided_at = COALESCE(?, decided_at) "
                "WHERE approval_id = ? AND status = ?",
                (
                    ApprovalStatus(new).value,
                    _opt_epoch_us(decided_at),
                    approval_id,
                    ApprovalStatus(expected).value,
                ),
            )
            == 1
        )

    def decide_approval(
        self, approval_id: str, *, approver_id: str, approve: bool, now: datetime
    ) -> bool:
        """Record the human's decision: PENDING -> APPROVED/DENIED, decided_at = now.

        Why every condition is in the WHERE clause: only the assigned approver may decide,
        only once, and only before the request expires. Checking these in Python first
        and then updating would let two concurrent decisions both pass the checks.
        The TOTP code itself is verified by the caller before this.
        """
        if not isinstance(approve, bool):
            # Fail closed: a truthy string like "false" must not count as approval.
            raise TypeError("approve must be a bool")
        new = ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED
        now_us = to_epoch_us(now)
        return (
            self._write(
                "UPDATE approvals SET status = ?, decided_at = ? "
                "WHERE approval_id = ? AND status = ? AND approver_id = ? AND expires_at > ?",
                (new.value, now_us, approval_id, ApprovalStatus.PENDING.value, approver_id, now_us),
            )
            == 1
        )

    def consume_approval(
        self, approval_id: str, *, agent_id: str, action_hash: str, now: datetime
    ) -> bool:
        """Use an approval for exactly one tool call: APPROVED -> USED.

        Why: the human approved ONE exact action (agent + task + tool + args, summarized
        by action_hash). Binding agent_id and action_hash stops another agent, or the
        same agent with different arguments, from riding on the approval. Single UPDATE,
        so two concurrent retries cannot both execute the action.
        """
        return (
            self._write(
                "UPDATE approvals SET status = ? "
                "WHERE approval_id = ? AND status = ? AND agent_id = ? AND action_hash = ? "
                "AND expires_at > ?",
                (
                    ApprovalStatus.USED.value,
                    approval_id,
                    ApprovalStatus.APPROVED.value,
                    agent_id,
                    action_hash,
                    to_epoch_us(now),
                ),
            )
            == 1
        )

    # -------------------------------------------------------------- risk events

    def add_risk_event(self, event: RiskEvent) -> None:
        data = event.model_dump(mode="json")
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO risk_events (agent_id, task_id, event_type, tool, target, "
                "timestamp, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    event.agent_id,
                    event.task_id,
                    data["event_type"],
                    event.tool,
                    event.target,
                    to_epoch_us(event.timestamp),
                    _dump_json(data["details"]),
                ),
            )

    def list_risk_events(self, agent_id: str, *, since: datetime | None = None) -> list[RiskEvent]:
        """Events of one agent, oldest first. ``since`` is inclusive."""
        if since is None:
            rows = self._all(
                "SELECT * FROM risk_events WHERE agent_id = ? ORDER BY timestamp, id",
                (agent_id,),
            )
        else:
            rows = self._all(
                "SELECT * FROM risk_events WHERE agent_id = ? AND timestamp >= ? "
                "ORDER BY timestamp, id",
                (agent_id, to_epoch_us(since)),
            )
        return [_risk_event_from_row(r) for r in rows]

    def delete_risk_events(self, agent_id: str) -> int:
        return self._write("DELETE FROM risk_events WHERE agent_id = ?", (agent_id,))

    # -------------------------------------------------------------- audit (append-only)

    def insert_audit(self, rec: AuditRecord) -> None:
        """Append one audit record. There is deliberately no update/delete method: the
        log is append-only, and raw-SQL tampering is what the T1.3 hash chain detects.
        The timestamp is stored verbatim so the record hashes identically when read back.
        """
        data = rec.model_dump(mode="json")
        self._insert(
            "INSERT INTO audit (seq, timestamp, prev_hash, hash, component, actor, event, "
            "outcome, reason_code, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rec.seq,
                data["timestamp"],
                rec.prev_hash,
                rec.hash,
                data["component"],
                rec.actor,
                rec.event,
                data["outcome"],
                data["reason_code"],
                _dump_json(data["details"]),
            ),
            "audit seq",
        )

    def last_audit(self) -> AuditRecord | None:
        row = self._one("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (1,))
        return None if row is None else _audit_from_row(row)

    def list_audit(self, after_seq: int = -1, limit: int = 100) -> list[AuditRecord]:
        """Records with seq > after_seq, ascending, at most ``limit``."""
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            # SQLite treats a negative LIMIT as "no limit"; refuse instead.
            raise ValueError("limit must be a non-negative int")
        rows = self._all(
            "SELECT * FROM audit WHERE seq > ? ORDER BY seq LIMIT ?", (int(after_seq), limit)
        )
        return [_audit_from_row(r) for r in rows]
