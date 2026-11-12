"""State behind the mock company systems: files, database tables, bank, email outbox.

All data is FAKE. The gateway has already authorized every call by the time one arrives
here, but each function re-checks its inputs anyway (defense in depth), because a bug in one
layer must not become a hole in the whole system.
"""

from __future__ import annotations

import json
import secrets
import shutil
import sqlite3
import threading
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aimfa.common.config import Settings
from aimfa.common.http import ApiError
from aimfa.common.models import ReasonCode
from aimfa.common.policy import PolicyError, normalize_path

SEED_DIR = Path(__file__).resolve().parent / "seed_data"
SEED_DB = SEED_DIR / "db.json"

# Table name -> constant SQL. A request can only pick a KEY of this dict; no part of the
# SQL text ever comes from the request (AGENTS.md rule 8), so there is nothing to inject.
_SELECT = {
    "vendors": "SELECT id, name, account, approved FROM vendors ORDER BY id",
    "payroll": "SELECT id, employee, salary FROM payroll ORDER BY id",
}
_DELETE = {
    "vendors": "DELETE FROM vendors",
    "payroll": "DELETE FROM payroll",
}

_SCHEMA = """
CREATE TABLE vendors (id INTEGER PRIMARY KEY, name TEXT, account TEXT, approved INTEGER);
CREATE TABLE payroll (id INTEGER PRIMARY KEY, employee TEXT, salary INTEGER);
CREATE TABLE bank (id INTEGER PRIMARY KEY CHECK (id = 1), balance REAL NOT NULL);
"""


def _bad_request(message: str) -> ApiError:
    return ApiError(400, ReasonCode.INVALID_ARGUMENTS, message)


def canonical_path(raw: str) -> str:
    """Normalize ``raw`` and refuse it unless it was already in canonical form.

    ``normalize_path`` rejects ``..``, backslashes and odd characters. We additionally refuse
    input that normalization would silently rewrite (``//etc/passwd``, ``/a/./b``, a
    trailing slash): the gateway sends canonical paths, so anything else is suspicious, and
    rewriting it would mean we serve a different file than the caller named.
    """
    try:
        normalized = normalize_path(raw)
    except PolicyError:
        raise _bad_request("invalid path") from None
    if normalized != raw:
        raise _bad_request("path is not canonical")
    return normalized


class ResourceStore:
    """Files under ``data_dir/resources``, SQLite tables, bank balance and the outbox."""

    def __init__(self, settings: Settings) -> None:
        self.root = (settings.data_dir / "resources").resolve()
        self.db_path = settings.data_dir / "resources.db"
        self.outbox = settings.data_dir / "outbox.jsonl"
        self._lock = threading.Lock()
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        if not self.root.exists() or not self.db_path.exists():
            self.reset()

    # ------------------------------------------------------------------ seeding
    def reset(self) -> None:
        """Wipe and re-seed everything, including the outbox (demo evidence)."""
        with self._lock:
            if self.root.exists():
                shutil.rmtree(self.root)
            shutil.copytree(SEED_DIR, self.root, ignore=shutil.ignore_patterns("db.json"))
            self.db_path.unlink(missing_ok=True)
            self.outbox.unlink(missing_ok=True)
            seed = json.loads(SEED_DB.read_text(encoding="utf-8"))
            with closing(self._connect()) as conn:
                conn.executescript(_SCHEMA)
                conn.executemany(
                    "INSERT INTO vendors (id, name, account, approved) VALUES (?, ?, ?, ?)",
                    [
                        (v["id"], v["name"], v["account"], int(v["approved"]))
                        for v in seed["vendors"]
                    ],
                )
                conn.executemany(
                    "INSERT INTO payroll (id, employee, salary) VALUES (?, ?, ?)",
                    [(p["id"], p["employee"], p["salary"]) for p in seed["payroll"]],
                )
                conn.execute(
                    "INSERT INTO bank (id, balance) VALUES (1, ?)", (seed["bank_balance"],)
                )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------ files
    def _locate(self, raw: str) -> tuple[str, Path]:
        """Canonical path plus its on-disk location, proven to be inside the data root.

        ``resolve()`` follows symlinks, so a link planted inside the tree cannot lead out of
        it. The access then uses this same resolved path (rule 7).
        """
        normalized = canonical_path(raw)
        target = (self.root / normalized.lstrip("/")).resolve()
        if target != self.root and not target.is_relative_to(self.root):
            raise _bad_request("path escapes the data root")
        return normalized, target

    def list_dir(self, raw: str) -> dict[str, Any]:
        normalized, target = self._locate(raw)
        if not target.is_dir():
            raise ApiError(404, ReasonCode.INVALID_ARGUMENTS, "directory not found")
        prefix = normalized.rstrip("/")
        entries = sorted(
            f"{prefix}/{p.name}" + ("/" if p.is_dir() else "") for p in target.iterdir()
        )
        return {"dir": normalized, "entries": entries}

    def read_file(self, raw: str) -> dict[str, Any]:
        normalized, target = self._locate(raw)
        if not target.is_file():
            raise ApiError(404, ReasonCode.INVALID_ARGUMENTS, "file not found")
        return {"path": normalized, "content": target.read_text(encoding="utf-8", errors="replace")}

    def write_file(self, raw: str, content: str) -> dict[str, Any]:
        normalized, target = self._locate(raw)
        if normalized == "/" or target.is_dir():
            raise _bad_request("path is a directory")
        data = content.encode("utf-8")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        except OSError:
            raise _bad_request("cannot write that path") from None
        return {"path": normalized, "bytes": len(data)}

    # ------------------------------------------------------------------ email
    def send_email(self, to: str, subject: str, body: str) -> dict[str, Any]:
        """Append the email to the outbox; the demo shows whether an exfil mail "left"."""
        message_id = f"msg-{secrets.token_hex(8)}"
        row = {
            "message_id": message_id,
            "to": to,
            "subject": subject,
            "body": body,
            "sent_at": datetime.now(UTC).isoformat(),
        }
        with self._lock, self.outbox.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        return {"message_id": message_id}

    # ------------------------------------------------------------------ bank
    def wire(self, amount: float) -> dict[str, Any]:
        """Debit the balance atomically; refuse to overdraw."""
        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            changed = conn.execute(
                "UPDATE bank SET balance = balance - ? WHERE id = 1 AND balance >= ?",
                (amount, amount),
            ).rowcount
            balance = conn.execute("SELECT balance FROM bank WHERE id = 1").fetchone()["balance"]
            conn.execute("COMMIT")
        if changed != 1:
            raise ApiError(422, ReasonCode.INVALID_ARGUMENTS, "insufficient funds")
        return {"transfer_id": f"tx-{secrets.token_hex(8)}", "balance": balance}

    # ------------------------------------------------------------------ db
    def _known_table(self, table: str) -> str:
        if table not in _SELECT:
            raise ApiError(404, ReasonCode.INVALID_ARGUMENTS, "unknown table")
        return table

    def read_table(self, table: str) -> dict[str, Any]:
        sql = _SELECT[self._known_table(table)]
        with closing(self._connect()) as conn:
            rows = [dict(r) for r in conn.execute(sql).fetchall()]
        return {"table": table, "rows": rows}

    def delete_table(self, table: str) -> dict[str, Any]:
        sql = _DELETE[self._known_table(table)]
        with self._lock, closing(self._connect()) as conn:
            conn.execute(sql)
        return {"table": table, "deleted": True}
