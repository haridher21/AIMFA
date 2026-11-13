"""A8: an insider with database access rewrites an audit row to hide a denial.

AIMFA: each audit row stores the hash of the row before it, so the edit breaks the chain and
``AuditLog.verify()`` reports it (AUDIT_CHAIN_BROKEN). The edit uses valid values so it is the
HASH, not a parse error, that catches it.

Baseline model (modelled: baseline has no chained audit): the old way is a plain JSONL log
file with no hashes (``PlainLog`` below), written to the temp dir from the same events. We
edit that file on disk, then "verify" it. The best a plain log can check is "do the rows still
parse?", which the edited file passes, so the tamper goes unnoticed.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from aimfa.common.db import Database
from aimfa.common.models import DecisionOutcome, ReasonCode
from aimfa.control_plane.audit import AuditLog
from attacks.common import (
    LAYER_HASH_CHAIN,
    MODE_BASELINE,
    AttackError,
    AttackResult,
    Env,
    check_mode,
    result,
)

NAME = "A8 audit tampering"


class PlainLog:
    """An unchained log file: one JSON row of (outcome, reason_code) per line, no hashes."""

    def __init__(self, path: Path, rows: list[tuple[str, str]]) -> None:
        self.path = path
        lines = [json.dumps({"outcome": o, "reason_code": r}) for o, r in rows]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def edit(self, index: int, outcome: str, reason: str) -> None:
        """The insider rewrites one line of the file on disk."""
        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines[index] = json.dumps({"outcome": outcome, "reason_code": reason})
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def verify(self) -> bool:
        """Only checks that every row is well-formed; there is nothing else to check."""
        valid_outcomes = {*(o.value for o in DecisionOutcome), "info"}
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                if row["outcome"] not in valid_outcomes:
                    return False
                ReasonCode(row["reason_code"])
            return True
        except (ValueError, KeyError, TypeError):
            return False


def _generate_activity(env: Env) -> None:
    """A few real decisions: some allowed, one denied (the one the insider wants to erase)."""
    if env.mode == MODE_BASELINE:
        env.baseline_call("read_file", {"path": "/expenses/q3.csv"})
        env.baseline_call("read_file", {"path": "/expenses/../nope"})
        return
    key, ident = env.onboard("victim-bot", "expense_reader")
    token = env.get_token(key, ident, ["files:read:/expenses/*"])["access_token"]
    env.gateway_call(key, token, "read_file", {"path": "/expenses/q3.csv"})
    env.gateway_call(key, token, "read_file", {"path": "/engineering/secrets.env"})  # denied
    env.gateway_call(key, token, "read_file", {"path": "/expenses/q4_draft.csv"})


def run(mode: str) -> AttackResult:
    check_mode(mode)
    with Env(mode) as env:
        _generate_activity(env)
        records = env.audit()
        denials = [r for r in records if r["outcome"] == DecisionOutcome.DENY.value]
        if not denials:
            raise AttackError("no denial was audited: scene is wrong")
        target = denials[0]

        if mode == MODE_BASELINE:
            plain = PlainLog(
                env.settings.data_dir / "plain_audit.jsonl",
                [(r["outcome"], r["reason_code"]) for r in records],
            )
            index = next(i for i, r in enumerate(records) if r["seq"] == target["seq"])
            plain.edit(index, DecisionOutcome.ALLOW.value, ReasonCode.OK.value)
            return result(
                NAME,
                mode,
                succeeded=plain.verify(),
                evidence=(
                    "modelled: baseline has no chained audit; "
                    f"denial at row {target['seq']} of a plain JSONL file rewritten to allow; "
                    "plain log still verifies"
                ),
            )

        log = AuditLog(Database(env.settings.db_path))
        if not log.verify().ok:
            raise AttackError("audit chain was already broken before the attack")
        conn = sqlite3.connect(env.settings.db_path)  # the insider bypasses the app entirely
        try:
            conn.execute(
                "UPDATE audit SET outcome = ?, reason_code = ? WHERE seq = ?",
                (DecisionOutcome.ALLOW.value, ReasonCode.OK.value, target["seq"]),
            )
            conn.commit()
        finally:
            conn.close()
        verdict = log.verify()
        return result(
            NAME,
            mode,
            succeeded=verdict.ok,
            blocked_by=LAYER_HASH_CHAIN,
            reason_code=verdict.reason_code,
            evidence=(
                f"row {target['seq']} rewritten via SQL; verify ok={verdict.ok}, "
                f"first_bad_seq={verdict.first_bad_seq}"
            ),
        )
