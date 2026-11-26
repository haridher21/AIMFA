"""demo_autoplay.py: the pieces that must never go wrong on stage (no processes, no network)."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from aimfa.common.config import Settings
from aimfa.common.models import ApprovalRecord, ApprovalStatus
from scripts import demo_autoplay

GOOD = "x" * 32


def _settings(tmp_path, **over) -> Settings:
    base = {
        "admin_api_key": GOOD,
        "internal_service_secret": GOOD + "1",
        "gateway_resource_secret": GOOD + "2",
        "baseline_api_key": GOOD + "3",
        "data_dir": tmp_path / "var",
    }
    return Settings(_env_file=None, **{**base, **over})


def test_steps_parse_by_name_or_number_in_demo_order():
    assert demo_autoplay.parse_steps(None) == list(demo_autoplay.STEPS)
    assert demo_autoplay.parse_steps("audit, 6") == ["human", "audit"]


@pytest.mark.parametrize("bad", ["nope", "0", "9"])
def test_unknown_step_is_refused(bad):
    with pytest.raises(ValueError, match="unknown step"):
        demo_autoplay.parse_steps(bad)


def test_default_secrets_refused_before_anything_starts(tmp_path, capsys):
    started = []
    s = Settings(_env_file=None, data_dir=tmp_path / "var")
    assert demo_autoplay.main([], settings=s, demo_factory=lambda *a, **k: started.append(1)) == 2
    assert not started
    assert "change-me" not in capsys.readouterr().out


def test_tampered_prompt_is_restored_byte_for_byte_even_on_error(tmp_path):
    s = _settings(tmp_path)
    prompt = tmp_path / "p.md"
    original = b"You are an expense bot.\r\n"
    prompt.write_bytes(original)
    with pytest.raises(RuntimeError), demo_autoplay.tampered_prompt(s, prompt):
        assert prompt.read_bytes() != original
        raise RuntimeError("step crashed")
    assert prompt.read_bytes() == original
    assert not demo_autoplay._backup_path(s).exists()


def test_prompt_left_modified_by_a_killed_run_is_restored(tmp_path):
    s = _settings(tmp_path)
    prompt = tmp_path / "p.md"
    prompt.write_bytes(b"tampered!")
    backup = demo_autoplay._backup_path(s)
    backup.parent.mkdir(parents=True)
    backup.write_bytes(b"original")
    assert demo_autoplay.restore_leftover_prompt(s, prompt) is True
    assert prompt.read_bytes() == b"original"
    assert demo_autoplay.restore_leftover_prompt(s, prompt) is False  # nothing left to do


def test_leftovers_are_repaired_before_a_reset_deletes_their_backups(tmp_path, monkeypatch):
    """Otherwise --reset wipes the backup and the tampered prompt becomes the golden value."""
    calls: list[str] = []
    monkeypatch.setattr(demo_autoplay, "busy_ports", lambda s: [])
    monkeypatch.setattr(demo_autoplay, "restore_leftover_prompt", lambda s: calls.append("p"))
    monkeypatch.setattr(demo_autoplay, "restore_leftover_audit_row", lambda s: calls.append("a"))
    monkeypatch.setattr(demo_autoplay.run_demo, "safe_reset", lambda p: calls.append("reset"))

    class FakeDemo:
        def __init__(self, *a, **k):
            self.stack = type("S", (), {"stop": lambda self: None})()

        def run(self, steps):
            calls.append("run")

    assert demo_autoplay.main(["--reset"], settings=_settings(tmp_path), demo_factory=FakeDemo) == 0
    assert calls == ["p", "a", "reset", "run"]


def _audit_db(s: Settings) -> sqlite3.Connection:
    s.data_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(s.db_path)
    conn.execute("CREATE TABLE audit (seq INTEGER PRIMARY KEY, outcome TEXT NOT NULL)")
    conn.executemany("INSERT INTO audit VALUES (?, ?)", [(1, "deny"), (2, "allow")])
    conn.commit()
    return conn


def _outcome(conn: sqlite3.Connection, seq: int) -> str:
    return conn.execute("SELECT outcome FROM audit WHERE seq = ?", (seq,)).fetchone()[0]


def test_tampered_audit_row_is_put_back_even_on_error(tmp_path):
    s = _settings(tmp_path)
    conn = _audit_db(s)
    with pytest.raises(RuntimeError), demo_autoplay.tampered_audit_row(s) as seq:
        assert seq == 1 and _outcome(conn, 1) == "allow"
        raise RuntimeError("step crashed")
    assert _outcome(conn, 1) == "deny"
    assert not demo_autoplay._audit_backup_path(s).exists()
    conn.close()


def test_audit_row_left_by_a_killed_run_is_restored(tmp_path):
    s = _settings(tmp_path)
    conn = _audit_db(s)
    conn.execute("UPDATE audit SET outcome = 'allow' WHERE seq = 1")
    conn.commit()
    backup = demo_autoplay._audit_backup_path(s)
    backup.parent.mkdir(parents=True)
    backup.write_text('{"seq": 1, "outcome": "deny"}', encoding="utf-8")
    assert demo_autoplay.restore_leftover_audit_row(s) is True
    assert _outcome(conn, 1) == "deny"
    assert not backup.exists()
    conn.close()


def _approval(agent: str, tool: str, created: datetime, status=ApprovalStatus.PENDING):
    return ApprovalRecord(
        agent_id=agent,
        task_id="t",
        tool=tool,
        args={},
        action_hash="0" * 64,
        reason="high_tier",
        risk_score=0.0,
        approval_id=f"{agent}-{created.timestamp()}",
        approver_id="approver",
        status=status,
        created_at=created,
        expires_at=created + timedelta(minutes=5),
    )


def test_find_approval_picks_this_steps_request_not_a_leftover():
    """The payroll step leaves a pending email approval; the human step must not approve it."""
    now = datetime.now(UTC)
    leftover = _approval("payroll-exfil-bot", "send_email", now)
    old_wire = _approval("wire-bot", "wire_transfer", now - timedelta(minutes=2))
    used_wire = _approval("wire-bot", "wire_transfer", now, ApprovalStatus.APPROVED)
    this_wire = _approval("wire-bot", "wire_transfer", now + timedelta(seconds=1))
    found = demo_autoplay.find_approval(
        [leftover, old_wire, used_wire, this_wire], "wire-bot", "wire_transfer", now
    )
    assert found is this_wire
    assert demo_autoplay.find_approval([leftover], "wire-bot", "wire_transfer", now) is None
