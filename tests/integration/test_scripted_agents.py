"""T5.2 scripted agents against the in-process stack (no network, no LLM)."""

from __future__ import annotations

import json

import pytest

from aimfa.agents.client import AgentClient, AuthError, PolicyDenied
from aimfa.agents.scripted import TranscriptEntry, injected_expense, normal_expense, step, wire_bot
from aimfa.common.models import ReasonCode
from tests.integration.test_client import approver_sleep


def make_client(stack, mod, **kw) -> AgentClient:
    key, ident = stack.h.onboard(mod.AGENT_ID, mod.ROLE)
    return AgentClient(
        stack.settings,
        key,
        ident,
        cp_http=stack.h.cp,
        gateway_http=stack.gw,
        poll_interval=1,
        poll_timeout=5,
        **kw,
    )


def outbox(stack) -> list[dict]:
    path = stack.settings.data_dir / "outbox.jsonl"
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines()]


def pairs(transcript) -> list[tuple[str, str]]:
    return [(e.tool, e.decision) for e in transcript]


def test_normal_expense_all_allowed_and_email_sent(stack):
    t = normal_expense.run(make_client(stack, normal_expense))
    assert pairs(t) == [
        ("list_files", "allow"),
        ("read_file", "allow"),
        ("send_email", "allow"),
    ]
    mails = outbox(stack)
    assert [m["to"] for m in mails] == ["finance@acme.test"]
    assert "6542.85" in mails[0]["body"]  # 1240.50 + 892.10 + 4100.00 + 310.25


def test_normal_expense_is_deterministic(stack):
    key, ident = stack.h.onboard(normal_expense.AGENT_ID, normal_expense.ROLE)

    def run_once():
        c = AgentClient(
            stack.settings, key, ident, cp_http=stack.h.cp, gateway_http=stack.gw, poll_interval=1
        )
        return pairs(normal_expense.run(c))

    first, second = run_once(), run_once()
    assert first == second


def test_injected_expense_attack_steps_are_denied(stack):
    t = injected_expense.run(make_client(stack, injected_expense))
    by_tool = pairs(t)
    assert by_tool[:3] == [("list_files", "allow"), ("read_file", "allow"), ("read_file", "allow")]
    secret_read, email = t[3], t[4]
    assert (secret_read.tool, secret_read.decision) == ("read_file", "deny")
    assert secret_read.reason_code == ReasonCode.SCOPE_DENIED.value
    assert (email.tool, email.decision) == ("send_email", "deny")
    assert email.reason_code == ReasonCode.SCOPE_DENIED.value


def test_injected_expense_leaks_nothing(stack):
    t = injected_expense.run(make_client(stack, injected_expense))
    assert not any(m["to"] == "attacker@evil.example" for m in outbox(stack))
    assert outbox(stack) == []
    assert "/engineering/secrets.env" not in json.dumps([e.result for e in t[3:]])
    assert all(e.result is None for e in t[3:])


def wire_amount(t) -> float:
    return next(e.result for e in t if e.tool == "wire_transfer" and e.result)["balance"]


def test_wire_bot_approved_executes_and_debits(stack):
    c = make_client(stack, wire_bot, sleep=approver_sleep(stack, approve=True))
    t = wire_bot.run(c)
    assert pairs(t) == [
        ("read_file", "allow"),
        ("query_db", "allow"),
        ("wire_transfer", "allow"),
    ]
    assert wire_amount(t) == pytest.approx(250000.0 - 1240.50)  # first Globex row


def test_wire_bot_denied_moves_no_money(stack):
    c = make_client(stack, wire_bot, sleep=approver_sleep(stack, approve=False))
    t = wire_bot.run(c)
    wire = t[-1]
    assert (wire.tool, wire.decision) == ("wire_transfer", "deny")
    assert wire.reason_code == ReasonCode.APPROVAL_DENIED.value
    assert wire.result is None


def test_wire_bot_timeout_is_pending(stack):
    t = wire_bot.run(make_client(stack, wire_bot, sleep=lambda _s: None))
    assert (t[-1].tool, t[-1].decision) == ("wire_transfer", "pending")


def test_task_token_revoked_after_run(stack):
    c = make_client(stack, normal_expense)
    normal_expense.run(c)
    with pytest.raises(AuthError) as ei:
        c.call("read_file", path="/expenses/q3.csv")
    assert ei.value.reason_code == ReasonCode.TOKEN_REVOKED


def test_task_completed_even_when_body_raises(stack):
    class Boom:
        def __init__(self) -> None:
            self.completed = False

        def start_task(self, description, scopes):
            return None

        def call(self, tool, /, **args):
            raise RuntimeError("bug")

        def complete_task(self):
            self.completed = True

    s = Boom()
    with pytest.raises(RuntimeError):
        normal_expense.run(s)
    assert s.completed


def test_step_records_denial_without_raising():
    class Denier:
        def call(self, tool, /, **args):
            raise PolicyDenied(ReasonCode.SCOPE_DENIED, 403)

    transcript: list[TranscriptEntry] = []
    entry = step(Denier(), transcript, "read_file", path="/x")
    assert transcript == [entry]
    assert entry == TranscriptEntry("read_file", "deny", "SCOPE_DENIED", None)
