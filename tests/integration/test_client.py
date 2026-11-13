"""T3.3 AgentClient tests against the in-process stack.

ASSUMPTIONS: the client uses real time for DPoP `iat` (FakeClock starts at real now and is not
advanced in these tests). Poll timeout is counted from the sleeps requested (sum of
`poll_interval` per poll), so a no-op `sleep` still terminates with ApprovalTimeout.
`call()` returns the final 200 ToolCallResponse; `start_task` stores the access token and task.
"""

from __future__ import annotations

import pytest
from aimfa.agents.client import (
    AgentClient,
    AimfaError,
    ApprovalTimeout,
    AuthError,
    PolicyDenied,
)

from aimfa.common.models import ReasonCode, TokenResponse
from tests.integration.conftest import valid_code

MAIL = {"to": "x@evil.example", "subject": "s", "body": "b"}


def make_client(stack, agent_id="expense-bot", role="expense_reader", **kw) -> AgentClient:
    key, ident = stack.h.onboard(agent_id, role)
    return AgentClient(stack.settings, key, ident, cp_http=stack.h.cp, gateway_http=stack.gw, **kw)


def approver_sleep(stack, approve: bool):
    """A sleep() stand-in that has the human decide the single pending approval."""

    def _sleep(_seconds: float) -> None:
        pending = stack.h.cp.get("/admin/approvals?status=pending", headers=stack.h.admin).json()
        for rec in pending:
            code = valid_code(stack.seed, stack.clock())
            r = stack.decide(rec["approval_id"], approve=approve, code=code)
            assert r.status_code == 200, r.text

    return _sleep


def test_start_task_and_read_returns_200(stack):
    c = make_client(stack)
    tr = c.start_task("summarize", ["files:read:/expenses/*"])
    assert isinstance(tr, TokenResponse) and tr.task_id
    r = c.call("read_file", path="/expenses/q3.csv")
    assert r.decision.outcome == "allow" and r.result["content"].strip()


def test_scope_escalation_in_start_task_raises_policy_denied(stack):
    c = make_client(stack)
    with pytest.raises(PolicyDenied) as ei:
        c.start_task("sneaky", ["files:read:/engineering/*"])
    assert ei.value.reason_code == ReasonCode.STS_SCOPE_ESCALATION
    assert ei.value.status_code == 403
    assert isinstance(ei.value, AimfaError)


def test_out_of_scope_call_raises_policy_denied(stack):
    c = make_client(stack)
    c.start_task("t", ["files:read:/expenses/*"])
    with pytest.raises(PolicyDenied) as ei:
        c.call("read_file", path="/engineering/docs/design.md")
    assert ei.value.reason_code == ReasonCode.SCOPE_DENIED


def test_invalid_arguments_raise_policy_denied_422(stack):
    c = make_client(stack)
    c.start_task("t", ["files:read:/expenses/*"])
    with pytest.raises(PolicyDenied) as ei:
        c.call("read_file", path="/expenses/../engineering/secrets.env")
    assert (ei.value.status_code, ei.value.reason_code) == (422, ReasonCode.INVALID_ARGUMENTS)


def test_each_request_uses_a_fresh_proof(stack):
    c = make_client(stack)
    c.start_task("t", ["files:read:/expenses/*"])
    for _ in range(3):  # a reused jti would be DPOP_REPLAY
        assert c.call("read_file", path="/expenses/q3.csv").decision.outcome == "allow"


def test_complete_task_then_call_raises_auth_error_revoked(stack):
    c = make_client(stack)
    c.start_task("t", ["files:read:/expenses/*"])
    assert c.complete_task() is None
    with pytest.raises(AuthError) as ei:
        c.call("read_file", path="/expenses/q3.csv")
    assert (ei.value.status_code, ei.value.reason_code) == (401, ReasonCode.TOKEN_REVOKED)


def test_approval_approved_while_polling_returns_final_200(stack):
    c = make_client(stack, "wire-bot", "finance_ops", sleep=approver_sleep(stack, approve=True))
    c.start_task("notify", ["email:send:external"])
    r = c.call("send_email", **MAIL)
    assert r.decision.outcome == "allow"
    assert (stack.settings.data_dir / "outbox.jsonl").read_text(encoding="utf-8").count("\n") == 1


def test_approval_denied_raises_policy_denied_and_does_not_execute(stack):
    c = make_client(stack, "wire-bot", "finance_ops", sleep=approver_sleep(stack, approve=False))
    c.start_task("notify", ["email:send:external"])
    with pytest.raises(PolicyDenied) as ei:
        c.call("send_email", **MAIL)
    assert ei.value.reason_code == ReasonCode.APPROVAL_DENIED
    assert not (stack.settings.data_dir / "outbox.jsonl").exists()


def test_approval_poll_timeout_raises(stack):
    slept: list[float] = []
    c = make_client(
        stack,
        "wire-bot",
        "finance_ops",
        poll_interval=1.0,
        poll_timeout=3.0,
        sleep=slept.append,  # time never advances, nobody approves
    )
    c.start_task("notify", ["email:send:external"])
    with pytest.raises(ApprovalTimeout):
        c.call("send_email", **MAIL)
    assert slept and not (stack.settings.data_dir / "outbox.jsonl").exists()


def test_call_before_start_task_fails_closed(stack):
    c = make_client(stack)
    with pytest.raises(AimfaError):
        c.call("read_file", path="/expenses/q3.csv")
