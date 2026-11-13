"""Control-plane approval + internal audit routes (pulled forward from T4.x for the gateway).

ASSUMPTIONS: decide on an already-decided approval returns 409 (checked with a fresh, unused TOTP
window impossible within one window, so the test advances the clock 60s first). Error bodies are
ErrorResponse. ntfy is not involved (ntfy_enabled=False).
"""

from __future__ import annotations

import hashlib
import json

import pytest

from tests.integration.conftest import (
    APPROVER,
    enroll_approver,
    invalid_code,
    valid_code,
)


def action_hash(agent_id, task_id, tool, args) -> str:
    obj = {"agent_id": agent_id, "task_id": task_id, "tool": tool, "args": args}
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


ARGS = {"to": "x@evil.example", "subject": "s", "body": "b"}


class Env:
    def __init__(self, h):
        self.h = h
        self.seed = enroll_approver(h)
        self.key, ident = h.onboard("expense-bot")
        r = h.request_token(self.key, ident, ["files:read:/expenses/*"])
        self.access, self.task_id = r.json()["access_token"], r.json()["task_id"]

    def create(self, args=None, agent_id="expense-bot", task_id=None):
        args = args or ARGS
        task_id = task_id or self.task_id
        body = {
            "agent_id": agent_id,
            "task_id": task_id,
            "tool": "send_email",
            "args": args,
            "action_hash": action_hash(agent_id, task_id, "send_email", args),
            "reason": "high_tier",
        }
        return self.h.cp.post("/internal/approvals", json=body, headers=self.h.internal)

    def new_id(self, args=None) -> str:
        r = self.create(args)
        assert r.status_code == 201, r.text
        return r.json()["approval_id"]

    def decide(self, aid, *, approve=True, code=None, approver=APPROVER):
        code = code or valid_code(self.seed, self.h.clock())
        body = {"approver_id": approver, "approve": approve, "totp_code": code}
        return self.h.cp.post(f"/approvals/{aid}/decide", json=body, headers=self.h.admin)

    def consume(self, aid, args=None):
        body = {"action_hash": action_hash("expense-bot", self.task_id, "send_email", args or ARGS)}
        return self.h.cp.post(
            f"/internal/approvals/{aid}/consume", json=body, headers=self.h.internal
        )

    def status(self, aid, key=None, access=None):
        path = f"/approvals/{aid}"
        hdrs = self.h.auth_headers(key or self.key, access or self.access, "GET", path)
        return self.h.cp.get(path, headers=hdrs)


@pytest.fixture
def env(h) -> Env:
    return Env(h)


@pytest.mark.parametrize(
    ("path", "body"),
    [
        (
            "/internal/audit",
            {"component": "gateway", "actor": "x", "event": "e", "outcome": "info"},
        ),
        ("/internal/approvals", {}),
        ("/internal/approvals/abc/consume", {"action_hash": "0" * 64}),
    ],
)
@pytest.mark.parametrize("headers", [{}, {"X-Internal-Secret": "wrong"}])
def test_internal_routes_reject_bad_secret(h, path, body, headers):
    r = h.cp.post(path, json=body, headers=headers)
    assert (r.status_code, r.json()["reason_code"]) == (401, "UNAUTHORIZED")


def test_create_approval_is_pending_with_registered_approver_and_expiry(env):
    r = env.create()
    assert r.status_code == 201, r.text
    rec = r.json()
    assert rec["status"] == "pending" and rec["approver_id"] == APPROVER
    assert rec["approval_id"]
    from datetime import datetime

    exp = datetime.fromisoformat(rec["expires_at"].replace("Z", "+00:00"))
    assert int((exp - env.h.clock()).total_seconds()) == env.h.settings.approval_timeout_seconds


def test_decide_with_wrong_totp_is_401(env):
    aid = env.new_id()
    r = env.decide(aid, code=invalid_code(env.seed, env.h.clock()))
    assert (r.status_code, r.json()["reason_code"]) == (401, "APPROVAL_INVALID_TOTP")
    assert env.status(aid).json()["status"] == "pending"


def test_totp_code_cannot_be_reused_across_approvals(env):
    a1, a2 = env.new_id(), env.new_id({**ARGS, "to": "y@evil.example"})
    code = valid_code(env.seed, env.h.clock())
    assert env.decide(a1, code=code).status_code == 200
    r = env.decide(a2, code=code)
    assert (r.status_code, r.json()["reason_code"]) == (401, "APPROVAL_INVALID_TOTP")


def test_wrong_approver_cannot_decide(env):
    bob_seed = enroll_approver(env.h, "bob-approver")
    aid = env.new_id()
    r = env.decide(aid, approver="bob-approver", code=valid_code(bob_seed, env.h.clock()))
    assert (r.status_code, r.json()["reason_code"]) == (401, "APPROVAL_INVALID_TOTP")


def test_decide_twice_is_409(env):
    aid = env.new_id()
    assert env.decide(aid).status_code == 200
    env.h.clock.advance(60)  # fresh TOTP window, so only "already decided" can reject
    assert env.decide(aid).status_code == 409


def test_consume_lifecycle_and_errors(env):
    aid = env.new_id()
    r = env.consume(aid)
    assert (r.status_code, r.json()["reason_code"]) == (403, "APPROVAL_STILL_PENDING")
    env.decide(aid)
    r = env.consume(aid, {**ARGS, "to": "z@evil.example"})
    assert (r.status_code, r.json()["reason_code"]) == (403, "APPROVAL_MISMATCH")
    ok = env.consume(aid)
    assert ok.status_code == 200 and ok.json()["status"] == "used"
    r = env.consume(aid)
    assert (r.status_code, r.json()["reason_code"]) == (403, "APPROVAL_ALREADY_USED")


def test_consume_denied_and_unknown(env):
    aid = env.new_id()
    env.decide(aid, approve=False)
    r = env.consume(aid)
    assert (r.status_code, r.json()["reason_code"]) == (403, "APPROVAL_DENIED")
    r = env.consume("does-not-exist")
    assert (r.status_code, r.json()["reason_code"]) == (404, "APPROVAL_NOT_FOUND")


def test_consume_past_expiry_is_expired_even_if_approved(env):
    aid = env.new_id()
    env.decide(aid)
    env.h.clock.advance(env.h.settings.approval_timeout_seconds + 1)
    r = env.consume(aid)
    assert (r.status_code, r.json()["reason_code"]) == (403, "APPROVAL_EXPIRED")


def test_agent_polls_status_and_other_agent_gets_404(env):
    aid = env.new_id()
    r = env.status(aid)
    assert r.status_code == 200
    assert r.json() == {"approval_id": aid, "status": "pending"}
    key2, ident2 = env.h.onboard("other-bot")
    tok2 = env.h.request_token(key2, ident2, ["files:read:/expenses/*"]).json()["access_token"]
    r = env.status(aid, key2, tok2)
    assert (r.status_code, r.json()["reason_code"]) == (404, "APPROVAL_NOT_FOUND")


def test_internal_audit_appends_gateway_record(h):
    body = {
        "component": "gateway",
        "actor": "expense-bot",
        "event": "gateway.tool_call",
        "outcome": "deny",
        "reason_code": "SCOPE_DENIED",
    }
    r = h.cp.post("/internal/audit", json=body, headers=h.internal)
    assert r.status_code in (200, 201), r.text
    assert r.json()["component"] == "gateway" and r.json()["hash"]
    h.assert_audited("SCOPE_DENIED")
    assert h.cp.get("/admin/audit/verify", headers=h.admin).json()["ok"] is True
