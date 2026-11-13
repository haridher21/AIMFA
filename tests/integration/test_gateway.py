"""T3.1 gateway pipeline tests (in-process CP + resources + gateway via the `stack` fixture).

ASSUMPTIONS: 2xx bodies are ToolCallResponse; error bodies are ErrorResponse (top-level
`reason_code`). `reason_of` accepts either shape. "No tool maps to resources /admin/reset" is
tested behaviorally (unknown tool / traversal) because proxy internals are not specified.
"""

from __future__ import annotations

import json

import pytest

from aimfa.common.crypto import generate_keypair
from tests.integration.conftest import GATEWAY_SECRET, reason_of

READ = {"path": "/expenses/q3.csv"}
EVIL_MAIL = {"to": "x@evil.example", "subject": "s", "body": "b"}
FIN_SCOPES = ["email:send:external", "bank:wire:*"]


@pytest.fixture
def exp(stack):
    return stack.onboard_task()


@pytest.fixture
def fin(stack):
    return stack.onboard_task("wire-bot", "finance_ops", FIN_SCOPES)


def gw_audit(stack, code):
    return [r for r in stack.h.audit() if r["component"] == "gateway" and r["reason_code"] == code]


def outbox_lines(stack):
    path = stack.settings.data_dir / "outbox.jsonl"
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def test_health_reports_aimfa_mode(stack):
    assert stack.gw.get("/health").json() == {"status": "ok", "mode": "aimfa"}


def test_happy_path_read_returns_content_and_is_audited(stack, exp):
    key, access, _ = exp
    r = stack.call(key, access, "read_file", READ)
    assert r.status_code == 200, r.text
    assert r.json()["decision"]["outcome"] == "allow"
    assert r.json()["result"]["content"].strip()
    assert GATEWAY_SECRET not in r.text
    assert gw_audit(stack, "OK")


def test_no_token_is_401_token_missing(stack):
    r = stack.gw.post("/tool", json={"tool": "read_file", "args": READ})
    assert (r.status_code, reason_of(r)) == (401, "TOKEN_MISSING")
    assert gw_audit(stack, "TOKEN_MISSING")


def test_garbage_token_is_401_token_invalid(stack, exp):
    key, _, _ = exp
    r = stack.call(key, "x", "read_file", READ, headers=stack.headers(key, "not.a.jwt"))
    assert (r.status_code, reason_of(r)) == (401, "TOKEN_INVALID")


def test_identity_token_as_access_token_is_401_token_invalid(stack):
    key, ident = stack.h.onboard("ident-bot")
    r = stack.call(key, ident, "read_file", READ)
    assert (r.status_code, reason_of(r)) == (401, "TOKEN_INVALID")


def test_expired_token_is_401_token_expired(stack, exp):
    key, access, _ = exp
    stack.clock.advance(stack.settings.access_token_ttl_seconds + 1)
    r = stack.call(key, access, "read_file", READ)
    assert (r.status_code, reason_of(r)) == (401, "TOKEN_EXPIRED")


def test_proof_from_other_key_is_401_key_mismatch(stack, exp):
    _, access, _ = exp
    r = stack.call(generate_keypair(), access, "read_file", READ)
    assert (r.status_code, reason_of(r)) == (401, "DPOP_KEY_MISMATCH")


def test_proof_without_ath_is_401_ath_mismatch(stack, exp):
    key, access, _ = exp
    h = {"Authorization": f"DPoP {access}", "DPoP": stack.proof(key, None)}
    r = stack.call(key, access, "read_file", READ, headers=h)
    assert (r.status_code, reason_of(r)) == (401, "DPOP_ATH_MISMATCH")


def test_proof_for_another_token_is_401_ath_mismatch(stack, exp):
    key, access, _ = exp
    _, other, _ = stack.onboard_task("other-bot")
    h = {"Authorization": f"DPoP {access}", "DPoP": stack.proof(key, other)}
    r = stack.call(key, access, "read_file", READ, headers=h)
    assert (r.status_code, reason_of(r)) == (401, "DPOP_ATH_MISMATCH")


def test_replayed_proof_is_401_dpop_replay(stack, exp):
    key, access, _ = exp
    hdr = stack.headers(key, access)
    assert stack.call(key, access, "read_file", READ, headers=hdr).status_code == 200
    r = stack.call(key, access, "read_file", READ, headers=hdr)
    assert (r.status_code, reason_of(r)) == (401, "DPOP_REPLAY")


def test_token_revoked_after_task_complete_is_401(stack, exp):
    key, access, body = exp
    path = f"/tasks/{body['task_id']}/complete"
    done = stack.h.cp.post(path, headers=stack.h.auth_headers(key, access, "POST", path))
    assert done.status_code == 204
    r = stack.call(key, access, "read_file", READ)
    assert (r.status_code, reason_of(r)) == (401, "TOKEN_REVOKED")


def test_quarantined_agent_is_403(stack, exp):
    key, access, _ = exp
    stack.h.quarantine("expense-bot")
    r = stack.call(key, access, "read_file", READ)
    assert (r.status_code, reason_of(r)) == (403, "AGENT_QUARANTINED")
    assert gw_audit(stack, "AGENT_QUARANTINED")


@pytest.mark.parametrize("tool", ["rm_rf", "admin_reset", ""])
def test_unknown_tool_is_403_action_forbidden(stack, exp, tool):
    key, access, _ = exp
    r = stack.call(key, access, tool, {})
    assert (r.status_code, reason_of(r)) == (403, "ACTION_FORBIDDEN")


@pytest.mark.parametrize(
    "path",
    ["/expenses/../engineering/secrets.env", "/expenses/%2e%2e/x", "/admin/reset/../../x", "rel"],
)
def test_traversal_and_bad_paths_are_422(stack, exp, path):
    key, access, _ = exp
    r = stack.call(key, access, "read_file", {"path": path})
    assert (r.status_code, reason_of(r)) == (422, "INVALID_ARGUMENTS")


def test_missing_and_extra_args_are_422(stack, exp):
    key, access, _ = exp
    assert reason_of(stack.call(key, access, "read_file", {})) == "INVALID_ARGUMENTS"
    extra = stack.call(key, access, "read_file", {**READ, "evil": 1})
    assert (extra.status_code, reason_of(extra)) == (422, "INVALID_ARGUMENTS")


def test_out_of_scope_path_is_403_scope_denied(stack, exp):
    key, access, _ = exp
    r = stack.call(key, access, "read_file", {"path": "/engineering/docs/design.md"})
    assert (r.status_code, reason_of(r)) == (403, "SCOPE_DENIED")
    assert gw_audit(stack, "SCOPE_DENIED")


def test_high_tier_returns_202_pending_and_does_not_execute(stack, fin):
    key, access, _ = fin
    r = stack.call(key, access, "send_email", EVIL_MAIL)
    assert r.status_code == 202, r.text
    d = r.json()["decision"]
    assert d["outcome"] == "pending" and d["reason_code"] == "PENDING_APPROVAL" and d["approval_id"]
    assert outbox_lines(stack) == []
    assert gw_audit(stack, "PENDING_APPROVAL")


def test_approval_flow_end_to_end(stack, fin):
    key, access, _ = fin
    aid = stack.call(key, access, "send_email", EVIL_MAIL).json()["decision"]["approval_id"]

    pending = stack.call(key, access, "send_email", EVIL_MAIL, approval_id=aid)
    assert (pending.status_code, reason_of(pending)) == (403, "APPROVAL_STILL_PENDING")

    assert stack.decide(aid).status_code == 200
    other = {**EVIL_MAIL, "to": "y@evil.example"}  # not what the human approved
    mism = stack.call(key, access, "send_email", other, approval_id=aid)
    assert (mism.status_code, reason_of(mism)) == (403, "APPROVAL_MISMATCH")

    ok = stack.call(key, access, "send_email", EVIL_MAIL, approval_id=aid)
    assert ok.status_code == 200, ok.text
    assert [json.loads(x)["to"] for x in outbox_lines(stack)] == ["x@evil.example"]

    again = stack.call(key, access, "send_email", EVIL_MAIL, approval_id=aid)
    assert (again.status_code, reason_of(again)) == (403, "APPROVAL_ALREADY_USED")
    assert len(outbox_lines(stack)) == 1


def test_approval_cannot_be_used_by_another_agent(stack, fin):
    key, access, _ = fin
    aid = stack.call(key, access, "send_email", EVIL_MAIL).json()["decision"]["approval_id"]
    stack.decide(aid)
    k2, a2, _ = stack.onboard_task("wire-bot-2", "finance_ops", FIN_SCOPES)
    r = stack.call(k2, a2, "send_email", EVIL_MAIL, approval_id=aid)
    assert r.status_code == 403
    assert reason_of(r) in {"APPROVAL_MISMATCH", "APPROVAL_NOT_FOUND"}
    assert outbox_lines(stack) == []


def test_unknown_approval_id_is_403_not_found(stack, fin):
    key, access, _ = fin
    r = stack.call(key, access, "send_email", EVIL_MAIL, approval_id="nope")
    assert (r.status_code, reason_of(r)) == (403, "APPROVAL_NOT_FOUND")


def test_every_decision_is_audited_with_component_gateway(stack, exp):
    key, access, _ = exp
    stack.call(key, access, "read_file", READ)
    stack.call(key, access, "read_file", {"path": "/engineering/x"})
    codes = {r["reason_code"] for r in stack.h.audit() if r["component"] == "gateway"}
    assert {"OK", "SCOPE_DENIED"} <= codes


def test_unexpected_error_in_pipeline_is_denied_and_audited(stack, exp):
    """Review fix: a crash inside a check must fail closed AND leave an audit record."""
    from fastapi.testclient import TestClient

    from aimfa.gateway.app import create_app
    from aimfa.gateway.cp_client import HttpControlPlaneClient

    class BrokenIntrospect(HttpControlPlaneClient):
        def introspect(self, req):
            raise RuntimeError("boom")

    gw = TestClient(
        create_app(
            stack.settings,
            control_plane_client=BrokenIntrospect(stack.h.cp, stack.settings),
            resources_http=stack.res,
            clock=stack.clock,
        )
    )
    key, access, _ = exp
    r = gw.post(
        "/tool", json={"tool": "read_file", "args": READ}, headers=stack.headers(key, access)
    )
    assert (r.status_code, reason_of(r)) == (500, "UPSTREAM_ERROR")
    assert "boom" not in r.text
    assert any(rec["outcome"] == "deny" for rec in gw_audit(stack, "UPSTREAM_ERROR"))
