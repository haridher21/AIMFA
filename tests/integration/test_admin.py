"""T2.1 registry + admin API. See conftest.py for factory/clock assumptions.

Extra assumptions: duplicate registration -> 409; revoke/clear-quarantine of an unknown agent
-> 404; every non-2xx body is an ErrorResponse (has `reason_code`).
"""

from __future__ import annotations

import pytest

from aimfa.common.crypto import generate_keypair, public_jwk
from aimfa.common.models import AgentRecord, ApproverEnrollment
from tests.integration.conftest import ADMIN_KEY, GOLDEN


def agent_body(**over):
    body = {
        "agent_id": "expense-bot",
        "role": "expense_reader",
        "golden_measurement": GOLDEN,
        "launcher_id": "launcher-1",
        "approver_id": "alice-approver",
    }
    body.update(over)
    return body


def test_health_needs_no_auth(h):
    r = h.cp.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-Admin-Key": "wrong"},
        {"X-Admin-Key": ADMIN_KEY[:-1]},
    ],
)
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/admin/agents"),
        ("POST", "/admin/launchers"),
        ("POST", "/admin/approvers"),
        ("POST", "/admin/agents/expense-bot/revoke"),
        ("POST", "/admin/agents/expense-bot/clear-quarantine"),
        ("GET", "/admin/tokens"),
    ],
)
def test_missing_or_wrong_admin_key_is_401_unauthorized(h, method, path, headers):
    r = h.cp.request(method, path, headers=headers, json={} if method == "POST" else None)
    assert r.status_code == 401
    assert r.json()["reason_code"] == "UNAUTHORIZED"


def test_register_launcher_and_agent_roundtrip(h):
    h.add_launcher()
    h.cp.post("/admin/approvers", json={"approver_id": "alice-approver"}, headers=h.admin)
    r = h.cp.post("/admin/agents", json=agent_body(), headers=h.admin)
    assert r.status_code == 201
    rec = AgentRecord.model_validate(r.json())
    assert rec.status == "registered" and rec.role == "expense_reader"
    listed = h.cp.get("/admin/agents", headers=h.admin).json()
    assert [a["agent_id"] for a in listed] == ["expense-bot"]


@pytest.mark.parametrize("role", ["root", "", "EXPENSE_READER"])
def test_registering_agent_with_unknown_role_is_422(h, role):
    h.add_launcher()
    r = h.cp.post("/admin/agents", json=agent_body(role=role), headers=h.admin)
    assert r.status_code == 422
    assert not h.cp.get("/admin/agents", headers=h.admin).json()


@pytest.mark.parametrize(
    "over", [{"agent_id": "Bad Id!"}, {"golden_measurement": "abc"}, {"is_admin": True}]
)
def test_invalid_or_unknown_agent_fields_are_422(h, over):
    h.add_launcher()
    r = h.cp.post("/admin/agents", json=agent_body(**over), headers=h.admin)
    assert r.status_code == 422


def test_duplicate_agent_registration_is_409(h):
    h.add_agent()
    r = h.cp.post("/admin/agents", json=agent_body(), headers=h.admin)
    assert r.status_code == 409


def test_launcher_registration_rejects_private_or_extra_fields(h):
    jwk = public_jwk(generate_keypair()).model_dump(mode="json")
    jwk["d"] = "AAAA"
    r = h.cp.post(
        "/admin/launchers",
        json={"launcher_id": "launcher-9", "public_jwk": jwk},
        headers=h.admin,
    )
    assert r.status_code == 422


def test_approver_enrollment_returns_otpauth_uri_exactly_once(h):
    r = h.cp.post("/admin/approvers", json={"approver_id": "bob-approver"}, headers=h.admin)
    assert r.status_code == 201
    uri = ApproverEnrollment.model_validate(r.json()).provisioning_uri
    assert uri.startswith("otpauth://totp/")
    seed = [p.split("=", 1)[1] for p in uri.split("?", 1)[1].split("&") if p.startswith("secret=")]
    assert seed and len(seed[0]) >= 16

    h.add_agent()  # also exercises other endpoints that must not leak the seed
    seen = [
        h.cp.post("/admin/approvers", json={"approver_id": "bob-approver"}, headers=h.admin),
        h.cp.get("/admin/agents", headers=h.admin),
        h.cp.get("/admin/tokens", headers=h.admin),
        h.cp.get("/admin/approvals?status=pending", headers=h.admin),
        h.cp.get("/admin/audit?limit=1000", headers=h.admin),
    ]
    for resp in seen:
        assert seed[0] not in resp.text
    assert seen[0].status_code == 409  # re-enrolling must not reveal or rotate the seed


def test_clear_quarantine_resets_status_to_registered(h):
    h.add_agent()
    h.quarantine("expense-bot")
    assert h.cp.get("/admin/agents", headers=h.admin).json()[0]["status"] == "quarantined"
    r = h.cp.post("/admin/agents/expense-bot/clear-quarantine", headers=h.admin)
    assert r.status_code == 200 and r.json()["status"] == "registered"


def test_revoke_kills_all_tokens_of_agent(h):
    key, ident = h.onboard()
    tok = h.request_token(key, ident, ["files:read:/expenses/*"]).json()
    r = h.cp.post("/admin/agents/expense-bot/revoke", headers=h.admin)
    assert r.status_code == 204
    views = h.cp.get("/admin/tokens", headers=h.admin).json()
    assert views and all(v["revoked"] for v in views)
    assert tok["access_token"] not in h.cp.get("/admin/tokens", headers=h.admin).text


@pytest.mark.parametrize(
    "path", ["/admin/agents/ghost-bot/revoke", "/admin/agents/ghost-bot/clear-quarantine"]
)
def test_admin_actions_on_unknown_agent_are_404(h, path):
    assert h.cp.post(path, headers=h.admin).status_code == 404


def test_audit_chain_verifies_after_admin_activity(h):
    h.add_agent()
    r = h.cp.get("/admin/audit/verify", headers=h.admin)
    assert r.status_code == 200 and r.json()["ok"] is True
