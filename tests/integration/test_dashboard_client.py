"""T7.1 integration tests: AdminClient against the real control plane app (in-process)."""

from __future__ import annotations

import httpx
import pytest

from aimfa.common.config import Settings
from aimfa.common.crypto import action_hash
from aimfa.dashboard.admin_client import (
    AdminApiError,
    AdminClient,
    ControlPlaneUnavailable,
    InvalidTotpCode,
)
from tests.integration.conftest import ADMIN_KEY, APPROVER, enroll_approver, valid_code


@pytest.fixture
def client(h, settings) -> AdminClient:
    return AdminClient(settings, http=h.cp)


def _make_approval(h) -> tuple[str, str]:
    """Enroll the approver (we keep the seed), onboard an agent and create a pending approval."""
    seed = enroll_approver(h, APPROVER)
    key, ident = h.onboard()
    task = h.request_token(key, ident, ["files:read:/expenses/*"]).json()["task_id"]
    args = {"to": "a@b.c"}
    body = {
        "agent_id": "expense-bot",
        "task_id": task,
        "tool": "send_email",
        "args": args,
        "action_hash": action_hash("expense-bot", task, "send_email", args),
        "reason": "high_tier",
    }
    r = h.cp.post("/internal/approvals", json=body, headers=h.internal)
    assert r.status_code == 201, r.text
    return r.json()["approval_id"], seed


def test_reads_return_typed_models(h, client):
    key, ident = h.onboard()
    h.request_token(key, ident, ["files:read:/expenses/*"])
    (agent,) = client.agents()
    (tok,) = client.tokens()
    assert agent.agent_id == tok.agent_id == "expense-bot"
    assert "access_token" not in tok.model_dump()
    assert client.risk() == [] or client.risk()[0].agent_id == "expense-bot"
    assert client.audit(after_seq=-1, limit=5)  # onboarding produced audit records
    assert client.verify_audit().ok


def test_audit_after_seq_is_incremental(h, client):
    h.onboard()
    first = client.audit(limit=2)
    rest = client.audit(after_seq=first[-1].seq, limit=1000)
    assert all(r.seq > first[-1].seq for r in rest)


def test_revoke_and_clear_quarantine(h, client):
    key, ident = h.onboard()
    h.request_token(key, ident, ["files:read:/expenses/*"])
    client.revoke_agent("expense-bot")
    assert client.tokens()[0].revoked
    h.quarantine("expense-bot")
    assert client.agents()[0].status.value == "quarantined"
    assert client.clear_quarantine("expense-bot").status.value == "registered"


def test_bad_totp_is_rejected_and_approval_stays_pending(h, client):
    approval_id, _ = _make_approval(h)
    (rec,) = client.approvals("pending")
    assert rec.approval_id == approval_id and rec.approver_id == APPROVER
    with pytest.raises(AdminApiError) as err:
        client.decide(approval_id, APPROVER, True, "000000")
    assert err.value.status == 401
    assert err.value.reason_code.value == "APPROVAL_INVALID_TOTP"
    assert client.approvals("pending")


def test_approve_and_deny_with_real_code(h, client, clock):
    approval_id, seed = _make_approval(h)
    done = client.decide(approval_id, APPROVER, True, valid_code(seed, clock()))
    assert done.status.value == "approved"
    assert client.approvals("pending") == []
    with pytest.raises(AdminApiError) as err:  # already decided
        client.decide(approval_id, APPROVER, False, valid_code(seed, clock()))
    assert err.value.status == 409


def test_no_request_is_sent_for_a_bad_totp(settings):
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(500)

    c = AdminClient(
        settings, http=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x")
    )
    for code in ("", "12345", "abcdef"):
        with pytest.raises(InvalidTotpCode):
            c.decide("ap1", APPROVER, True, code)
    assert sent == []


def test_wrong_admin_key_is_rejected_and_never_leaked(h, settings):
    bad = Settings(_env_file=None, admin_api_key="wrong-key-should-not-leak")
    c = AdminClient(bad, http=h.cp)
    with pytest.raises(AdminApiError) as err:
        c.agents()
    assert err.value.status == 401 and err.value.reason_code.value == "UNAUTHORIZED"
    for text in (str(err.value), repr(err.value), repr(c), str(c)):
        assert "wrong-key-should-not-leak" not in text
        assert ADMIN_KEY not in text


def test_good_client_repr_hides_key(client):
    assert ADMIN_KEY not in repr(client) and ADMIN_KEY not in str(client)


def test_control_plane_down_raises_friendly_error_without_key(settings):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    c = AdminClient(
        settings, http=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x")
    )
    with pytest.raises(ControlPlaneUnavailable) as err:
        c.agents()
    assert ADMIN_KEY not in str(err.value)


def test_non_json_error_body_becomes_upstream_error(settings):
    c = AdminClient(
        settings,
        http=httpx.Client(
            transport=httpx.MockTransport(lambda r: httpx.Response(500, text="<html>oops")),
            base_url="http://x",
        ),
    )
    with pytest.raises(AdminApiError) as err:
        c.tokens()
    assert err.value.status == 500 and err.value.reason_code.value == "UPSTREAM_ERROR"


def test_ids_are_url_encoded_so_they_cannot_change_the_path(settings):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.raw_path.decode())
        return httpx.Response(204)

    c = AdminClient(
        settings, http=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x")
    )
    c.revoke_agent("../../admin/reset")
    assert seen == ["/admin/agents/..%2F..%2Fadmin%2Freset/revoke"]
    for bad in ("..", "."):  # dot segments would be resolved by httpx: refuse them
        with pytest.raises(ValueError):
            c.revoke_agent(bad)
    assert len(seen) == 1


def test_admin_key_header_is_sent(settings):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("X-Admin-Key", ""))
        return httpx.Response(200, json=[])

    c = AdminClient(
        settings, http=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x")
    )
    c.agents()
    assert seen == [ADMIN_KEY]


@pytest.mark.parametrize("url", ["http://evil.example:8000", "http://10.0.0.5:8000"])
def test_non_local_control_plane_url_is_refused(settings, url):
    """The admin key must never be sent off this laptop, even with a tampered .env."""
    with pytest.raises(ValueError):
        AdminClient(settings.model_copy(update={"control_plane_url": url}))


def test_default_http_client_ignores_proxy_env_and_redirects(settings, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:8080")
    c = AdminClient(settings.model_copy(update={"control_plane_url": "http://127.0.0.1:8000"}))
    assert c._http._trust_env is False and c._http.follow_redirects is False
