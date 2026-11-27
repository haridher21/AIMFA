"""Dashboard web app: pages render, nothing secret leaks, and the browser-safety basics hold
(CSRF token, Host allow-list, security headers, escaping). No network: the admin API is faked.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from aimfa.common.config import Settings
from aimfa.common.models import (
    ActiveTokenView,
    AgentRecord,
    AgentStatus,
    ApprovalRecord,
    AuditRecord,
    AuditVerifyResult,
    DecisionOutcome,
    ReasonCode,
    RiskContribution,
    RiskScore,
)
from aimfa.dashboard.app import create_app
from attacks.common import AttackResult

KEY = "dashboard-test-admin-key-never-render"
BASE = "http://127.0.0.1:8501"
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
FULL_JTI = "jti-abcdefghijklmnopqrstuvwxyz"
PAGES = ["/", "/agents", "/tokens", "/risk", "/approvals", "/audit", "/attack-lab"]


def _settings(**over) -> Settings:
    return Settings(
        _env_file=None,
        admin_api_key=KEY,
        internal_service_secret="internal-secret-0123456789",
        gateway_resource_secret="gateway-secret-0123456789",
        baseline_api_key="baseline-secret-0123456789",
        dashboard_url=BASE,
        **over,
    )


class FakeClient:
    """Same read/action methods as AdminClient, with canned data and a call log."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def agents(self):
        return [
            AgentRecord.model_construct(
                agent_id="expense-bot", role="expense", status=AgentStatus.QUARANTINED,
                approver_id="alice", created_at=NOW,
            )
        ]  # fmt: skip

    def tokens(self):
        return [
            ActiveTokenView(
                jti=FULL_JTI, agent_id="expense-bot", task_id="t1", scopes=["files:read:/x/*"],
                issued_at=NOW, expires_at=datetime.now(UTC) + timedelta(minutes=5), revoked=False,
            )
        ]  # fmt: skip

    def risk(self):
        hit = RiskContribution(rule="exfil_sequence", points=40, at=NOW)
        return [
            RiskScore(agent_id="expense-bot", score=65, status=AgentStatus.ACTIVE,
                      step_up_required=True, recent=[hit])
        ]  # fmt: skip

    def approvals(self, status=None):
        return [
            ApprovalRecord.model_construct(
                approval_id="ap-1", approver_id="alice", agent_id="wire-bot", tool="bank:wire",
                args={"memo": "<script>alert(1)</script>", "amount": 5},
                reason=ReasonCode.PENDING_APPROVAL, risk_score=12.0, status="pending",
                created_at=NOW, expires_at=datetime.now(UTC) + timedelta(seconds=90),
            )
        ]  # fmt: skip

    def audit(self, after_seq=-1, limit=100):
        recs = [
            AuditRecord.model_construct(
                seq=i, timestamp=NOW, component="gateway", actor="expense-bot", event="tool_call",
                outcome=o, reason_code=ReasonCode.OK, prev_hash="0" * 64, hash=f"{i:064d}",
            )
            for i, o in enumerate(DecisionOutcome)
        ]  # fmt: skip
        return [r for r in recs if r.seq > after_seq]

    def verify_audit(self):
        return AuditVerifyResult(ok=True, records_checked=3)

    def clear_quarantine(self, agent_id):
        self.calls.append(("clear", agent_id))

    def revoke_agent(self, agent_id):
        self.calls.append(("revoke", agent_id))

    def decide(self, approval_id, approver_id, approve, code):
        self.calls.append(("decide", approval_id, approver_id, approve, code))


def a1_blocked(mode):
    return AttackResult("A1 tampered", False, "attestation", ReasonCode.OK, f"ev {KEY}", mode)


def a2_broken(mode):
    raise RuntimeError("boom")


@pytest.fixture
def fake():
    return FakeClient()


@pytest.fixture
def web(fake):
    app = create_app(_settings(), client=fake, load_attacks=lambda: [a1_blocked, a2_broken])
    return TestClient(app, base_url=BASE)


def _token(web) -> str:
    return re.search(r'name="csrf-token" content="([^"]+)"', web.get("/").text).group(1)


def _post(web, path, json=None, **headers):
    return web.post(path, json=json or {}, headers={"X-CSRF-Token": _token(web), **headers})


# ------------------------------------------------------------------------ rendering
@pytest.mark.parametrize("path", PAGES)
def test_pages_render_with_headers_and_no_secret(web, path):
    resp = web.get(path)
    assert resp.status_code == 200
    assert KEY not in resp.text
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-frame-options"] == "DENY"


@pytest.mark.parametrize(
    "name", ["home", "agents", "tokens", "risk", "approvals", "audit", "attack_results"]
)
def test_partials_render(web, name):
    assert web.get(f"/partials/{name}").status_code == 200


def test_unknown_partial_is_404(web):
    assert web.get("/partials/../app").status_code == 404
    assert web.get("/partials/nope").status_code == 404


@pytest.mark.parametrize("path", PAGES)
def test_pages_warn_when_control_plane_down(path):
    app = create_app(_settings(control_plane_url="http://127.0.0.1:9"), warm_up=False)
    resp = TestClient(app, base_url=BASE).get(path)
    assert resp.status_code == 200
    if path != "/attack-lab":
        assert "not reachable" in resp.text
    assert KEY not in resp.text


def test_token_table_shows_only_truncated_jti(web):
    text = web.get("/tokens").text
    assert FULL_JTI[:8] in text and FULL_JTI not in text


def test_agent_supplied_text_is_escaped(web):
    text = web.get("/approvals").text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


def test_attack_lab_states_isolation_and_lists_attacks(web):
    text = web.get("/attack-lab").text
    assert "OWN throwaway" in text
    assert text.count('data-action="/api/attacks/run"') == 2 + 1  # one per attack + Run all


# ------------------------------------------------------------------------ CSRF + host
def test_post_without_csrf_token_is_refused(web, fake):
    resp = web.post("/api/agents/expense-bot/revoke")
    assert resp.status_code == 403
    assert resp.json()["reason_code"] == ReasonCode.UNAUTHORIZED
    assert fake.calls == []


@pytest.mark.parametrize(
    "headers",
    [
        {"X-CSRF-Token": "wrong"},
        {"Origin": "http://evil.example"},
        {"Sec-Fetch-Site": "cross-site"},
    ],
)
def test_forged_requests_are_refused(web, fake, headers):
    token = {"X-CSRF-Token": _token(web)}
    resp = web.post("/api/agents/expense-bot/revoke", headers={**token, **headers})
    assert resp.status_code == 403
    assert fake.calls == []


def test_same_origin_post_with_token_runs(web, fake):
    resp = _post(
        web, "/api/agents/expense-bot/revoke", Origin=BASE, **{"Sec-Fetch-Site": "same-origin"}
    )
    assert resp.status_code == 200 and resp.json()["ok"] is True
    assert fake.calls == [("revoke", "expense-bot")]


def test_unknown_host_is_refused(web):
    assert web.get("/", headers={"Host": "evil.example"}).status_code == 400


# ------------------------------------------------------------------------ actions
def test_decide_takes_approver_from_server_not_browser(web, fake):
    resp = _post(web, "/api/approvals/ap-1/decide", {"approve": True, "code": "123456"})
    assert resp.json()["ok"] is True
    assert fake.calls == [("decide", "ap-1", "alice", True, "123456")]


def test_decide_rejects_extra_fields_and_unknown_approvals(web, fake):
    bad = _post(web, "/api/approvals/ap-1/decide", {"approve": True, "approver_id": "mallory"})
    assert bad.status_code == 422
    gone = _post(web, "/api/approvals/ap-9/decide", {"approve": True, "code": "123456"})
    assert gone.json()["ok"] is False
    assert fake.calls == []


def test_attack_run_records_results_and_failures_are_not_blocked(web):
    ok = _post(web, "/api/attacks/run", {"mode": "aimfa", "index": 0})
    assert ok.json()["ok"] is True
    broken = _post(web, "/api/attacks/run", {"mode": "aimfa", "index": 1})
    assert broken.json()["ok"] is False and "could not run" in broken.json()["message"]
    text = web.get("/partials/attack_results").text
    assert text.count("badge-green") == 1  # only the real result; the crash is not "blocked"
    assert KEY not in text  # evidence is redacted


@pytest.mark.parametrize("body", [{"mode": "evil", "index": 0}, {"mode": "aimfa", "index": 7}])
def test_attack_run_rejects_bad_input(web, body):
    assert _post(web, "/api/attacks/run", body).status_code == 422
