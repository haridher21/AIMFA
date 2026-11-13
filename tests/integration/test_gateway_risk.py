"""T4.2: the gateway reports every call to the real control-plane monitor.

ASSUMPTIONS:
* `aimfa.gateway.pipeline.ControlPlaneMonitor(cp_client)` has `report(event) -> RiskScore` (it calls
  POST /internal/events through the control-plane client). It is the default when
  `create_app(..., monitor=None)`, so the plain `stack` fixture uses the real monitor.
* Step 7 sends details={"category": <str|None>, "sensitive": <bool>} from the resolved action.
* Verified-agent denials are reported best effort: SCOPE_DENIED -> scope_denied (+30),
  ACTION_FORBIDDEN -> action_forbidden (+30), DPOP_* -> dpop_failure (+15),
  TOKEN_REVOKED -> token_failure (+15). A failing monitor never changes the denial returned.
* Scores are read via GET /admin/risk (an agent not listed yet counts as 0).
* "Broad test token": built by running with a policy copy whose roles.yaml is widened, so the STS
  issues it legitimately (no forged JWTs).
"""

from __future__ import annotations

import shutil

import pytest

from aimfa.common.crypto import generate_keypair
from aimfa.common.models import AgentStatus, EventType, RiskEvent, RiskScore
from aimfa.gateway.cp_client import HttpControlPlaneClient
from aimfa.gateway.pipeline import ControlPlaneMonitor, StubMonitor  # noqa: F401
from tests.integration.conftest import Harness, Stack, reason_of

READ = {"path": "/expenses/q3.csv"}
SCOPES = ["files:read:/expenses/*", "email:send:internal"]
INTERNAL_MAIL = {"to": "bob@acme.test", "subject": "s", "body": "b"}
EXTERNAL_MAIL = {"to": "x@evil.example", "subject": "s", "body": "b"}


def score(h, agent) -> float:
    r = h.cp.get("/admin/risk", headers=h.admin)
    assert r.status_code == 200, r.text
    return next((s["score"] for s in r.json() if s["agent_id"] == agent), 0)


def push(h, event_type, agent="expense-bot") -> None:
    body = {
        "agent_id": agent, "task_id": "x", "event_type": event_type,
        "timestamp": h.clock().isoformat(), "details": {},
    }  # fmt: skip
    assert h.cp.post("/internal/events", json=body, headers=h.internal).status_code == 200


def widened_stack(settings, clock, tmp_path, edits: dict[str, str]) -> Stack:
    policy = tmp_path / "policy"
    shutil.copytree(settings.policy_dir, policy)
    roles = policy / "roles.yaml"
    text = roles.read_text(encoding="utf-8")
    for old, new in edits.items():
        assert old in text, old
        text = text.replace(old, new)
    roles.write_text(text, encoding="utf-8")
    s2 = settings.model_copy(update={"policy_dir": policy})
    return Stack(Harness(s2, clock), s2, clock)


# ------------------------------------------------------------------ elevated score / step-up


def test_control_plane_monitor_returns_the_cp_risk_score(stack):
    stack.onboard_task()
    monitor = ControlPlaneMonitor(HttpControlPlaneClient(stack.h.cp, stack.settings))
    event = RiskEvent(
        agent_id="expense-bot", task_id="t1", event_type=EventType.SCOPE_DENIED,
        timestamp=stack.clock(),
    )  # fmt: skip
    result = monitor.report(event)
    assert isinstance(result, RiskScore) and result.score == 30


def test_internal_email_is_allowed_at_zero_risk(stack):
    key, access, _ = stack.onboard_task(scopes=SCOPES)
    r = stack.call(key, access, "send_email", INTERNAL_MAIL)
    assert r.status_code == 200, r.text


def test_elevated_score_turns_internal_email_into_202(stack):
    key, access, _ = stack.onboard_task(scopes=SCOPES)
    push(stack.h, "out_of_profile")  # 50 >= step-up threshold, below revoke
    r = stack.call(key, access, "send_email", INTERNAL_MAIL)
    assert r.status_code == 202, r.text
    assert r.json()["decision"]["reason_code"] == "PENDING_APPROVAL"


# ------------------------------------------------------------------ quarantine mid-task


def test_quarantine_mid_task_blocks_the_next_call(stack):
    key, access, _ = stack.onboard_task()
    assert stack.call(key, access, "read_file", READ).status_code == 200
    push(stack.h, "out_of_profile")
    push(stack.h, "scope_denied")  # 80
    r = stack.call(key, access, "read_file", READ)
    assert (r.status_code, reason_of(r)) == (403, "AGENT_QUARANTINED")


def test_repeated_scope_denials_by_the_gateway_quarantine_the_agent(stack):
    key, access, _ = stack.onboard_task()
    bad = {"path": "/engineering/docs/design.md"}
    first = stack.call(key, access, "read_file", bad)
    assert (first.status_code, reason_of(first)) == (403, "SCOPE_DENIED")
    stack.call(key, access, "read_file", bad)
    stack.call(key, access, "read_file", bad)  # 3 x 30 = 90 >= 80
    r = stack.call(key, access, "read_file", READ)
    assert (r.status_code, reason_of(r)) == (403, "AGENT_QUARANTINED")
    assert stack.h.cp.get("/admin/agents", headers=stack.h.admin).json()[0]["status"] == (
        AgentStatus.QUARANTINED.value
    )


# ------------------------------------------------------------------ denials are reported


def _scope_denied(stack, key, access):
    return stack.call(key, access, "read_file", {"path": "/engineering/docs/design.md"})


def _forbidden(stack, key, access):
    return stack.call(key, access, "rm_rf", {})


def _bad_dpop_key(stack, key, access):
    return stack.call(generate_keypair(), access, "read_file", READ)


def _revoked(stack, key, access):
    tid = stack.h.cp.get("/admin/tokens", headers=stack.h.admin).json()[0]["task_id"]
    path = f"/tasks/{tid}/complete"
    stack.h.cp.post(path, headers=stack.h.auth_headers(key, access, "POST", path))
    return stack.call(key, access, "read_file", READ)


@pytest.mark.parametrize(
    ("trigger", "code", "points"),
    [
        (_scope_denied, "SCOPE_DENIED", 30),
        (_forbidden, "ACTION_FORBIDDEN", 30),
        (_bad_dpop_key, "DPOP_KEY_MISMATCH", 15),
        (_revoked, "TOKEN_REVOKED", 15),
    ],
)
def test_verified_agent_denials_add_risk_points(stack, trigger, code, points):
    key, access, _ = stack.onboard_task()
    r = trigger(stack, key, access)
    assert reason_of(r) == code
    assert score(stack.h, "expense-bot") == points


def test_failing_monitor_does_not_change_a_denial(stack):
    from fastapi.testclient import TestClient

    from aimfa.gateway.app import create_app

    class Boom:
        def report(self, event):
            raise RuntimeError("monitor down")

    gw = TestClient(
        create_app(
            stack.settings,
            control_plane_client=HttpControlPlaneClient(stack.h.cp, stack.settings),
            resources_http=stack.res,
            monitor=Boom(),
            clock=stack.clock,
        )
    )
    key, access, _ = stack.onboard_task()
    r = gw.post(
        "/tool",
        json={"tool": "read_file", "args": {"path": "/engineering/x"}},
        headers=stack.headers(key, access),
    )
    assert (r.status_code, reason_of(r)) == (403, "SCOPE_DENIED")


# ------------------------------------------------------------------ out-of-profile / exfil


def test_expense_agent_reading_engineering_gets_out_of_profile_points(settings, clock, tmp_path):
    st = widened_stack(
        settings, clock, tmp_path,
        {'"files:read:/expenses/*"': '"files:read:/expenses/*"\n      - "files:read:/engineering/*"'},  # noqa: E501
    )  # fmt: skip
    key, access, _ = st.onboard_task(scopes=["files:read:/engineering/*"])
    r = st.call(key, access, "read_file", {"path": "/engineering/docs/design.md"})
    assert r.status_code in (200, 404), r.text  # allowed by scope, so the call is not denied
    assert score(st.h, "expense-bot") == 50  # but it is not normal for this role


def test_sensitive_read_then_external_email_in_same_task_adds_exfil_points(
    settings, clock, tmp_path
):
    st = widened_stack(
        settings, clock, tmp_path,
        {
            '"files:write:/engineering/docs/*"': '"files:write:/engineering/docs/*"\n      - "email:send:external"',  # noqa: E501
            "profile: [engineering, email_internal]": "profile: [engineering, email_internal, email_external]",  # noqa: E501
        },
    )  # fmt: skip
    key, access, _ = st.onboard_task(
        "eng-bot", "eng_assistant", ["files:read:/engineering/*", "email:send:external"]
    )
    r = st.call(key, access, "read_file", {"path": "/engineering/secrets.env"})
    assert r.status_code in (200, 404), r.text
    assert score(st.h, "eng-bot") == 0  # reading alone is not suspicious
    mail = st.call(key, access, "send_email", EXTERNAL_MAIL)
    assert mail.status_code == 202, mail.text  # high tier: still parked for a human
    assert score(st.h, "eng-bot") == 60  # exfil sequence
