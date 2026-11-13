"""T4.3 human approvals: ntfy push, risk event on deny, TOTP lockout, dedupe, enroll script.

decide/consume/poll basics already live in test_approval_routes.py and are not repeated here.

ASSUMPTIONS (names the implementer must provide):
* aimfa/control_plane/notify.py:
    - `Notifier` Protocol: `send(approval: ApprovalRecord) -> None`
    - `NtfyNotifier(settings, http: httpx.Client)`: POSTs the message as the body to
      `{ntfy_server}/{ntfy_topic}` with ntfy headers `Title` and `Click`. Does nothing (no POST)
      when `settings.ntfy_enabled` is False or `ntfy_topic` is empty. NEVER raises: failures are
      logged (WARNING or higher) and swallowed.
    - `build_notification(approval, dashboard_url) -> dict` with keys "title", "message", "click".
* `aimfa.control_plane.app.create_app(settings, *, clock=None, notifier=None)`.
* Wrong-TOTP lockout: 5 wrong codes on one approval -> status "denied"; a 6th (correct) code is
  refused (any status >= 400) and consume gives 403 APPROVAL_DENIED. 4 wrong then correct works.
* Duplicate create (same action_hash while pending) returns the existing record (200 or 201, same
  approval_id) and sends no second push.
* scripts/enroll_approver.py exposes `render_qr(uri) -> str`, `save_qr_png(uri, path) -> None` and
  `enroll(http: httpx.Client, settings, approver_id) -> str` (POST /admin/approvers with
  X-Admin-Key; returns the provisioning URI).
"""

from __future__ import annotations

import importlib.util
import logging
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from aimfa.control_plane.notify import NtfyNotifier, build_notification
from fastapi.testclient import TestClient

from aimfa.common.models import ApprovalReason, ApprovalRecord, ApprovalStatus
from aimfa.control_plane.app import create_app
from tests.integration.conftest import ADMIN_KEY, Harness, invalid_code, reason_of, valid_code
from tests.integration.test_approval_routes import ARGS, Env, action_hash

SECRET_ARG = "HUNTER2-s3cr3t-9f3a"
SECRET_ARGS = {"to": "victim@evil.example", "subject": "s", "body": SECRET_ARG}
FORBIDDEN_WORDS = ("code", "totp", "reply")
REPO = Path(__file__).resolve().parents[2]


class Ntfy:
    """Mock ntfy server: records requests, answers with `status` or raises `exc`."""

    def __init__(self, status: int = 200, exc: Exception | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self.status, self.exc = status, exc

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.exc:
            raise self.exc
        return httpx.Response(self.status)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))


def make_env(settings, clock, ntfy: Ntfy, **overrides) -> Env:
    s = settings.model_copy(update={"ntfy_enabled": True, "ntfy_topic": "aimfa-test", **overrides})
    h = Harness(s, clock)
    h.cp = TestClient(create_app(s, clock=clock, notifier=NtfyNotifier(s, ntfy.client())))
    return Env(h)


def text_of(req: httpx.Request) -> str:
    return (
        req.content.decode() + " " + " ".join(f"{k}: {v}" for k, v in req.headers.items())
    ).lower()


# ------------------------------------------------------------------ ntfy push


def test_creating_an_approval_sends_exactly_one_ntfy_post(settings, clock):
    ntfy = Ntfy()
    env = make_env(settings, clock, ntfy)
    env.new_id()
    assert len(ntfy.requests) == 1
    req = ntfy.requests[0]
    assert req.method == "POST"
    assert str(req.url) == f"{settings.ntfy_server}/aimfa-test"


def test_notification_has_agent_tool_risk_and_link_but_no_args(settings, clock):
    ntfy = Ntfy()
    env = make_env(settings, clock, ntfy)
    assert env.create(SECRET_ARGS).status_code == 201
    blob = text_of(ntfy.requests[0])
    assert "expense-bot" in blob and "send_email" in blob and "risk" in blob
    assert settings.dashboard_url.lower() in blob
    assert SECRET_ARG.lower() not in blob and "evil.example" not in blob


def test_notification_never_asks_for_a_code_and_link_points_at_dashboard(settings, clock):
    ntfy = Ntfy()
    make_env(settings, clock, ntfy).new_id()
    req = ntfy.requests[0]
    text = (req.content.decode() + " " + req.headers.get("title", "")).lower()
    assert not any(w in text for w in FORBIDDEN_WORDS)
    assert req.headers["click"].startswith(settings.dashboard_url)


def _record(settings) -> ApprovalRecord:
    from tests.integration.conftest import FakeClock

    now = FakeClock().now
    return ApprovalRecord(
        agent_id="expense-bot", task_id="t1", tool="send_email", args=SECRET_ARGS,
        action_hash=action_hash("expense-bot", "t1", "send_email", SECRET_ARGS),
        reason=ApprovalReason.HIGH_TIER, risk_score=42.0, approval_id="ap-1",
        approver_id="alice-approver", status=ApprovalStatus.PENDING,
        created_at=now, expires_at=now + timedelta(minutes=5),
    )  # fmt: skip


def test_build_notification_is_pure_safe_and_localhost_linked(settings):
    n = build_notification(_record(settings), settings.dashboard_url)
    assert set(n) >= {"title", "message", "click"}
    text = (n["title"] + " " + n["message"]).lower()
    assert "expense-bot" in text and "send_email" in text
    assert SECRET_ARG.lower() not in text and "evil.example" not in text
    assert not any(w in text for w in FORBIDDEN_WORDS)
    assert n["click"].startswith(settings.dashboard_url)


@pytest.mark.parametrize("overrides", [{"ntfy_enabled": False}, {"ntfy_topic": ""}])
def test_disabled_or_topicless_ntfy_sends_nothing_but_approval_works(settings, clock, overrides):
    ntfy = Ntfy()
    env = make_env(settings, clock, ntfy, **overrides)
    assert env.create().status_code == 201
    assert ntfy.requests == []


@pytest.mark.parametrize(
    "ntfy", [Ntfy(exc=httpx.ConnectError("down")), Ntfy(status=500)], ids=["raises", "http500"]
)
def test_ntfy_failure_still_creates_the_approval_and_is_logged(settings, clock, ntfy, caplog):
    env = make_env(settings, clock, ntfy)
    with caplog.at_level(logging.WARNING):
        r = env.create()
    assert r.status_code == 201, r.text
    assert env.status(r.json()["approval_id"]).json()["status"] == "pending"
    assert any(rec.levelno >= logging.WARNING for rec in caplog.records)


# ------------------------------------------------------------------ deny -> risk + gateway 403


def test_deny_records_approval_denied_risk_and_gateway_retry_is_403(stack):
    key, access, _ = stack.onboard_task("wire-bot", "finance_ops", ["email:send:external"])
    mail = {"to": "x@evil.example", "subject": "s", "body": "b"}
    aid = stack.call(key, access, "send_email", mail).json()["decision"]["approval_id"]

    def risk() -> float:
        r = stack.h.cp.get("/admin/risk", headers=stack.h.admin).json()
        return next((s["score"] for s in r if s["agent_id"] == "wire-bot"), 0)

    before = risk()
    assert stack.decide(aid, approve=False).status_code == 200
    assert risk() == before + 25  # same clock instant: no decay in between

    r = stack.call(key, access, "send_email", mail, approval_id=aid)
    assert (r.status_code, reason_of(r)) == (403, "APPROVAL_DENIED")


# ------------------------------------------------------------------ carry-over hardening


def test_five_wrong_totp_attempts_lock_the_approval(h):
    env = Env(h)
    aid = env.new_id()
    bad = invalid_code(env.seed, h.clock())
    for _ in range(5):
        assert env.decide(aid, code=bad).status_code == 401
    assert env.status(aid).json()["status"] == "denied"
    good = env.decide(aid, code=valid_code(env.seed, h.clock()))
    assert good.status_code >= 400
    r = env.consume(aid)
    assert (r.status_code, r.json()["reason_code"]) == (403, "APPROVAL_DENIED")


def test_four_wrong_attempts_do_not_lock_the_approval(h):
    env = Env(h)
    aid = env.new_id()
    bad = invalid_code(env.seed, h.clock())
    for _ in range(4):
        env.decide(aid, code=bad)
    assert env.decide(aid).status_code == 200


def test_duplicate_pending_action_returns_existing_approval_without_second_push(settings, clock):
    ntfy = Ntfy()
    env = make_env(settings, clock, ntfy)
    first = env.create()
    second = env.create()
    assert second.status_code in (200, 201)
    assert second.json()["approval_id"] == first.json()["approval_id"]
    assert len(ntfy.requests) == 1
    env.create({**ARGS, "to": "other@evil.example"})  # a different action is a new approval
    assert len(ntfy.requests) == 2


# ------------------------------------------------------------------ enroll script


def _enroll_module():
    spec = importlib.util.spec_from_file_location(
        "enroll_approver", REPO / "scripts/enroll_approver.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


URI = "otpauth://totp/AIMFA:alice-approver?secret=JBSWY3DPEHPK3PXP&issuer=AIMFA"


def test_enroll_script_renders_and_saves_qr_offline(tmp_path):
    mod = _enroll_module()
    art = mod.render_qr(URI)
    assert isinstance(art, str) and len(art.splitlines()) > 5
    png = tmp_path / "var" / "approver.png"
    png.parent.mkdir()
    mod.save_qr_png(URI, png)
    assert png.read_bytes().startswith(b"\x89PNG")


def test_enroll_script_network_call_is_injectable(settings):
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(201, json={"approver_id": "alice-approver", "provisioning_uri": URI})

    http = httpx.Client(transport=httpx.MockTransport(handler))
    uri = _enroll_module().enroll(
        http, settings.model_copy(update={"admin_api_key": ADMIN_KEY}), "alice-approver"
    )
    assert uri == URI
    assert seen[0].method == "POST" and seen[0].url.path == "/admin/approvers"
    assert seen[0].headers["x-admin-key"] == ADMIN_KEY
