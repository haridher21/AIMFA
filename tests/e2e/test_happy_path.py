"""T5.5 E2E happy path: the REAL manifests, the REAL launcher, all in-process (no network).

Each test walks one part of the story a student would explain in the demo:
register -> launch (attestation) -> token -> tool calls -> human approval -> task complete
(token revoked) -> tamper-evident audit.
"""

from __future__ import annotations

from typing import Any

import pytest

from aimfa.agents.launcher import (
    LAUNCHER_ID,
    MANIFEST_DIR,
    Launcher,
    load_manifest,
    load_or_create_launcher_key,
)
from aimfa.agents.scripted import normal_expense, wire_bot
from aimfa.common import crypto
from aimfa.common.models import ReasonCode
from tests.integration.conftest import APPROVER, valid_code


class Recorder:
    """Wraps an AgentClient so the test can see the access token; behavior is unchanged.

    Why: the client keeps its token private, but the test needs the OLD token after the task.
    """

    def __init__(self, client) -> None:
        self.client = client
        self.access_token: str | None = None

    def start_task(self, description, scopes):
        tr = self.client.start_task(description, scopes)
        self.access_token = tr.access_token
        return tr

    def call(self, tool, /, **args):
        return self.client.call(tool, **args)

    def complete_task(self) -> None:
        self.client.complete_task()


@pytest.fixture
def keys(monkeypatch):
    """Record every keypair the launcher generates (test-only; no production key API)."""
    made: list[Any] = []
    real = crypto.generate_keypair

    def recording():
        k = real()
        made.append(k)
        return k

    monkeypatch.setattr(crypto, "generate_keypair", recording)
    return made


@pytest.fixture
def lnch(stack) -> Launcher:
    return Launcher(
        stack.settings,
        load_or_create_launcher_key(stack.settings),
        LAUNCHER_ID,
        cp_http=stack.h.cp,
        gateway_http=stack.gw,
    )


def register(stack, lnch: Launcher, name: str):
    """Admin step: trust the launcher's key (once) and record the agent's golden hash."""
    h = stack.h
    manifest = load_manifest(MANIFEST_DIR / f"{name}.yaml")
    jwk = crypto.public_jwk(lnch._key).model_dump(mode="json")
    r = h.cp.post(
        "/admin/launchers",
        json={"launcher_id": lnch.launcher_id, "public_jwk": jwk},
        headers=h.admin,
    )
    assert r.status_code in (201, 409), r.text  # 409: already registered
    body = {
        "agent_id": manifest.agent_id,
        "role": manifest.role,
        "golden_measurement": lnch.measure_agent(manifest),
        "launcher_id": lnch.launcher_id,
        "approver_id": APPROVER,
    }
    r = h.cp.post("/admin/agents", json=body, headers=h.admin)
    assert r.status_code == 201, r.text
    return manifest


def human_sleep(stack, approve: bool = True):
    """A stand-in for sleep(): the human opens the push, enters a TOTP code, and decides."""

    def _sleep(_seconds: float) -> None:
        pending = stack.h.cp.get("/admin/approvals?status=pending", headers=stack.h.admin).json()
        for rec in pending:
            code = valid_code(stack.seed, stack.clock())
            r = stack.decide(rec["approval_id"], approve=approve, code=code)
            assert r.status_code == 200, r.text

    return _sleep


def test_step1_launch_token_list_and_read_expenses(stack, lnch):
    manifest = register(stack, lnch, "normal_expense")
    client = lnch.launch(manifest)  # attestation happens here
    client.start_task("summarize expenses", normal_expense.SCOPES)

    listing = client.call("list_files", dir="/expenses")
    assert listing.decision.outcome == "allow"
    assert listing.result  # the directory listing is present

    read = client.call("read_file", path="/expenses/q3.csv")
    assert read.decision.outcome == "allow"
    assert read.result["content"].strip()


def test_step2_internal_email_is_allowed(stack, lnch):
    client = lnch.launch(register(stack, lnch, "normal_expense"))
    client.start_task("email finance", normal_expense.SCOPES)

    resp = client.call(
        "send_email", to="finance@acme.test", subject="Q3 summary", body="Total: 1.00"
    )
    assert resp.decision.outcome == "allow"
    assert resp.result  # the mock outbox accepted it


def test_normal_expense_script_runs_clean(stack, lnch):
    client = lnch.launch(register(stack, lnch, "normal_expense"))
    transcript = normal_expense.run(client)
    assert [e.tool for e in transcript] == ["list_files", "read_file", "send_email"]
    assert all(e.decision == "allow" for e in transcript)


def test_step3_wire_needs_human_approval_then_executes(stack, lnch):
    client = lnch.launch(register(stack, lnch, "wire_bot"), sleep=human_sleep(stack))

    transcript = wire_bot.run(client)

    wire = transcript[-1]
    assert wire.tool == "wire_transfer"
    assert wire.decision == "allow" and wire.result  # executed after approval
    # The 202 really happened: an approval record exists and the retry consumed it.
    approvals = stack.h.cp.get("/admin/approvals", headers=stack.h.admin).json()
    assert len(approvals) == 1
    assert approvals[0]["status"] == "used"


def test_wire_denied_by_human_never_executes(stack, lnch):
    client = lnch.launch(register(stack, lnch, "wire_bot"), sleep=human_sleep(stack, approve=False))
    wire = wire_bot.run(client)[-1]
    assert wire.tool == "wire_transfer"
    assert wire.decision == "deny" and wire.result is None


def test_step4_completed_task_token_is_revoked(stack, lnch, keys):
    client = lnch.launch(register(stack, lnch, "wire_bot"), sleep=human_sleep(stack))
    rec = Recorder(client)
    wire_bot.run(rec)  # run_task completes the task at the end -> token revoked
    old_token = rec.access_token
    agent_key = keys[-1]  # the launcher's per-instance key (generated last)
    assert old_token

    # A perfectly valid proof from the right key, with the old token: still refused.
    r = stack.call(agent_key, old_token, "list_files", {"dir": "/expenses"})
    assert r.status_code == 401, r.text
    assert r.json()["reason_code"] == ReasonCode.TOKEN_REVOKED.value


def test_step5_audit_chain_verifies_and_records_each_decision(stack, lnch, keys):
    client = lnch.launch(register(stack, lnch, "wire_bot"), sleep=human_sleep(stack))
    rec = Recorder(client)
    wire_bot.run(rec)
    stack.call(keys[-1], rec.access_token, "list_files", {"dir": "/expenses"})  # revoked

    r = stack.h.cp.get("/admin/audit/verify", headers=stack.h.admin)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["records_checked"] > 0

    records = stack.h.audit()
    decisions = {x["outcome"] for x in records}
    assert {"allow", "pending"} <= decisions
    assert any(x["reason_code"] == "TOKEN_REVOKED" for x in records)
