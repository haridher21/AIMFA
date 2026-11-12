"""T2.4 mock resources.

ASSUMPTIONS: `aimfa.resources.app.create_app(settings)` seeds fake data on startup under
`settings.data_dir`. Outbox is `settings.data_dir / "outbox.jsonl"` (one JSON object per line
with the email fields). Paths in responses are normalized with a leading "/". Traversal at the
resource -> 400 or 422 with ErrorResponse reason_code INVALID_ARGUMENTS. Unknown db table
-> 404. Invalid wire (negative/non-numeric amount, extra field) -> 422. Bank starting balance
is unspecified, so tests only use deltas. Reset (204) restores files, db tables and balance.
"""

from __future__ import annotations

import json

import pytest
from aimfa.resources.app import create_app
from fastapi.testclient import TestClient

from tests.integration.conftest import GATEWAY_SECRET

HDR = {"X-Gateway-Secret": GATEWAY_SECRET}
EMAIL = {"to": "bob@acme.test", "subject": "hi", "body": "hello"}
WIRE = {"to_account": "ACME-0001", "amount": 100.0, "memo": "invoice"}


@pytest.fixture
def res(settings) -> TestClient:
    return TestClient(create_app(settings))


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "/files?dir=/expenses", None),
        ("GET", "/files/expenses/q3.csv", None),
        ("PUT", "/files/engineering/docs/x.md", {"content": "x"}),
        ("POST", "/email/send", EMAIL),
        ("POST", "/bank/wire", WIRE),
        ("GET", "/db/payroll", None),
        ("DELETE", "/db/payroll", None),
        ("POST", "/admin/reset", None),
    ],
)
@pytest.mark.parametrize("headers", [{}, {"X-Gateway-Secret": "wrong"}, {"X-Gateway-Secret": ""}])
def test_every_endpoint_without_correct_gateway_secret_is_403(res, method, path, body, headers):
    r = res.request(method, path, json=body, headers=headers)
    assert r.status_code == 403
    assert r.json()["reason_code"] == "UNAUTHORIZED"


def test_denied_calls_have_no_side_effects(res, settings):
    res.post("/email/send", json=EMAIL)
    res.delete("/db/payroll")
    assert not (settings.data_dir / "outbox.jsonl").exists()
    assert res.get("/db/payroll", headers=HDR).json()["rows"]


def test_health_needs_no_secret(res):
    assert res.get("/health").json() == {"status": "ok"}


def test_list_and_read_seed_files(res):
    r = res.get("/files", params={"dir": "/expenses"}, headers=HDR)
    assert r.status_code == 200
    names = r.json()["entries"]
    assert any("q3.csv" in n for n in names) and any("q4_draft.csv" in n for n in names)
    assert any("vendor_note.txt" in n for n in names)
    body = res.get("/files/expenses/q3.csv", headers=HDR).json()
    assert body["path"] == "/expenses/q3.csv" and body["content"].strip()


def test_poisoned_note_and_fake_secrets_are_seeded(res):
    note = res.get("/files/expenses/vendor_note.txt", headers=HDR).json()["content"]
    assert "/engineering/secrets.env" in note and "attacker@evil.example" in note
    secrets_env = res.get("/files/engineering/secrets.env", headers=HDR).json()["content"]
    assert "FAKE" in secrets_env
    assert res.get("/files/engineering/docs/design.md", headers=HDR).status_code == 200


def test_missing_file_is_404(res):
    assert res.get("/files/expenses/nope.csv", headers=HDR).status_code == 404


def test_write_then_read_roundtrip(res):
    p = "/files/engineering/docs/new.md"
    r = res.put(p, json={"content": "héllo"}, headers=HDR)
    assert r.status_code == 200 and r.json()["bytes"] == len("héllo".encode())
    assert res.get(p, headers=HDR).json()["content"] == "héllo"


@pytest.mark.parametrize(
    "path",
    [
        "/files/expenses/%2e%2e/engineering/secrets.env",
        "/files/expenses/..%2fengineering%2fsecrets.env",
        "/files/expenses%5c..%5cengineering%5csecrets.env",
        "/files//etc/passwd",
        "/files/expenses/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    ],
)
def test_path_traversal_is_rejected_at_the_resource(res, path):
    r = res.get(path, headers=HDR)
    assert r.status_code in (400, 422), r.text
    assert r.json()["reason_code"] == "INVALID_ARGUMENTS"
    assert "FAKE" not in r.text


def test_traversal_in_list_dir_and_write_is_rejected_without_writing(res, settings):
    r = res.get("/files", params={"dir": "/expenses/../engineering"}, headers=HDR)
    assert r.status_code in (400, 422) and r.json()["reason_code"] == "INVALID_ARGUMENTS"
    r = res.put("/files/expenses/%2e%2e/evil.txt", json={"content": "x"}, headers=HDR)
    assert r.status_code in (400, 422)
    assert res.get("/files/evil.txt", headers=HDR).status_code in (400, 404)
    assert not list(settings.data_dir.rglob("evil.txt"))


def test_email_is_appended_to_outbox(res, settings):
    r1 = res.post("/email/send", json=EMAIL, headers=HDR)
    r2 = res.post("/email/send", json={**EMAIL, "to": "evil@evil.example"}, headers=HDR)
    assert r1.status_code == r2.status_code == 200
    assert r1.json()["message_id"] != r2.json()["message_id"]
    lines = (settings.data_dir / "outbox.jsonl").read_text(encoding="utf-8").splitlines()
    rows = [json.loads(line) for line in lines]
    assert [r["to"] for r in rows] == ["bob@acme.test", "evil@evil.example"]
    assert rows[0]["subject"] == "hi"


def test_wire_changes_the_balance(res):
    first = res.post("/bank/wire", json=WIRE, headers=HDR)
    assert first.status_code == 200
    second = res.post("/bank/wire", json=WIRE, headers=HDR)
    assert second.json()["balance"] == first.json()["balance"] - 100.0
    assert second.json()["transfer_id"] != first.json()["transfer_id"]


@pytest.mark.parametrize("over", [{"amount": -5}, {"amount": "lots"}, {"admin": True}])
def test_invalid_wire_is_422_and_balance_untouched(res, over):
    before = res.post("/bank/wire", json={**WIRE, "amount": 1.0}, headers=HDR).json()["balance"]
    assert res.post("/bank/wire", json={**WIRE, **over}, headers=HDR).status_code == 422
    after = res.post("/bank/wire", json={**WIRE, "amount": 1.0}, headers=HDR).json()["balance"]
    assert after == before - 1.0


def test_db_tables_seeded_delete_and_unknown_table(res):
    for table in ("vendors", "payroll"):
        body = res.get(f"/db/{table}", headers=HDR).json()
        assert body["table"] == table and body["rows"]
    assert res.delete("/db/payroll", headers=HDR).json() == {"table": "payroll", "deleted": True}
    assert res.get("/db/payroll", headers=HDR).json()["rows"] == []
    assert res.get("/db/users; DROP TABLE vendors", headers=HDR).status_code in (400, 404, 422)
    assert res.get("/db/vendors", headers=HDR).json()["rows"]
    assert res.get("/db/sqlite_master", headers=HDR).status_code in (400, 404, 422)


def test_reset_restores_the_seed(res):
    vendors = res.get("/db/vendors", headers=HDR).json()["rows"]
    payroll = res.get("/db/payroll", headers=HDR).json()["rows"]
    original = res.get("/files/expenses/q3.csv", headers=HDR).json()["content"]
    baseline_balance = res.post("/bank/wire", json=WIRE, headers=HDR).json()["balance"] + 100.0

    res.put("/files/expenses/q3.csv", json={"content": "tampered"}, headers=HDR)
    res.put("/files/engineering/docs/new.md", json={"content": "x"}, headers=HDR)
    res.delete("/db/payroll", headers=HDR)
    res.delete("/db/vendors", headers=HDR)
    res.post("/bank/wire", json=WIRE, headers=HDR)

    assert res.post("/admin/reset", headers=HDR).status_code == 204

    assert res.get("/db/vendors", headers=HDR).json()["rows"] == vendors
    assert res.get("/db/payroll", headers=HDR).json()["rows"] == payroll
    assert res.get("/files/expenses/q3.csv", headers=HDR).json()["content"] == original
    assert res.get("/files/engineering/docs/new.md", headers=HDR).status_code == 404
    after = res.post("/bank/wire", json=WIRE, headers=HDR).json()["balance"]
    assert after == baseline_balance - 100.0
