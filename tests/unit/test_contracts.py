"""Sanity checks for the frozen contracts (aimfa/common/models.py) and policy files.

These guard the foundation every other task builds on: if a contract or policy edit
breaks one of these, the edit is wrong (or needs a deliberate contract-change PR).
"""

from datetime import UTC, datetime

import pytest
import yaml
from pydantic import ValidationError

from aimfa.common import models as m
from aimfa.common.config import POLICY_DIR, Settings

SHA = "a" * 64
JWK = {"kty": "OKP", "crv": "Ed25519", "x": "A" * 43}


# ---------------------------------------------------------------- models


def test_reason_codes_are_unique():
    values = [c.value for c in m.ReasonCode]
    assert len(values) == len(set(values))


def test_extra_fields_are_rejected():
    with pytest.raises(ValidationError):
        m.ToolCall(tool="read_file", args={}, task_id="smuggled")  # task_id comes from token


def test_agent_id_pattern():
    m.AttestationChallengeRequest(agent_id="expense-bot")
    for bad in ["Expense-Bot", "-bot", "a", "bot!", "x" * 80]:
        with pytest.raises(ValidationError):
            m.AttestationChallengeRequest(agent_id=bad)


def test_totp_code_must_be_six_digits():
    m.ApprovalDecisionRequest(approver_id="alice", approve=True, totp_code="123456")
    for bad in ["12345", "1234567", "abcdef"]:
        with pytest.raises(ValidationError):
            m.ApprovalDecisionRequest(approver_id="alice", approve=True, totp_code=bad)


def test_token_claims_fix_audience_and_token_use():
    now = 1_700_000_000
    access = m.AccessTokenClaims(
        sub="expense-bot",
        iat=now,
        exp=now + 900,
        jti="j1",
        task_id="t1",
        role="expense_reader",
        scopes=["files:read:/expenses/*"],
        cnf={"jkt": "abc"},
    )
    assert access.aud == m.GATEWAY_AUDIENCE and access.token_use == m.ACCESS_TOKEN_USE
    identity = m.IdentityCredentialClaims(
        sub="expense-bot",
        iat=now,
        exp=now + 3600,
        jti="j2",
        role="expense_reader",
        measurement=SHA,
        cnf={"jwk": JWK},
    )
    assert identity.aud == m.STS_AUDIENCE and identity.token_use == m.IDENTITY_TOKEN_USE
    with pytest.raises(ValidationError):  # cannot mint an "identity" token for the gateway
        m.AccessTokenClaims(**{**access.model_dump(), "token_use": "identity"})


def test_audit_record_round_trip():
    rec = m.AuditRecord(
        seq=0,
        timestamp=datetime.now(UTC),
        prev_hash="0" * 64,
        hash=SHA,
        component="gateway",
        actor="expense-bot",
        event="gateway.tool_call",
        outcome=m.DecisionOutcome.DENY,
        reason_code=m.ReasonCode.SCOPE_DENIED,
    )
    assert m.AuditRecord.model_validate_json(rec.model_dump_json()) == rec


def test_settings_defaults_are_safe_to_construct():
    s = Settings(_env_file=None)
    assert s.access_token_ttl_seconds <= 900
    assert s.risk_step_up_threshold < s.risk_revoke_threshold
    assert "change-me" not in repr(s)  # secrets are masked in reprs


# ---------------------------------------------------------------- policy files


@pytest.fixture(scope="module")
def actions():
    return yaml.safe_load((POLICY_DIR / "actions.yaml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def roles():
    return yaml.safe_load((POLICY_DIR / "roles.yaml").read_text(encoding="utf-8"))["roles"]


def _service_verbs(actions):
    return {(t["service"], t["verb"]) for t in actions["tools"].values()}


def test_every_tool_has_a_valid_tier(actions):
    valid = {t.value for t in m.Tier}
    for name, tool in actions["tools"].items():
        tiers = [tool["tier"]] if "tier" in tool else list(tool["tiers"].values())
        assert tiers, name
        assert set(tiers) <= valid, name
        assert ("target_arg" in tool) != ("target" in tool), f"{name}: need exactly one"
        assert isinstance(tool["args"], list) and tool["args"], name


def test_role_scopes_reference_known_service_verbs(actions, roles):
    known = _service_verbs(actions)
    for role, spec in roles.items():
        assert spec["allowed_scopes"], role
        for scope in spec["allowed_scopes"]:
            service, verb, target = scope.split(":", 2)
            assert (service, verb) in known, f"{role}: {scope}"
            assert target, f"{role}: {scope}"
            if service == "files":
                assert target.startswith("/"), f"{role}: {scope}"


def test_role_profiles_reference_known_categories(actions, roles):
    categories = set(actions["categories"])
    for role, spec in roles.items():
        assert set(spec["profile"]) <= categories, role
        assert spec["rate_limit_per_minute"] > 0, role


def test_expense_reader_cannot_touch_engineering_or_money(roles):
    scopes = roles["expense_reader"]["allowed_scopes"]
    assert not any("engineering" in s for s in scopes)
    assert not any(s.startswith(("bank:", "db:")) for s in scopes)
    assert "email:send:external" not in scopes
