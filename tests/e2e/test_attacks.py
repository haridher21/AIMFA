"""T6.1/T6.2: attacks A1-A9 against the in-process stack, AIMFA mode vs baseline mode.

The attacks build their own isolated stacks (no pytest fixtures), so we run everything once
per module and let each test look at its own result.
"""

from __future__ import annotations

import pytest

from aimfa.common.models import ReasonCode
from attacks import run_all
from attacks.common import (
    LAYER_ATTESTATION,
    LAYER_DPOP,
    LAYER_DPOP_REPLAY,
    LAYER_HASH_CHAIN,
    LAYER_SCOPE_MONITOR,
    LAYER_STEP_UP,
    LAYER_STS_POLICY,
    LAYER_TOTP_BINDING,
    LAYER_TTL_REVOCATION,
    AttackResult,
    check_mode,
)

# name prefix -> (blocked_by, accepted reason codes in AIMFA mode)
EXPECTED = {
    "A1": (LAYER_ATTESTATION, {ReasonCode.ATTEST_MEASUREMENT_MISMATCH}),
    "A2": (LAYER_DPOP, {ReasonCode.DPOP_KEY_MISMATCH, ReasonCode.DPOP_MISSING}),
    "A3": (LAYER_DPOP_REPLAY, {ReasonCode.DPOP_REPLAY}),
    "A4": (LAYER_SCOPE_MONITOR, {ReasonCode.SCOPE_DENIED}),
    "A5": (LAYER_STEP_UP, {ReasonCode.APPROVAL_DENIED}),
    "A6": (LAYER_TTL_REVOCATION, {ReasonCode.TOKEN_REVOKED, ReasonCode.TOKEN_EXPIRED}),
    "A7": (LAYER_STS_POLICY, {ReasonCode.STS_SCOPE_ESCALATION}),
    "A8": (LAYER_HASH_CHAIN, {ReasonCode.AUDIT_CHAIN_BROKEN}),
    "A9": (LAYER_TOTP_BINDING, {ReasonCode.APPROVAL_INVALID_TOTP}),
}
IDS = list(EXPECTED)


@pytest.fixture(scope="module")
def results() -> dict[tuple[str, str], AttackResult]:
    return {(r.name.split()[0], r.mode): r for r in run_all.run_all()}


@pytest.mark.parametrize("attack", IDS)
def test_aimfa_mode_blocks_attack(results, attack):
    res = results[(attack, "aimfa")]
    blocked_by, codes = EXPECTED[attack]
    assert res.succeeded is False, res.evidence
    assert res.blocked_by == blocked_by
    assert res.reason_code in codes


@pytest.mark.parametrize("attack", IDS[:8])
def test_baseline_mode_attack_succeeds(results, attack):
    res = results[(attack, "baseline")]
    assert res.succeeded is True, res.evidence
    assert res.blocked_by is None and res.reason_code is None


def test_baseline_a9_has_no_human_step(results):
    res = results[("A9", "baseline")]
    assert res.succeeded is True and "no human step" in res.evidence


def test_a4_evidence_shows_nothing_left_in_the_outbox(results):
    assert "mails to attacker: 0" in results[("A4", "aimfa")].evidence
    assert "mails to attacker: 1" in results[("A4", "baseline")].evidence


def test_a9_covers_both_tries(results):
    evidence = results[("A9", "aimfa")].evidence
    assert "APPROVAL_INVALID_TOTP" in evidence and "APPROVAL_MISMATCH" in evidence


def test_a6_covers_revoked_and_expired(results):
    evidence = results[("A6", "aimfa")].evidence
    assert "TOKEN_REVOKED" in evidence and "TOKEN_EXPIRED" in evidence


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError):
        check_mode("both")


def test_markdown_table_has_a_row_per_attack(results):
    md = run_all.render_markdown(results.values())
    for attack in IDS:
        assert f"| {attack} " in md
    assert "ATTEST_MEASUREMENT_MISMATCH" in md and "n/a (no human step)" in md


def test_main_writes_the_table_to_the_given_path(results, monkeypatch, tmp_path):
    monkeypatch.setattr(run_all, "run_all", lambda modes=run_all.MODES: list(results.values()))
    out = tmp_path / "nested" / "results.md"
    assert run_all.main(["--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert text.startswith("# Attack results") and "hash_chain" in text
