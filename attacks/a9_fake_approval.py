"""A9: someone without the approver's phone tries to push a risky action through.

AIMFA, two tries: (1) approve a pending wire with a WRONG TOTP code -> APPROVAL_INVALID_TOTP;
(2) after a legitimate approval of a small wire, reuse that approval for a much bigger wire
-> APPROVAL_MISMATCH (the approval is bound to the exact action hash). Judged by the balance.
Baseline: there is no approval step at all, so the wire just executes; the table shows n/a.
"""

from __future__ import annotations

from aimfa.common.models import ReasonCode
from attacks.common import (
    LAYER_TOTP_BINDING,
    MODE_BASELINE,
    AttackError,
    AttackResult,
    Env,
    check_mode,
    reason_of,
    result,
)

NAME = "A9 fake approval"
SMALL = {"to_account": "ACME-0001", "amount": 100.0, "memo": "invoice"}
BIG = {"to_account": "ACME-0001", "amount": 100000.0, "memo": "invoice"}


def run(mode: str) -> AttackResult:
    check_mode(mode)
    with Env(mode) as env:
        before = env.balance()
        if mode == MODE_BASELINE:
            resp = env.baseline_call("wire_transfer", BIG)
            after = env.balance()
            return result(
                NAME,
                mode,
                succeeded=after != before,
                evidence=(
                    f"no human step exists: HTTP {resp.status_code}, balance {before} -> {after}"
                ),
            )

        key, ident = env.onboard("victim-bot", "finance_ops")
        token = env.get_token(key, ident, ["bank:wire:*"])["access_token"]
        pending = env.gateway_call(key, token, "wire_transfer", SMALL)
        approval_id = (pending.json().get("decision") or {}).get("approval_id")
        if pending.status_code != 202 or not approval_id:
            raise AttackError(f"wire was not held for approval: HTTP {pending.status_code}")

        bad = env.decide(approval_id, approve=True, code=env.wrong_totp_code())
        bad_code = reason_of(bad)
        if bad.status_code == 200:  # the attacker's "approval" was accepted
            return result(NAME, mode, succeeded=True, evidence="wrong TOTP code was accepted")

        good = env.decide(approval_id, approve=True, code=env.totp_code())  # the real human
        if good.status_code != 200:
            raise AttackError(f"legit approval failed: HTTP {good.status_code}")
        swapped = env.gateway_call(key, token, "wire_transfer", BIG, approval_id=approval_id)
        after = env.balance()
        if swapped.status_code != 200 and reason_of(swapped) is not ReasonCode.APPROVAL_MISMATCH:
            raise AttackError(f"reuse refused for an unexpected reason: {reason_of(swapped)}")
        if bad_code is not ReasonCode.APPROVAL_INVALID_TOTP:
            raise AttackError(f"wrong TOTP refused for an unexpected reason: {bad_code}")
        return result(
            NAME,
            mode,
            succeeded=swapped.status_code == 200 or after != before,
            blocked_by=LAYER_TOTP_BINDING,
            reason_code=bad_code,
            evidence=(
                f"wrong TOTP: HTTP {bad.status_code} {bad_code}; approval reused for a "
                f"different amount: HTTP {swapped.status_code} {reason_of(swapped)}; "
                f"balance {before} -> {after}"
            ),
        )
