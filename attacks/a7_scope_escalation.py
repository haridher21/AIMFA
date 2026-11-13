"""A7: a hijacked agent asks the token service for more power than its role has.

AIMFA: the STS only issues scopes the agent's ROLE allows, so asking for bank and engineering
scopes is refused (STS_SCOPE_ESCALATION) and no token exists to misuse.
Baseline: the one static key is all-powerful, so an out-of-role tool just works.
"""

from __future__ import annotations

from aimfa.common.models import ReasonCode
from attacks.common import (
    LAYER_STS_POLICY,
    MODE_BASELINE,
    SECRETS_PATH,
    AttackError,
    AttackResult,
    Env,
    check_mode,
    reason_of,
    result,
)

NAME = "A7 scope escalation"
GREEDY = ["files:read:/expenses/*", "files:read:/engineering/*", "bank:wire:*"]


def run(mode: str) -> AttackResult:
    check_mode(mode)
    with Env(mode) as env:
        if mode == MODE_BASELINE:
            resp = env.baseline_call("read_file", {"path": SECRETS_PATH})
            return result(
                NAME,
                mode,
                succeeded=resp.status_code == 200,
                evidence=f"out-of-role read with the static key: HTTP {resp.status_code}",
            )

        key, ident = env.onboard("victim-bot", "expense_reader")
        resp = env.request_token(key, ident, GREEDY)
        if resp.status_code != 200 and reason_of(resp) is not ReasonCode.STS_SCOPE_ESCALATION:
            raise AttackError(f"refused for an unexpected reason: {reason_of(resp)}")
        return result(
            NAME,
            mode,
            succeeded=resp.status_code == 200,
            blocked_by=LAYER_STS_POLICY,
            reason_code=reason_of(resp),
            evidence=f"token request with {len(GREEDY)} scopes: HTTP {resp.status_code}",
        )
