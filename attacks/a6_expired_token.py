"""A6: a token is used after its task finished, or after its lifetime ran out.

AIMFA: completing a task revokes its token (TOKEN_REVOKED); tokens also expire on their own
(TOKEN_EXPIRED). Both are tested with a VALID proof from the right key, so only the token's
lifecycle can be what stops it. The clock is injected: no sleeping.
Baseline: the static key never expires and cannot be revoked per task.
"""

from __future__ import annotations

from aimfa.common.models import ReasonCode
from attacks.common import (
    LAYER_TTL_REVOCATION,
    MODE_BASELINE,
    AttackError,
    AttackResult,
    Env,
    check_mode,
    reason_of,
    result,
)

NAME = "A6 expired token"
LIST = {"dir": "/expenses"}
SCOPES = ["files:list:/expenses"]
TTL = 300


def run(mode: str) -> AttackResult:
    check_mode(mode)
    with Env(mode, access_ttl=TTL) as env:
        if mode == MODE_BASELINE:
            env.clock.advance(TTL + 1)  # "later": nothing about the key changes
            resp = env.baseline_call("list_files", LIST)
            return result(
                NAME,
                mode,
                succeeded=resp.status_code == 200,
                evidence=f"static key after the task and {TTL + 1}s: HTTP {resp.status_code}",
            )

        key, ident = env.onboard("victim-bot", "expense_reader")
        done = env.get_token(key, ident, SCOPES)
        if env.gateway_call(key, done["access_token"], "list_files", LIST).status_code != 200:
            raise AttackError("victim's own call failed")
        env.complete_task(key, done["access_token"], done["task_id"])
        revoked = env.gateway_call(key, done["access_token"], "list_files", LIST)

        fresh = env.get_token(key, ident, SCOPES)  # a second task whose token just ages out
        env.clock.advance(TTL + 1)
        expired = env.gateway_call(key, fresh["access_token"], "list_files", LIST)

        if 200 not in (revoked.status_code, expired.status_code) and (
            reason_of(revoked) is not ReasonCode.TOKEN_REVOKED
            or reason_of(expired) is not ReasonCode.TOKEN_EXPIRED
        ):
            raise AttackError(f"unexpected reasons: {reason_of(revoked)}, {reason_of(expired)}")
        got_in = 200 in (revoked.status_code, expired.status_code)
        return result(
            NAME,
            mode,
            succeeded=got_in,
            blocked_by=LAYER_TTL_REVOCATION,
            reason_code=reason_of(revoked),
            evidence=(
                f"after task complete: HTTP {revoked.status_code} {reason_of(revoked)}; "
                f"after {TTL + 1}s: HTTP {expired.status_code} {reason_of(expired)}"
            ),
        )
