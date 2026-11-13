"""A3: a network observer captures one valid request and sends the exact same bytes again.

AIMFA: every DPoP proof has a one-time ``jti``; the gateway remembers it, so the copy is
refused. Baseline: the static key request is valid forever, so the replay runs again.
The effect we count is emails in the outbox (1 = executed once, 2 = replay worked).
"""

from __future__ import annotations

from attacks.common import (
    LAYER_DPOP_REPLAY,
    MODE_BASELINE,
    AttackError,
    AttackResult,
    Env,
    check_mode,
    reason_of,
    result,
)

NAME = "A3 replayed request"
EMAIL = {"to": "finance@acme.test", "subject": "Q3 total", "body": "Total: 1.00"}


def run(mode: str) -> AttackResult:
    check_mode(mode)
    with Env(mode) as env:
        if mode == MODE_BASELINE:
            first = env.baseline_call("send_email", EMAIL)  # "captured" request
            replay = env.baseline_call("send_email", EMAIL)  # same bytes again
            sent = len(env.outbox())
            return result(
                NAME,
                mode,
                succeeded=first.status_code == 200 and replay.status_code == 200 and sent == 2,
                evidence=f"replay HTTP {replay.status_code}; emails delivered: {sent}",
            )

        key, ident = env.onboard("victim-bot", "expense_reader")
        token = env.get_token(key, ident, ["email:send:internal"])["access_token"]
        captured = env.gateway_headers(key, token)  # what the observer copies off the wire
        first = env.gateway_call(None, token, "send_email", EMAIL, headers=captured)
        if first.status_code != 200:
            raise AttackError(f"victim's own call failed: HTTP {first.status_code}")
        replay = env.gateway_call(None, token, "send_email", EMAIL, headers=captured)
        sent = len(env.outbox())
        return result(
            NAME,
            mode,
            succeeded=replay.status_code == 200 or sent != 1,
            blocked_by=LAYER_DPOP_REPLAY,
            reason_code=reason_of(replay),
            evidence=(
                f"replay HTTP {replay.status_code} {reason_of(replay)}; emails delivered: {sent}"
            ),
        )
