"""A2: an access token leaks (log, screenshot, proxy) and a thief tries to use it.

AIMFA: the token is bound to the agent's private key (DPoP). The thief has the token but not
the key, so a proof from their own key (or no proof at all) is refused.
Baseline: the leaked static API key is all anyone needs.
"""

from __future__ import annotations

from aimfa.common.crypto import generate_keypair
from aimfa.common.models import ReasonCode
from attacks.common import (
    LAYER_DPOP,
    MODE_BASELINE,
    SECRETS_PATH,
    AttackError,
    AttackResult,
    Env,
    check_mode,
    reason_of,
    result,
)

NAME = "A2 stolen token"
EXPECTED_CODES = {ReasonCode.DPOP_KEY_MISMATCH, ReasonCode.DPOP_MISSING}


def run(mode: str) -> AttackResult:
    check_mode(mode)
    with Env(mode) as env:
        if mode == MODE_BASELINE:
            resp = env.baseline_call(
                "read_file", {"path": SECRETS_PATH}, api_key=env.leaked_baseline_key()
            )
            return result(
                NAME,
                mode,
                succeeded=resp.status_code == 200,
                evidence=f"leaked static key used by the thief: HTTP {resp.status_code}",
            )

        key, ident = env.onboard("victim-bot", "expense_reader")
        token = env.get_token(key, ident, ["files:read:/expenses/*"])["access_token"]
        legit = env.gateway_call(key, token, "read_file", {"path": "/expenses/q3.csv"})
        if legit.status_code != 200:
            raise AttackError(f"victim's own call failed: HTTP {legit.status_code}")

        thief_key = generate_keypair()  # the thief has the token, not the victim's key
        wrong_key = env.gateway_call(thief_key, token, "read_file", {"path": "/expenses/q3.csv"})
        no_proof = env.gateway_call(
            None,
            token,
            "read_file",
            {"path": "/expenses/q3.csv"},
            headers={"Authorization": f"DPoP {token}"},
        )
        got_in = 200 in (wrong_key.status_code, no_proof.status_code)
        code = reason_of(wrong_key)
        if not got_in and (code not in EXPECTED_CODES or reason_of(no_proof) not in EXPECTED_CODES):
            raise AttackError(f"refused for an unexpected reason: {code}, {reason_of(no_proof)}")
        return result(
            NAME,
            mode,
            succeeded=got_in,
            blocked_by=LAYER_DPOP,
            reason_code=code,
            evidence=(
                f"thief's own key: HTTP {wrong_key.status_code} {code}; "
                f"no proof: HTTP {no_proof.status_code} {reason_of(no_proof) or ReasonCode.OK}"
            ),
        )
