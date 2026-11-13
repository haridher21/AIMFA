# attacks: A1-A9 against baseline and AIMFA

Run everything: `python attacks/run_all.py` (prints the table, writes `docs/results.md`;
`--mode aimfa|baseline`, `--out PATH`). No services needed: each attack builds its own
throwaway in-process stack (temp dirs, random fake secrets, no network).

| File | Attack | Stopped by (AIMFA) | Reason code |
|---|---|---|---|
| `a1_tampered_agent.py` | edited agent prompt | attestation | `ATTEST_MEASUREMENT_MISMATCH` |
| `a2_stolen_token.py` | leaked token, thief's own key | dpop | `DPOP_KEY_MISMATCH` / `DPOP_MISSING` |
| `a3_replay.py` | exact request replayed | dpop_replay | `DPOP_REPLAY` |
| `a4_prompt_injection.py` | poisoned note: read secrets, email out | scope_monitor | `SCOPE_DENIED` |
| `a5_unauthorized_wire.py` | hijacked wire, human denies | step_up | `APPROVAL_DENIED` |
| `a6_expired_token.py` | token after task end / TTL | ttl_revocation | `TOKEN_REVOKED` / `TOKEN_EXPIRED` |
| `a7_scope_escalation.py` | ask STS for too many scopes | sts_policy | `STS_SCOPE_ESCALATION` |
| `a8_audit_tamper.py` | insider edits an audit row in SQL | hash_chain | `AUDIT_CHAIN_BROKEN` |
| `a9_fake_approval.py` | wrong TOTP; approval reused for other args | totp_action_binding | `APPROVAL_INVALID_TOTP` / `APPROVAL_MISMATCH` |

Each module exposes `run(mode) -> AttackResult`. Success is judged from real effects (outbox, balance, HTTP status, audit verify), never hard-coded.
`common.Env` is the *evaluator*: it holds the admin and gateway secrets to build the scene and read evidence. Attacker code uses only what a real attacker would have. A8 edits SQLite directly on purpose (that is the insider threat being modelled); A8 baseline uses an unchained `PlainLog` stand-in. A9 baseline is "n/a": there is no human step to attack.
Tests: `tests/e2e/test_attacks.py`.
