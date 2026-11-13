# Phase 6: Attacks + evaluation (T6.1, T6.2, T6.3)

## Task
- `T6.1`: Attack scripts A1–A9
- `T6.2`: Results table
- `T6.3`: Live LLM prompt-injection run. The code and unit tests are done. The live run waits for the **Live test session** after T7.1.

## What changed

### T6.1: Attack scripts A1–A9
- `attacks/common.py` builds a fresh, throwaway in-process stack for each attack. That stack is the control plane, the gateway and the resources, run through `TestClient` with temp dirs, random per-run secrets, ntfy turned off and no network.
- It also defines `AttackResult(name, mode, succeeded, blocked_by, reason_code, evidence)` and the `blocked_by` layer names.
- The nine attacks live in `attacks/a1_tampered_agent.py` … `attacks/a9_fake_approval.py`. Each exposes `run(mode)` for `mode` in `aimfa` or `baseline`.
- `succeeded` is judged from **real effects**: the outbox, the bank balance, HTTP status codes and `AuditLog.verify()`.
- Each attack checks that it was stopped by the **specific** defence it targets. If it was stopped by anything else, it raises `AttackError` instead of reporting "blocked", so a broken setup can't pass as a defence.

### T6.2: Results table
- `attacks/run_all.py` runs all 9 attacks in both modes, prints the table and writes `docs/results.md`. It accepts `--out` and `--mode`.
- `tests/e2e/test_attacks.py` covers both modes:
  - in `aimfa` mode, every attack is blocked with the expected `blocked_by` and `ReasonCode`
  - in `baseline` mode, A1–A8 succeed
  - the markdown table is generated (written to `tmp_path`)

### T6.3: `scripts/run_agent.py`
- `python scripts/run_agent.py <normal_expense|injected_expense|wire_bot|llm_expense>` launches an agent through the real `Launcher` against the services started by `run_demo.py`, then prints the transcript.
- It refuses any service URL that isn't localhost, and it prints only the tool, decision and reason code, never keys, tokens or file contents.
- If the services aren't running, it says so and exits with a non-zero code.
- Its unit tests (`tests/unit/test_run_agent.py`) cover argument parsing, manifest selection, refusal of spoofed hosts (`127.0.0.1.evil.com`, `localhost@evil.com`) and the "services not running" hint. They make no network calls.

### Docs
- `attacks/README.md` is new.
- `docs/LEARNING.md` §5, `aimfa/agents/README.md` and `docs/ROADMAP.md` (ticks) are updated.

## Results

| Attack | Baseline (static API key) | AIMFA | Blocked by | Reason code |
|---|---|---|---|---|
| A1 tampered agent | succeeded | blocked | attestation | `ATTEST_MEASUREMENT_MISMATCH` |
| A2 stolen token | succeeded | blocked | dpop | `DPOP_KEY_MISMATCH` / `DPOP_MISSING` |
| A3 replayed request | succeeded | blocked | dpop_replay | `DPOP_REPLAY` |
| A4 prompt injection | succeeded (1 mail to attacker) | blocked (0 mails) | scope_monitor | `SCOPE_DENIED` |
| A5 unauthorized wire | succeeded (balance −9,999) | blocked (balance unchanged) | step_up | `APPROVAL_DENIED` |
| A6 expired / finished token | succeeded | blocked | ttl_revocation | `TOKEN_REVOKED` / `TOKEN_EXPIRED` |
| A7 scope escalation | succeeded | blocked | sts_policy | `STS_SCOPE_ESCALATION` |
| A8 audit tampering | succeeded (modelled) | blocked | hash_chain | `AUDIT_CHAIN_BROKEN` |
| A9 fake / reused approval | n/a (no human step) | blocked | totp_action_binding | `APPROVAL_INVALID_TOTP` / `APPROVAL_MISMATCH` |

The full evidence is in `docs/results.md`. To regenerate it, run `python attacks/run_all.py`.

## Plain-English summary
Phases 0–5 built the security guard. This phase **attacks it on purpose** and writes down what happened.

We run each of 9 realistic attacks twice:
- once against the **baseline**, which is how many agent setups work today: one static API key, and anyone holding it can do anything
- once against **AIMFA**

**Baseline.** Every attack works:
- a tampered agent still gets in
- a leaked key works for a thief
- a captured request can be replayed
- a prompt-injected agent emails our "secrets" to an attacker
- a hijacked bot wires money
- an old key never expires
- an edited log goes unnoticed

**AIMFA.** Each attack is stopped by a *different* layer, which is the point of having four independent checks (see `docs/LEARNING.md`):
- **What the agent IS (attestation):** the tampered agent's fingerprint doesn't match its registered one, so it never gets an identity (A1).
- **What the agent HAS (DPoP + short-lived tokens):** a stolen token is useless without the private key that signs each request (A2). Each signed request can be used only once (A3). Tokens die when the task ends or after a few minutes (A6). An agent can't ask for more permissions than its role allows (A7).
- **What the agent DOES (scope + monitor):** the hijacked expense agent can't read engineering secrets or email outsiders, and every denial raises its risk score (A4).
- **A HUMAN for risky actions:** a wire needs a person to approve it with a code from their authenticator app. If they deny it, the wire never happens (A5). A wrong code fails, and an approval can't be reused for a different amount (A9).
- **Tamper-evident audit:** editing a past log row breaks the hash chain, so `verify()` reports exactly which row changed (A8).

## Tests
- [ ] Tests were written by the test-writer **before** implementation. *This phase used one coder for both tests and code to save tokens. Existing tests were not edited.*
- [x] Every Accept bullet in ROADMAP has a test. *T6.3's live run is manual and waits for the Live test session.*
- [x] Each attack asserts its specific `ReasonCode`.
- [x] `pytest` gives 649 passed, 1 skipped, 2 xfailed (35 new tests). `ruff check .`, `ruff format --check .` and `bandit -q -ll -r aimfa scripts attacks` are clean.

## Security checklist
- [x] No JWT decoding added (attacks reuse the existing client and verifier).
- [x] Attack environments use `secrets.token_urlsafe` secrets, with no `random`.
- [x] No secrets, tokens or keys in output, `docs/results.md` or the diff. `run_agent.py` prints only the tool, decision and reason code.
- [x] `run_agent.py` refuses non-localhost service URLs, including the `127.0.0.1.evil.com` and `localhost@evil.com` tricks.
- [x] Fails closed: setup errors raise `AttackError`, and a missing or unexpected reason code is never counted as "blocked".
- [x] The `security-reviewer` subagent ran: 0 critical, 0 high, 3 medium and 5 low findings. All 3 medium findings and 4 of the low ones are fixed. The fixes:
  - A8 baseline now edits a real file
  - A4 and A5 check the specific malicious call
  - A1, A2 and A7 only accept the expected codes
  - A6 and A9 check both codes
  - `run_agent.py` handles connection errors
  - spoofed-host tests were added

**Accepted risks:**
- **`run_agent.py` loads the full `Settings`.** Settings include `ADMIN_API_KEY` and `GATEWAY_RESOURCE_SECRET`, even though the agent only needs the launcher key and the TAMU key. This is acceptable for a localhost prototype. Revisit in T8.1 by splitting agent-side settings.
- **`attacks/` is excluded from bandit** by the existing `pyproject.toml`. The reviewer checked it by hand and found no `random`, SQL f-strings, `0.0.0.0` or `shell=True`.
- **The A8 baseline is a model.** The baseline has no audit chain at all, so "tampering goes undetected" is shown with a plain JSONL log. The evidence string says "modelled".
- **The attack harness holds the admin and gateway secrets** so it can play the evaluator: reading the outbox and balance, and acting as the approver. Attacker-side code only uses what a real attacker would have, such as a leaked token, a captured request or its own key.

## Contracts
- [x] No changes to `aimfa/common/models.py`, `docs/CONTRACTS.md` or `policy/*.yaml`.

## Docs
- [x] ROADMAP T6.1–T6.3 ticked, with T6.3 noted as waiting on the live run.
- [x] `aimfa/agents/README.md`, `attacks/README.md` and `docs/LEARNING.md` §5 updated.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
