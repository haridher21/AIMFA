## Task
`Phase 4`: Monitor + human step-up (T4.1, T4.2, T4.3)

## What changed
- **T4.1 Behavioral monitor:** new `aimfa/control_plane/monitor.py`.
  - `score_event()` is one pure function that holds every rule:
    | Rule | Points |
    |---|---|
    | out-of-profile | +50 |
    | scope denied / action forbidden | +30 |
    | over the role's rate limit | +20 |
    | exfiltration sequence (sensitive read, then external email, in the same task) | +60 |
    | DPoP / token failure | +15 |
    | approval denied | +25 |
  - `RiskMonitor` stores the events, applies linear decay against the injected clock, and quarantines the agent at the revoke threshold. Quarantining revokes all of the agent's tokens in one transaction and writes an audit record.
  - New routes: `POST /internal/events` and `GET /admin/risk`.
  - Clear-quarantine resets the score.
- **T4.2 Monitor wired into the gateway:**
  - `ControlPlaneMonitor` replaces `StubMonitor` as the default.
  - Step 7 sends the action's `category` and `sensitive` flag.
  - Denials from a verified agent are also reported, best effort: `SCOPE_DENIED`, `ACTION_FORBIDDEN`, `DPOP_*` and `TOKEN_REVOKED`. A monitor failure never changes the denial.
  - A raised score turns a medium action into a 202 that waits for a human.
- **T4.3 Human approvals (push + TOTP):**
  - New `aimfa/control_plane/notify.py`, with `NtfyNotifier` and the pure `build_notification()`.
  - The push contains only the agent, the tool, the risk score and a `DASHBOARD_URL` link. It contains no arguments and never asks for a code.
  - An ntfy failure is logged, and the approval still works.
  - A deny records an `APPROVAL_DENIED` risk event.
  - New `scripts/enroll_approver.py` shows the TOTP QR code in the terminal and saves a PNG under `var/`.
- **Hardening carried over from Phase 3 and the security review:**
  - Five wrong codes lock that approval.
  - Five wrong codes from one approver within 10 minutes lock that approver.
  - A repeated approval request with the same action hash returns the existing one, with no second push.
  - An agent may have at most 3 approvals pending; beyond that the gateway returns 403 `RATE_LIMITED`.
  - The monitor only loads events inside the decay window, and stores nothing for an agent that is already quarantined.
  - The `httpx` logger is set to WARNING, so the ntfy topic doesn't end up in INFO logs.

## Plain-English summary
In the office-building picture from [LEARNING.md §2](../LEARNING.md), Phase 3 built the checkpoint. Phase 4 adds **a guard who watches behavior** and **a manager who must sign off on risky actions**.

- **The behavior guard (T4.1, T4.2).** A valid badge doesn't prove an agent is behaving. An agent that was tricked by a poisoned document still holds real credentials. So every call adds to a per-agent "suspicion meter":
  - Reading outside its usual area adds points.
  - Being refused adds points.
  - Reading a secret and then emailing outside the company in the same task adds a lot of points; that pattern is how data gets stolen.
  - Points fade over time, so a single slip is forgiven.
  - At 50 points, even medium actions need a human.
  - At 80 points, the agent is **quarantined**: every badge it holds is cancelled on the spot, and it can't get new ones until an admin clears it.
- **The manager's sign-off (T4.3).** For risky actions the approver's phone gets a "doorbell" push saying *which agent, which tool, how risky*. The push never includes the data and never asks for a code. The approver opens our dashboard and types the six-digit code from their authenticator app (TOTP, see the glossary in LEARNING.md §3). Because the code is typed only on our page, a fake push has nothing to phish. Guessing is capped, so an attacker can't brute-force the code. An agent also can't flood the approver with requests until they click "yes" out of fatigue.

See also the [LEARNING.md](../LEARNING.md) section "The risk score and push-then-TOTP approvals".

## Tests
- [x] Tests were written by the test-writer **before** implementation.
  - The implementer did not edit them.
  - The orchestrator fixed three test bugs the implementer reported:
    - ids too short for the frozen id regex
    - `{}` headers treated as "use the default secret"
    - expecting `active` instead of `registered` after clear-quarantine, which contradicted CONTRACTS
- [x] Every Accept bullet in ROADMAP has a test. The new test files are:
  - `tests/unit/test_monitor.py`
  - `tests/integration/test_monitor_api.py`
  - `tests/integration/test_gateway_risk.py`
  - `tests/integration/test_approvals.py`
  - `tests/integration/test_phase4_hardening.py`
- [x] Each new security check has a negative test asserting the specific `ReasonCode`
- [x] `pytest` (545 passed, 1 skipped, 2 xfailed), `ruff check .`, `ruff format --check .` and `bandit -ll` all pass locally

## Security checklist
- [x] JWT decode pins `EdDSA` and checks `aud` / `iss` / `exp` / `token_use` (unchanged)
- [x] Secrets compared with `hmac.compare_digest`; randomness from `secrets`
- [x] No secrets, tokens or keys in logs, responses, audit details or the diff
  - The push holds no arguments.
  - The enroll script never prints the admin key.
- [x] Inputs validated with `models.py`
  - `/internal/events` takes a `RiskEvent` with `extra="forbid"`.
  - The monitor overwrites the event timestamp with its own clock.
- [x] Fails closed; every decision audited with a `ReasonCode`. Quarantine, approval lock, approver lockout and the pending cap are all audited.
- [x] The `security-reviewer` subagent has run.
  - Fixed: all three blocking mediums (per-approver lockout, pending-approval cap, bounded monitor storage) and the httpx-logging low.

**Accepted risks:**
- **A stolen token can push its own agent toward quarantine.** Someone holding a validly signed token, but not its DPoP key, can send bad proofs, and each one adds 15 points. This is by design: it fails toward safety. Documented in THREAT_MODEL §6.
- **An attacker holding the admin key can trigger the per-approver lockout as a denial of service.** Documented in THREAT_MODEL §6.
- **The wrong-code counters live in memory, so a restart resets them.** Approvals only live 5 minutes.
- **Exfil detection only spans the decay window.** It covers about 26 minutes at the default 5 points per minute.
- **The duplicate-approval check is not atomic.** Two truly concurrent identical requests could create two approvals; the pending cap still bounds them.
- **`DASHBOARD_URL` is not validated** to be localhost. It is set by the operator.
- **`chmod 0600` on the QR PNG has no effect on Windows.**
- **An approval is still spent if the resource then returns 502** (carried over from Phase 3).

## Contracts
- [x] No changes to `aimfa/common/models.py`, `docs/CONTRACTS.md` or `policy/*.yaml`.

## Docs
- [x] ROADMAP T4.1–T4.3 ticked
- [x] Control-plane and gateway READMEs updated
- [x] LEARNING.md §5 updated, plus its risk/TOTP explainer
- [x] THREAT_MODEL §6 accepted-risk notes added

🤖 Generated with [Claude Code](https://claude.com/claude-code)
