# Demo Runbook

**Target length: 8 minutes.** Setup, dashboard reading and the full manual checklist live in
[LIVE_TEST_GUIDE.md](LIVE_TEST_GUIDE.md) — do that **first**; this file assumes the stack has
already run live at least once.

## Hard prerequisite

Everything in this repo is tested in-process with `TestClient`. Until the **Live test session**
in ROADMAP is checked off, no one has started the real services, so there is nothing to rehearse
against. Order is: live test session → demo `.env` → three rehearsals → record the backup video.

## Roles (assign at the first rehearsal)

| Role | Does |
|---|---|
| **Driver** | Terminal A (services) and Terminal B (agents). Types nothing unplanned. |
| **Narrator** | Talks. Never touches the keyboard. |
| **Approver** | Holds the phone, types the TOTP in the dashboard. **Must be a different person from the Driver** — factor 4 is "a human approves", and that only reads as true if the audience sees a second human. |
| **Dashboard** | Drives the browser: switches pages, calls out the quarantine flip. |
| **Spotter** | Watches the clock, holds the backup video, runs the Attack Lab if the live stack dies. |

## Demo `.env` profile

`Settings` always reads `<repo root>/.env`, so there is no separate demo file — paste these over
your normal values before the demo and restore them afterwards.

```ini
ACCESS_TOKEN_TTL_SECONDS=180     # 15 min never expires inside an 8 min demo
APPROVAL_TIMEOUT_SECONDS=120     # long enough for a human, short enough to show auto-deny
RISK_DECAY_PER_MINUTE=2          # at the default 5, a 120 spike sags toward 80 while you talk
```

**`ACCESS_TOKEN_TTL_SECONDS` must stay larger than `APPROVAL_TIMEOUT_SECONDS`.** The agent holds
its token while it waits for the human; if the token dies first, the approved retry comes back
`TOKEN_EXPIRED` and the factor-4 beat collapses. 180 > 120 leaves a minute of slack.

Leave `RISK_STEP_UP_THRESHOLD=50` and `RISK_REVOKE_THRESHOLD=80` alone — the risk arithmetic in
the beats below depends on them.

## Script

| Time | Beat | Driver does | Audience sees |
|---|---|---|---|
| **0:00** | The problem | `run_demo.py --reset --mode baseline`, then `run_agent.py injected_expense` | The poisoned vendor note works. `var/outbox.jsonl` has the secrets, addressed to `attacker@evil.example`. One static key, no questions asked. |
| **1:00** | Same attack, AIMFA on | Restart in `aimfa` mode, rerun the same agent | `read_file:deny:SCOPE_DENIED`, `send_email:deny:SCOPE_DENIED`. Outbox empty. Identical agent, identical document. |
| **1:45** | **Factor 1** — what it *is* | Edit one character of `agents/manifests/prompts/normal_expense.md` on screen, then `run_agent.py normal_expense` | `ATTEST_MEASUREMENT_MISMATCH`. It never reaches the token step. Revert the file. |
| **3:00** | **Factor 2** — what it *has* | Tokens page, then Attack Lab → A2, A3. Leave the token to die. | TTL counting down. `DPOP_KEY_MISMATCH` — a genuine stolen token is useless. `DPOP_REPLAY`. Then the countdown hits zero and the next call is `TOKEN_EXPIRED`. |
| **4:15** | **Factor 3** — what it *does* | Run `injected_expense` **twice within a minute** | Risk climbs 60, then 120. Crosses 80, the agent flips to **quarantined**, its live token is revoked mid-task, and the next call is `403 AGENT_QUARANTINED`. |
| **5:45** | **Factor 4** — the human | `run_agent.py wire_bot`. Wrong code first, then the right one. | Phone buzzes. The card shows the action, the args and the risk. Wrong code → `APPROVAL_INVALID_TOTP`, card stays. Right code → the wire executes and the balance moves. |
| **7:00** | Accountability | Audit page → **Verify**. Then edit one row with `sqlite3` in Terminal B and Verify again. | `ok`, then red at `first_bad_seq`. Nothing can be quietly erased. |
| **7:45** | Close | Results table slide | 10/10 blocked under AIMFA, 9/10 succeed on the baseline. Then name the limitations out loud. |

### Why A10 is a slide, not a live beat

A10 is the only attack where the agent never breaks a rule, so scope cannot help and the monitor
is the only layer left — it is the most interesting result we have. But it runs only as an
in-process attack script: there is **no `finance_ops` agent manifest**, so `run_agent.py` cannot
drive it against the live services. Show it from the **Attack Lab** card and the results table,
and present the risk arithmetic (0 → 60 → 120 → quarantine) from the slide.

To make it a live beat, someone needs to add a scripted `finance_ops` agent that reads `payroll`
and mails it out — tracked as **T6.7**.

### What *not* to do live

Do not put the TAMU AI agent on the critical path. The roadmap only claims the injection
reproduces in at least one of three live runs, and it is a third-party network call inside a
graded eight minutes. The scripted `injected_expense` agent is deterministic and behaves
identically. Show the live-model transcript from `docs/results/` as evidence instead, and say so
plainly: "this also reproduces with a real model — here is the transcript."

## Rehearsal reset

Between runs, in this order:

1. **Clear the quarantine** — it is sticky. `finance-bot`/`expense-bot` stay quarantined until an
   admin clears them, so a second rehearsal silently skips the factor-3 beat. Use the dashboard's
   **Clear quarantine**, or `run_demo.py --reset`.
2. `--reset` wipes `var/` (database, audit chain, outbox) **and invalidates the approver QR** —
   delete the old entry in the authenticator and scan the new one.
3. Restore `/engineering`-adjacent files you edited for the attestation beat (`git status` should
   be clean).
4. Check the laptop clock. TOTP tolerates one 30-second step either way; a drifting clock looks
   exactly like a wrong code.

## Fallback ladder

1. **Live stack** — the plan above.
2. **Attack Lab** — each attack runs in its own in-process temp stack with throwaway secrets, so
   it needs nothing but the dashboard. If the services fall over mid-demo, this still produces the
   whole baseline-vs-AIMFA table.
3. **Backup video** — record it during the *first successful live run*, not the night before, and
   keep it on the desktop with timestamps matching the beats above.

Network: every service binds `127.0.0.1`, so the laptop is self-contained apart from ntfy and
TAMU AI. Do not trust campus wifi for the push — tether to cellular. With `NTFY_ENABLED=false`
approvals still work fully in the dashboard, so the push is a flourish, never a dependency.
