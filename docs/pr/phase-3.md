## Task
`Phase 3`: Gateway + agent client (T3.1, T3.2, T3.3). It also brings forward the control-plane approval routes that the gateway needs (part of T4.3).

## What changed
- **T3.1 Gateway pipeline:**
  - New files: `aimfa/gateway/app.py`, `pipeline.py`, `proxy.py`, `cp_client.py`.
  - `create_app(settings, *, control_plane_client=None, resources_http=None, monitor=None, clock=None)`. Tests run the control plane, gateway and resources in one process.
  - `POST /tool` runs the 10 steps from CONTRACTS.md in order.
  - The monitor is a stub that returns score 0 until T4.2 replaces it.
- **T3.2 Baseline mode:** `aimfa/gateway/baseline.py`. With `AIMFA_MODE=baseline`, the only check is a constant-time comparison of `X-API-Key`. It still audits every call.
- **T3.3 Agent client SDK:** `aimfa/agents/client.py`.
  - `AgentClient` has three methods. `start_task` gets a token, `call` makes a tool call, and `complete_task` ends the task.
  - `call` builds a fresh DPoP proof for every request. If the gateway answers 202, it waits for the approval and then retries the same call.
  - Errors are typed: `AuthError`, `PolicyDenied` and `ApprovalTimeout`, each carrying its `ReasonCode`.
- **Control-plane approval routes (brought forward from T4.3):**
  - New file `aimfa/control_plane/approvals.py` adds these routes:
    - `POST /internal/approvals` (create)
    - `POST /internal/approvals/{id}/consume`
    - `GET /approvals/{id}` (the agent polls, using DPoP)
    - `POST /approvals/{id}/decide` (needs the admin key and a TOTP code)
    - `POST /internal/audit` (accepts gateway records only)
  - The ntfy push is still a `TODO(T4.3)` hook.
- **Small shared changes:**
  - `crypto.action_hash()`: one action-hash rule, shared by the gateway and the control plane.
  - `sts.check_dpop` takes an `htm` argument, because the approval poll is a GET.

## Plain-English summary
In the office-building picture from [LEARNING.md §2](../LEARNING.md), Phase 2 built the badge office. Phase 3 builds **the security checkpoint every request must walk through** (the gateway), and **the badge holder's wallet** (the agent client).

- **The checkpoint (T3.1).** Each tool call passes ten guards in a fixed order, and the first "no" ends it. Nothing reaches the company systems after a "no".
  1. Is there a badge?
  2. Is it genuine, for this building, not expired, and an *access* badge rather than an ID card?
  3. Does the caller hold the private key the badge is tied to (DPoP)? The proof must also be fresh, never seen before, and made for *this* badge.
  4. Has the badge been cancelled, or the agent quarantined? The gateway asks the control plane each time, which is what makes the kill switch instant.
  5. Is this a real tool with clean arguments? `/expenses/../engineering/secrets.env` is rejected here.
  6. Does the badge's scope cover this exact (cleaned-up) path?
  7. What is the agent's risk score? This is a placeholder until Phase 4.
  8. Is this a dangerous action, like an external email or a bank wire? Then a human must say yes.
  9. If a human approved, is the approval for *exactly* this action? The approval is tied to a fingerprint (hash) of agent + task + tool + arguments, so approving "wire $10" can't be reused for "wire $10,000". It can also be used only once.
  10. Only then does the gateway call the resource, using its own secret, which agents never see.
- **Two habits worth copying:**
  - The gateway writes every decision to the tamper-evident audit log *before* acting. If it can't write the log, it refuses.
  - It authorizes the cleaned-up path and then uses that same cleaned-up path, never the raw one the agent sent.
- **The old way (T3.2).** Baseline mode checks one shared password (`X-API-Key`) and nothing else. It is deliberately weak, so in Phase 6 we can show what each attack achieves *without* AIMFA.
- **The wallet (T3.3).** `AgentClient` hides the crypto from agent code. It signs a fresh proof for every request, so proofs are never replayed. When the gateway says "a human must approve", it waits and then retries the identical call.
- **The human's side, early.** The approver types a 6-digit TOTP code (the one their authenticator app shows). A code works once, and only for the assigned approver. An agent can poll *its own* approval, but another agent's approval looks like it doesn't exist (404). That way, poking at ids reveals nothing.

## Tests
- [x] Tests were written by the test-writer **before** implementation, and the implementer did not edit them. *(The orchestrator added one test after the security review: `test_unexpected_error_in_pipeline_is_denied_and_audited`.)*
- [x] Every Accept bullet in ROADMAP has a test: no token, garbage token, identity-as-access, expired, wrong DPoP key, replay, revoked, unknown tool, traversal, out-of-scope, high-tier → 202, every decision audited, baseline key, and the client's approve and deny paths
- [x] Each new security check has a negative test asserting the specific `ReasonCode`
- [x] `pytest` (478 passed, 1 skipped, 2 xfailed), `ruff check .`, `ruff format --check .` and `bandit -ll` all pass locally

New tests (59):
- `tests/integration/test_gateway.py` (27)
- `test_baseline.py` (6)
- `test_client.py` (10)
- `test_approval_routes.py` (16)

`conftest.py` gained a `Stack` fixture (control plane + resources + gateway, in process) and TOTP helpers.

## Security checklist
- [x] JWT decode pins `EdDSA` and checks `aud` / `iss` / `exp` / `token_use`. The gateway uses `aud=aimfa-gateway` and `token_use="access"`, closing the Phase 1 carry-over.
- [x] The DPoP check gets `expected_jkt` (from the token's `cnf.jkt`) and `access_token` (the `ath` binding). A token with no `cnf.jkt` is refused, so the key check can never be skipped.
- [x] Secrets compared with `hmac.compare_digest`; randomness from `secrets`
- [x] No secrets, tokens or keys in logs, responses, audit details or the diff. Resource error bodies are never passed back to agents.
- [x] Inputs validated with `models.py`; paths normalized before authorization; the agent's `approval_id` is shape-checked and URL-quoted before it goes into an internal URL.
- [x] **No tool can reach resources `/admin/reset`.** Every route in `proxy.TOOL_ROUTES` has a fixed prefix (`/files`, `/email`, `/bank`, `/db`). This closes the Phase 1 carry-over.
- [x] Fails closed; every decision is audited with a `ReasonCode`.
- [x] The `security-reviewer` subagent has run. No critical, high or medium findings. Fixed:
  - **An unexpected exception in the pipeline gave an unaudited 500.** It is now caught, denied (500 `UPSTREAM_ERROR`, with no details to the caller) and audited.
  - **A denial was silently unaudited if the audit write failed.** The call was already denied; now it also leaves a warning in the server log.

**Accepted risks:**
- **No attempt limit on wrong TOTP codes at `/approvals/{id}/decide`.** An attacker would need the admin key first, every wrong code is audited, and with a one-step window a guess succeeds about 3 times in a million. Revisit in T4.3.
- **An agent can create unlimited pending approvals** (each high-tier call without an `approval_id` creates one), which could flood the approver. Deferred to T4.x: deduplicate by action hash, or let the monitor score it.
- **An approval is spent even if the resource then fails with a 502.** The agent must ask again.
- **The gateway fetches the control-plane JWKS once.** There is no key rotation.
- **Baseline mode doesn't refuse a default `change-me` baseline key at startup.** The demo runner (T5.4) handles default-secret refusal.
- **Monitor stub, no ntfy push yet, and a denied approval doesn't raise the risk score yet.** These are scheduled for T4.1–T4.3.

## Contracts
- [x] No changes to `aimfa/common/models.py`, `docs/CONTRACTS.md` or `policy/*.yaml`.

## Docs
- [x] ROADMAP T3.1–T3.3 ticked. T4.3 notes which parts were done early.
- [x] Package READMEs (gateway, control_plane, agents) updated
- [x] LEARNING.md §5 updated, with a new "checkpoint pipeline in plain English" paragraph

🤖 Generated with [Claude Code](https://claude.com/claude-code)
