## Task
`Phase 2` — Control plane + resources (T2.1, T2.2, T2.3, T2.4)

## What changed
- **T2.1 Registry + admin API:** `aimfa/control_plane/app.py` (`create_app(settings, *, clock=None)`), `registry.py`, `state.py`; `aimfa/common/http.py` (ErrorResponse mapping, constant-time `secret_matches`, `require_strong_secrets`). Endpoints: `/admin/launchers`, `/admin/agents`, `/admin/approvers`, revoke, clear-quarantine, `/admin/audit`, `/health`.
- **T2.2 Attestation:** `aimfa/control_plane/attestation.py`. Endpoints: `/attest/challenge`, `/attest`, `/.well-known/jwks.json`. The signing key is created in `KEYS_DIR` on first start.
- **T2.3 STS + revocation:** `aimfa/control_plane/sts.py`, `revocation.py`. Endpoints: `/token`, `/tasks/{id}/complete`, `/internal/introspect`, `/admin/tokens`. `crypto.verify_jwt` gained an optional `now=` (injected clock) and a future-`iat` check. `db.py` gained `identity_not_before` and `revoke_agent_identity`.
- **T2.4 Mock resources:** `aimfa/resources/app.py`, `store.py`, `seed_data/**` (files, including the poisoned `vendor_note.txt` and the FAKE `secrets.env`; `vendors` / `payroll` tables; bank balance; outbox).

## Plain-English summary
Think of the system as an office building (see [LEARNING.md §2](../LEARNING.md)).

- **Front desk (T2.1).** Admins register who exists: *launchers* (the trusted programs that start agents), *agents* (with a role, e.g. `expense_reader`), and *approvers* (humans with an authenticator app). The admin key is checked in **constant time**, which means the comparison takes the same time whether the first character or the last one is wrong, so an attacker can't guess the key one character at a time. An approver's TOTP seed (the secret behind the 6-digit codes) is shown **once**, at enrollment, and never again.
- **ID-card desk (T2.2: "what the agent IS").** Before an agent gets anything, its launcher fingerprints it (code + prompt + tools + model → a hash called the *measurement*) and signs that, together with a one-time random *nonce*. The control plane checks the signature, checks the nonce is fresh, unused and issued to this agent (so old evidence can't be replayed), and compares the measurement to the registered "golden" value. A modified agent fails, and every failure is written to the audit chain with its reason.
- **Badge office (T2.3: "what the agent HAS").** The agent trades its ID card for a short-lived **access token** limited to what its role allows (asking for more → `STS_SCOPE_ESCALATION`). The token is **bound to the agent's private key** (DPoP), so a stolen token is useless without that key. Finishing a task, or the admin **kill switch**, cancels the badge, and the gateway's introspection check will see that.
- **Fake company (T2.4).** Pretend files, email, bank and database for the agents to use (and attack). They only answer requests that carry the gateway's secret, and they re-check file paths themselves (*defense in depth*): even if the gateway had a bug, `/expenses/../engineering/secrets.env` is still refused.

## Tests
- [x] Tests were written by the test-writer **before** implementation, and the implementer did not edit them. *(One exception: the orchestrator changed `FakeClock` to start at the real current time. PyJWT checks `exp` against the wall clock, so a hard-coded date made 7 tests fail once that time had passed.)*
- [x] Every Accept bullet in ROADMAP has a test
- [x] Each new security check has a negative test asserting the specific `ReasonCode`
- [x] `pytest` (419 passed, 1 skipped, 2 xfailed), `ruff check .`, `ruff format --check .` and `bandit -ll` all pass locally

New files: `tests/integration/{conftest,test_admin,test_attestation,test_sts,test_resources,test_review_fixes}.py`.

## Security checklist
- [x] JWT decode pins `EdDSA` and checks `aud` / `iss` / `exp` / `token_use`. Every call site passes `token_use` and the DPoP `expected_jkt`, closing the Phase 1 deferred items.
- [x] Secrets compared with `hmac.compare_digest`; randomness from `secrets`
- [x] No secrets, tokens or keys in logs, responses, audit details or the diff
- [x] Inputs validated with `models.py`; paths normalized before authorization
- [x] Fails closed; every decision audited with a `ReasonCode`
- [x] The `security-reviewer` subagent has run. Fixed:
  - **The kill switch could be bypassed by minting a new token.** Revoke now also invalidates identity tokens issued before it (`identity_not_before`).
  - **The services started with the default `change-me-*` secrets.** They now refuse to start if a secret is a default or shorter than 12 characters.
  - **The nonce table could grow without limit.** Expired nonces are purged, and each agent can hold at most 5 live nonces (`RATE_LIMITED`).
  - **`verify_jwt(now=…)` accepted a future `iat`.** It now rejects an `iat` more than 30 s in the future.
  - **A malformed agent key could get through `/attest`.** It is now rejected, and audited, before the nonce is used.

**Accepted risks:**
- Request-validation 422s (bad body or path shape) are not audited.
- The STS does not re-check the golden measurement. A golden change takes effect when the current identity token expires.
- Resources `/admin/reset` is guarded only by the gateway secret. **T3 must ensure no tool maps to it.**
- There is a small symlink TOCTOU window in `write_file`, and the outbox grows without bound. Both are localhost-only fake data.
- `/attest/challenge` reveals which agent ids exist (404). Agent ids aren't secret on localhost.

## Contracts
- [x] No changes to `aimfa/common/models.py`, `docs/CONTRACTS.md` or `policy/*.yaml`.

## Docs
- [x] ROADMAP T2.1–T2.4 ticked · control-plane README updated · LEARNING.md §5 updated

🤖 Generated with [Claude Code](https://claude.com/claude-code)
