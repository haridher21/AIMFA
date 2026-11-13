# AIMFA Roadmap: ordered task board

**How to use this board:**
- **Pick a task:** take the first unchecked task whose **Deps** are all checked. Tasks marked **∥** can run in parallel with their siblings.
- **Work in the usual loop:** one branch and one PR per task (`feat/T2.3-sts`), using the three-role loop described in [AGENTS.md](../AGENTS.md).
- **Acceptance criteria are the test-writer's spec.** Every bullet in **Accept** must have at least one test.
- **Tick the box in the same PR** that completes the task.

**Critical path:** `T0.3 → T1.1 → T1.2 → T2.2 → T2.3 → T3.1 → T4.3 → T5.5 → T6.2 → T7.1`

| Tier | Phases | Target | Meaning |
|---|---|---|---|
| **Core** | 0–6 | Day 15 (~Nov 24) | The demo works from the CLI. |
| **Polish** | 7 | Day 17 | Dashboard and attack lab. |
| **Hardening + submission** | 8 | Day 20 | |

Each phase leaves a working, tested system, so stopping early still leaves a demo.

---

## Phase 0: Foundations (Days 1–2)
- [x] **T0.1 Scaffold**
  - **Files:** `pyproject.toml`, `.gitignore`, `.env.example`, package dirs, `aimfa/common/config.py`
  - **Accept:** `pip install -e .[dev]` works; `pytest` runs; `ruff check .` is clean.
- [x] **T0.2 AI-dev docs**
  - **Files:**
    - root: README, AGENTS.md, CLAUDE.md
    - `docs/*`: ARCHITECTURE, THREAT_MODEL, RESEARCH, LEARNING, DEMO, ADRs
    - package READMEs
    - `.claude/agents/*`
    - `.github/*`
  - **Accept:** a new agent can find any task, its contracts and the rules from these files alone.
- [x] **T0.3 Contracts: team sign-off required** (approved 2026-11-12, now frozen)
  - **Files:** `aimfa/common/models.py`, `docs/CONTRACTS.md`, `tests/unit/test_contracts.py`
  - **Accept:** all 5 team members have read CONTRACTS.md and approved the PR. After that, both files are frozen.
- [x] **T0.4 Policy files**
  - **Files:** `policy/roles.yaml`, `policy/actions.yaml`
  - **Roles:** `expense_reader`, `eng_assistant`, `finance_ops`
  - **Accept:** the policy sanity tests in `test_contracts.py` pass.
- [x] **T0.5 TAMU AI smoke test** (`TOOL_CALLING_OK` with `protected.Claude-Opus-5`; must send `stream=False`, see ADR-0005)
  - **Files:** `scripts/check_tamu_ai.py` (written)
  - **Accept:** a teammate with a key runs it. Record in ADR-0005 whether the result is `TOOL_CALLING_OK` or `NO_TOOL_CALLS`, and which model was used.
- [x] **T0.6 CI** (all steps pass locally 2026-11-12: ruff, pytest, bandit, pip-audit with 0 vulns. Confirm the green check on GitHub after the first manual push.)
  - **Files:** `.github/workflows/ci.yml`, `.github/pull_request_template.md`
  - **Accept:** a PR shows ruff + pytest + bandit + pip-audit checks.

## Phase 1: Primitives (Days 3–4). All ∥; pure functions, no network.
- [x] **T1.1 Crypto helpers** ∥
  - **Deps:** T0.3
  - **Files:** `aimfa/common/crypto.py`, `tests/unit/test_crypto.py`
  - **Functions:**
    - `generate_keypair()`, `save_private_key(path)` / `load_private_key(path)` (PEM, file mode best-effort 0600)
    - `public_jwk(key) -> PublicJWK`, `jwk_thumbprint(jwk) -> str` (RFC 7638, SHA-256, base64url without padding)
    - `sign_jwt(claims: dict, key, headers=None) -> str`, `verify_jwt(token, public_key, audience, issuer) -> dict` (algorithm pinned to EdDSA)
    - `measure(code_paths, system_prompt, tool_manifest, model_id) -> str` (hex SHA-256)
    - `canonical_json(obj) -> bytes`, `sha256_hex(data) -> str`
  - **Accept:**
    - sign/verify round-trips
    - a tampered payload or header is rejected
    - a token signed by another key is rejected
    - `alg=none` and HS256 tokens are rejected
    - `jwk_thumbprint` of the RFC 8037 Ed25519 example key (`x = 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo`) equals `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`
    - `measure` is independent of the order of `code_paths`, and changes when any file byte, the prompt, the manifest or the model id changes
    - `canonical_json` sorts keys and has no whitespace
- [x] **T1.2 DPoP** ∥
  - **Deps:** T1.1
  - **Files:** `aimfa/common/dpop.py`, `tests/unit/test_dpop.py`
  - **Functions:**
    - `make_proof(private_key, htm, htu, access_token=None, now=None) -> str`
    - `verify_proof(proof, *, htm, htu, expected_jkt=None, access_token=None, replay_cache, max_age, now=None) -> PublicJWK`, which raises `DPoPError(reason_code)`
    - `ReplayCache` (in-memory, TTL = 2 × max_age, thread-safe)
  - **Accept:** a valid proof passes. Each of these fails with its own `ReasonCode`:
    - not a JWT / wrong `typ` / wrong `alg` / no `jwk` → `DPOP_MALFORMED`
    - bad signature → `DPOP_BAD_SIGNATURE`
    - wrong key vs `expected_jkt` → `DPOP_KEY_MISMATCH`
    - wrong method → `DPOP_HTM_MISMATCH`
    - wrong URL, or URL with a query string → `DPOP_HTU_MISMATCH`
    - `iat` too old or too far in the future → `DPOP_STALE`
    - same `jti` twice → `DPOP_REPLAY`
    - missing or wrong `ath` when an access token is given → `DPOP_ATH_MISMATCH`
    - a private-key `jwk` (has `d`) in the header → `DPOP_MALFORMED`
- [x] **T1.3 Audit hash chain** ∥
  - **Deps:** T1.1, T1.5
  - **Files:** `aimfa/control_plane/audit.py`, `tests/unit/test_audit.py`
  - **Functions:** `AuditLog(db).append(AuditAppend) -> AuditRecord`, `verify() -> AuditVerifyResult`, `list(after_seq, limit)`
  - **Hashing:** `hash = sha256_hex(prev_hash + canonical_json(record fields except hash))`; the genesis `prev_hash` is `"0"*64`.
  - **Accept:**
    - an empty chain verifies OK
    - changing any field of a stored row → `ok=false` and `first_bad_seq` points at that row
    - deleting a middle row is detected
    - swapping two rows is detected
    - appends are serialized (a concurrent-append test produces no duplicate `seq`)
- [x] **T1.4 Policy engine** ∥
  - **Deps:** T0.4
  - **Files:** `aimfa/common/policy.py`, `tests/unit/test_policy.py`
  - **Functions:**
    - `Policy.load(policy_dir)`
    - `resolve(tool, args) -> ResolvedAction(service, verb, target, tier, category, sensitive)`; raises `PolicyError(ACTION_FORBIDDEN | INVALID_ARGUMENTS)`
    - `scope_allows(scopes, action) -> bool`
    - `role_permits(role, requested_scopes) -> bool`
    - `role(name)`
  - **Accept (table-driven):**
    - `/expenses/q3.csv` is allowed by `files:read:/expenses/*`
    - `/expenses/../engineering/secrets.env` → `INVALID_ARGUMENTS`
    - relative paths and backslashes are rejected
    - `/expenses` vs `/expenses-evil/x` must not match `/expenses/*`
    - email `bob@acme.test` → internal/medium; `x@evil.example` → external/high; `x@acme.test.evil.com` → external
    - an unknown tool → `ACTION_FORBIDDEN`
    - missing or extra args → `INVALID_ARGUMENTS`
    - requesting `files:read:/engineering/*` as `expense_reader` → not permitted
    - a requested scope that is a *subset* of an allowed one (`files:read:/expenses/q3.csv`) → permitted
    - categories and `sensitive` are computed correctly
- [x] **T1.5 SQLite storage** ∥
  - **Deps:** T0.3
  - **Files:** `aimfa/common/db.py`, `tests/unit/test_db.py`
  - **Tables:** schema + repository functions for `launchers`, `agents`, `approvers` (TOTP seed, last used step), `nonces`, `tokens` (jti, agent, task, scopes, exp, revoked), `approvals`, `risk_events`, `audit`
  - **Connections:** one connection per call, WAL mode, `check_same_thread=False`-safe usage
  - **Accept:**
    - CRUD works for each table in a temp dir
    - nonce consume is atomic (a second consume fails)
    - `revoke_all_for_agent` works
    - all queries are parameterized (a review check)

## Phase 2: Control plane + resources (Days 5–7)
- [x] **T2.1 Registry + admin API**
  - **Deps:** T1.5
  - **Files:** `aimfa/control_plane/app.py`, `registry.py`, `tests/integration/test_admin.py`
  - **Endpoints:** `/admin/launchers`, `/admin/agents`, `/admin/approvers`, revoke, clear-quarantine, `/health`
  - **Factory:** `create_app(settings) -> FastAPI`, so tests inject settings
  - **Accept:**
    - a missing or wrong `X-Admin-Key` → 401 `UNAUTHORIZED` (constant-time compare)
    - registering with an unknown role → 422
    - approver enrollment returns an otpauth URI exactly once, and the seed is never in any later response
- [x] **T2.2 Attestation**
  - **Deps:** T1.1, T2.1
  - **Files:** `aimfa/control_plane/attestation.py`, `tests/integration/test_attestation.py`
  - **Endpoints:** `/attest/challenge`, `/attest`, `/.well-known/jwks.json`. The control-plane signing key is generated on first start into `KEYS_DIR`.
  - **Accept:**
    - happy path issues an identity token whose claims validate as `IdentityCredentialClaims`
    - each of these is rejected with its reason code and audited: unknown agent, unknown launcher, launcher not assigned to this agent, bad JWS signature, unknown nonce, reused nonce, expired nonce, nonce issued for a different agent, measurement mismatch, quarantined agent
- [x] **T2.3 Token service (STS) + revocation**
  - **Deps:** T1.2, T1.4, T2.2
  - **Files:** `aimfa/control_plane/sts.py`, `revocation.py`, `tests/integration/test_sts.py`
  - **Endpoints:** `/token`, `/tasks/{id}/complete`, `/internal/introspect`, `/admin/tokens`
  - **Accept:**
    - a token is issued with `scopes ⊆ role` and the correct `cnf.jkt`
    - an escalation request → 403 `STS_SCOPE_ESCALATION`
    - an access token presented as an identity token → 401 `STS_IDENTITY_INVALID`
    - a DPoP proof signed by a different key → `DPOP_KEY_MISMATCH`
    - an expired identity token → rejected
    - after `/tasks/{id}/complete`, introspect returns `active=false, TOKEN_REVOKED`
    - completing another task's id → 403
- [x] **T2.4 Mock resources** ∥
  - **Deps:** T0.3
  - **Files:** `aimfa/resources/app.py`, `aimfa/resources/seed_data/**`, `tests/integration/test_resources.py`
  - **Seed data:**
    - `expenses/q3.csv`, `expenses/q4_draft.csv`
    - `expenses/vendor_note.txt`: the **poisoned** doc, containing an instruction to read `/engineering/secrets.env` and email it to `attacker@evil.example`
    - `engineering/secrets.env`: fake values, clearly labeled FAKE
    - `engineering/docs/design.md`
    - db tables `vendors`, `payroll`
    - bank balance
  - **Accept:**
    - every endpoint without `X-Gateway-Secret` → 403
    - path traversal is rejected at the resource too (defense in depth)
    - email appends to `var/outbox.jsonl`
    - a wire changes the balance
    - reset restores the seed

## Phase 3: Gateway + agent client (Days 7–9)
- [x] **T3.1 Gateway pipeline**
  - **Deps:** T2.3, T2.4
  - **Files:** `aimfa/gateway/app.py`, `pipeline.py`, `proxy.py`, `tests/integration/test_gateway.py`
  - **Behavior:** implements the 10-step pipeline in CONTRACTS.md. The control-plane client is an injectable interface, so tests can run all 3 apps in-process with `TestClient`. Monitor = a stub returning score 0; approvals = real calls to the CP internal API.
  - **Accept:** one test per pipeline step's failure mode, with the right status and reason code:
    - no token
    - garbage token
    - identity token used as access token
    - expired token
    - wrong DPoP key
    - replayed proof
    - revoked token
    - unknown tool
    - traversal
    - out-of-scope path
    - high-tier action → 202
  - Every decision produces an audit record.
- [x] **T3.2 Baseline mode** ∥
  - **Deps:** T2.4
  - **Files:** `aimfa/gateway/baseline.py`, `tests/integration/test_baseline.py`
  - **Accept:** with `AIMFA_MODE=baseline`, any tool call carrying the correct `X-API-Key` is forwarded, including out-of-scope calls (intentionally weak). A wrong key → 401 `BASELINE_API_KEY_INVALID`.
- [x] **T3.3 Agent client SDK**
  - **Deps:** T3.1
  - **Files:** `aimfa/agents/client.py`, `tests/integration/test_client.py`
  - **Class:** `AgentClient(settings, private_key, identity_token)` with methods:
    - `start_task(description, scopes)`
    - `call(tool, **args)`: on 202, polls the approval (configurable interval/timeout), then retries with `approval_id`
    - `complete_task()`
    - Also raises typed exceptions carrying the `ReasonCode`.
  - **Accept:** works against the T3.1 in-process fixture, including the approve and deny paths.

## Phase 4: Monitor + human step-up (Days 9–11)
- [x] **T4.1 Behavioral monitor**
  - **Deps:** T1.5, T2.3
  - **Files:** `aimfa/control_plane/monitor.py`, `tests/unit/test_monitor.py`
  - **Rules:**

    | Rule | Points |
    |---|---|
    | out-of-profile | +50 |
    | scope_denied / action_forbidden | +30 |
    | rate above role limit | +20 |
    | exfil sequence (sensitive read, then external egress, same task) | +60 |
    | dpop_failure / token_failure | +15 |
    | approval_denied | +25 |

  - **Decay:** linear, `RISK_DECAY_PER_MINUTE`. The clock is injected.
  - **Thresholds:** score ≥ `RISK_STEP_UP_THRESHOLD` → `step_up_required`. Score ≥ `RISK_REVOKE_THRESHOLD` → revoke all of the agent's tokens, set quarantined, audit.
  - **Endpoints:** `/internal/events`, `/admin/risk`
  - **Accept:**
    - one test per rule
    - exfil only fires with sensitive-then-egress in the same task
    - decay lowers the score over time
    - crossing 80 quarantines, and then `/attest` and `/token` are refused
    - clear-quarantine resets the agent
- [x] **T4.2 Wire monitor into gateway**
  - **Deps:** T3.1, T4.1
  - **Files:** `aimfa/gateway/pipeline.py`, `tests/integration/test_gateway_risk.py`
  - **Accept:**
    - an elevated score makes a medium action (internal email) return 202
    - a quarantine mid-task makes the next call 403 `AGENT_QUARANTINED`
    - an expense agent reading `/engineering/...` with a broad test token still gets risk points (out-of-profile)
- [x] **T4.3 Human approvals (push + TOTP)**
  - **Deps:** T3.1, T2.1
  - **Already done in Phase 3:** the approval routes in `approvals.py` (create, consume, poll, decide with TOTP and one-time codes), tested in `tests/integration/test_approval_routes.py`. **Still to do:** `notify.py` (the `TODO(T4.3)` hook in create), the enroll script, a risk event on deny, and the remaining Accept bullets (ntfy content, ntfy failure).
  - **Files:**
    - `aimfa/control_plane/approvals.py`, `notify.py`
    - `scripts/enroll_approver.py` (prints a QR code in the terminal + saves a PNG to `var/`)
    - `tests/integration/test_approvals.py`
  - **Accept:**
    - creating an approval sends exactly one ntfy POST (mocked) containing no args/secrets, just the agent, tool, risk and a dashboard link
    - the notification never asks for a code, and its link always points at `DASHBOARD_URL` (localhost). The TOTP is typed **only** in the dashboard, so a spoofed notification can't phish it.
    - a wrong TOTP → 401 `APPROVAL_INVALID_TOTP`
    - the same TOTP code used twice → rejected the second time
    - the wrong approver → rejected
    - deny → the retry gets 403 `APPROVAL_DENIED`
    - an approval consumed with different args → `APPROVAL_MISMATCH`
    - a second consume → `APPROVAL_ALREADY_USED`
    - past timeout → `APPROVAL_EXPIRED`
    - an agent can't poll another agent's approval
    - with ntfy disabled or failing, the approval still works (failure is logged)

## Phase 5: Agents + end-to-end (Days 11–13)
- [x] **T5.1 Launcher**
  - **Deps:** T2.2, T3.3
  - **Files:**
    - `aimfa/agents/launcher.py`
    - `aimfa/agents/manifests/*.yaml` (each agent's prompt file, tool manifest, model id, role)
    - `tests/integration/test_launcher.py`
  - **Behavior:**
    - `measure_agent(manifest)`
    - `launch(manifest) -> AgentClient`: challenge → measure → fresh key → signed evidence → identity
    - `scripts/register_agents.py`: computes golden measurements and registers them via the admin API
  - **ADR:** ADR-0003 documents the in-process trust assumption.
  - **Accept:**
    - a launch succeeds for an unmodified agent
    - editing one character of the prompt file → `ATTEST_MEASUREMENT_MISMATCH`
    - the private key is never written to disk
- [x] **T5.2 Scripted agents** ∥
  - **Deps:** T3.3
  - **Files:** `aimfa/agents/scripted/{normal_expense,injected_expense,wire_bot}.py`
  - **Behavior:** deterministic, with no LLM. `injected_expense` "obeys" `vendor_note.txt`.
  - **Accept:** each runs to completion against the in-process stack and returns a transcript of `(tool, decision)`.
- [x] **T5.3 TAMU AI agent** (code + fake-LLM tests done 2026-11-12. **Still manual:** the 1 normal + 3 injection live runs, transcripts in `docs/results/`)
  - **Deps:** T0.5, T3.3
  - **Files:** `aimfa/agents/llm.py`, `aimfa/agents/llm_agent.py`, `tests/unit/test_llm_agent.py`
  - **Behavior:**
    - `LLMClient` protocol, with `TamuAIClient` (OpenAI-compatible, native tools, **always `stream=False`**, see ADR-0005) and a `JsonActionClient` fallback
    - a tool loop with a max-steps cap of 15
    - the system prompt comes from the agent manifest (so it's attested)
  - **Accept:**
    - unit tests use a fake `LLMClient` (no network)
    - a manual live run completes the normal expense task
    - the injection is observed in at least 1 of 3 live runs; record the transcripts in `docs/results/`
- [x] **T5.4 One-command demo runner** (code + secret-refusal test done 2026-11-12. **Still manual:** a real run on Windows and macOS, steps in `docs/DEMO.md`)
  - **Deps:** T4.3, T5.1
  - **Files:** `scripts/run_demo.py`
  - **Behavior:**
    - starts CP, gateway, resources (uvicorn subprocesses) and Streamlit
    - waits on `/health`
    - registers the launcher, agents and approver
    - `--reset` wipes `var/`
    - `--mode aimfa|baseline`
    - Ctrl+C stops all children
  - **Hardening:**
    - every service binds to `127.0.0.1` only, never `0.0.0.0`, so nothing is reachable from campus Wi-Fi
    - it refuses to start if any secret in `.env` still starts with `change-me` or is shorter than 16 characters, and prints how to generate one
  - **Accept:**
    - works on Windows and macOS; a manual check by two teammates
    - a test shows the default-secret refusal
- [x] **T5.5 E2E happy path**
  - **Deps:** T5.1, T5.2, T4.3
  - **Files:** `tests/e2e/test_happy_path.py`
  - **Accept:**
    1. launch → token → list and read expenses
    2. internal email (allowed)
    3. `finance_ops` wire → 202 → approve with an in-test TOTP → executed
    4. complete task → the old token gets 401 `TOKEN_REVOKED`
    5. audit `verify()` passes

## Phase 6: Attacks + evaluation (Days 13–15)
- [x] **T6.1 Attack scripts A1–A9** ∥
  - **Deps:** T5.5
  - **Files:** `attacks/a1_tampered_agent.py` … `attacks/a9_fake_approval.py`, `attacks/common.py`
  - **Interface:** each exposes `run(mode) -> AttackResult(name, succeeded: bool, blocked_by: str | None, reason_code, evidence)`.
  - **Accept:** each script runs against the in-process stack in both modes.
- [x] **T6.2 Results table**
  - **Deps:** T6.1
  - **Files:** `attacks/run_all.py`, `tests/e2e/test_attacks.py`, `docs/results.md` (generated)
  - **Accept:**
    - in `aimfa` mode, every attack has `succeeded=False`, with the expected `blocked_by` layer
    - in `baseline` mode, A1–A8 have `succeeded=True`
    - the markdown table is generated
- [x] **T6.3 Live LLM prompt-injection run** (code + unit tests done; live run waits for the Live test session)
  - **Deps:** T5.3, T6.2
  - **Files:** `scripts/run_agent.py` (added 2026-11-12: nothing yet launches an agent against the *running* services)
  - **Behavior:** `python scripts/run_agent.py <manifest>` (`normal_expense`, `injected_expense`, `wire_bot`, `llm_expense`) launches through the real `Launcher` against `run_demo.py`'s services, runs the scripted agent or `run_llm_agent` with `TamuAIClient`, and prints the transcript. It never prints keys or tokens.
  - **Accept:**
    - unit tests for argument parsing and manifest selection (no network)
    - the live run itself waits for the **Live test session** in Phase 7, where it produces a recorded transcript + audit excerpt in `docs/results/a4_live.md`

## Phase 7: Dashboard + demo polish (Days 14–17)
- [ ] **T7.1 Streamlit dashboard**
  - **Deps:** T4.3, T6.2
  - **Files:** `aimfa/dashboard/app.py`, `aimfa/dashboard/pages/*`
  - **Pages:**
    - Agents
    - Tokens (TTL countdown, revoke)
    - Risk (chart)
    - Approvals (approve/deny + TOTP)
    - Audit (live tail, Verify button)
    - **Attack Lab** (run A1–A9, mode toggle, result cards)
    - It auto-refreshes, and it uses only the admin API (no direct DB access).
  - **Accept:**
    - a manual walkthrough of `docs/DEMO.md` works end to end
    - the admin key is never displayed
- [ ] **Live test session** (manual, right after T7.1; all live testing was deferred to here on 2026-11-12)
  - **Setup:**
    - `.env`: four strong secrets (`python -c "import secrets; print(secrets.token_urlsafe(32))"`), a long random `NTFY_TOPIC`, `NTFY_ENABLED=true`, `TAMU_AI_API_KEY`
    - phone: ntfy app subscribed to the topic on ntfy.sh, plus an authenticator app
    - `python scripts/run_demo.py --reset`, then scan the printed QR into the authenticator
  - **Checks (each closes a manual Accept item):**
    - T5.4: services start on Windows (and macOS); Ctrl+C stops them all; a `change-me` secret is refused
    - push + TOTP: `run_agent.py wire_bot` → phone buzzes → approve in the dashboard with the code → wire executes
    - T5.3: `run_agent.py llm_expense`, 1 normal run + 3 injection runs; save the transcripts in `docs/results/`
    - T6.3: record the live injection transcript + audit excerpt in `docs/results/a4_live.md`
- [ ] **T7.2 Demo runbook + rehearsals**
  - **Files:** `docs/DEMO.md`
  - **Accept:** 3 timed rehearsals (≤ 8 min each). A backup video is recorded.

## Phase 8: Hardening + submission (Days 17–20)
- [ ] **T8.1 Security pass:** `/security-review` on the whole repo, plus bandit + pip-audit. Fix the findings, or record them as accepted risks in THREAT_MODEL.
- [ ] **T8.2 Threat model final:** STRIDE per component, the attack → mitigation table, and limitations.
- [ ] **T8.3 Report + slides + video:** recorded **before** Thanksgiving (Nov 26).

## Stretch (only if Core and Polish are done)
- Docker image-digest attestation
- OPA/Rego policies
- IsolationForest anomaly scoring
- Gateway in front of a real MCP server
- WebAuthn approvals
- mTLS between services
