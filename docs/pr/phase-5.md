## Task
`Phase 5`: Agents + end-to-end (T5.1, T5.2, T5.3, T5.4, T5.5)

## What changed
- **T5.1 Launcher:** new `aimfa/agents/launcher.py`.
  - `load_manifest()` reads an agent's YAML recipe. The system prompt comes **only** from the manifest's `prompt_file`: a `system_prompt` key, an unknown field or a path escaping the manifest dir is rejected.
  - `measure_agent()` fingerprints the code files, prompt, `{tools, role}` and model id.
  - `Launcher.launch()` runs the attestation flow: challenge → measure → fresh in-memory key → evidence signed with the launcher key → identity token → `AgentClient`. A failure raises the client's typed error carrying the `ReasonCode`.
  - Four manifests live in `aimfa/agents/manifests/` (`normal_expense`, `injected_expense`, `wire_bot`, `llm_expense`), with prompts in `manifests/prompts/`.
  - New `scripts/register_agents.py` registers the launcher key and the golden fingerprints through the admin API. A 409 counts as "already registered".
  - The launcher key lives in `keys/launcher.pem` (git-ignored). An implementation note was added to ADR-0003.
- **T5.2 Scripted agents:** new `aimfa/agents/scripted/`, deterministic agents with no LLM.
  - `normal_expense` lists and reads the expense files, then emails a total to `finance@acme.test`.
  - `injected_expense` "obeys" the poisoned `vendor_note.txt`: it tries to read `/engineering/secrets.env` and email it to an external address. Both steps are denied with `SCOPE_DENIED`.
  - `wire_bot` reads the vendors and wires a payment. The wire returns 202, a human approves with TOTP, and then it executes.
  - `step()` records a denial instead of raising, so each transcript shows every blocked step.
  - The agents only use `start_task`, `call` and `complete_task`, so Phase 6 can run the same scripts against a baseline client.
- **T5.3 TAMU AI agent:** new `aimfa/agents/llm.py` and `llm_agent.py`.
  - `TamuAIClient` uses native tool calls and always sends `stream=False` (ADR-0005). `JsonActionClient` is the fallback for models without tool calls.
  - `run_llm_agent()` runs the tool loop with a 15-step cap. Tools outside the manifest are never forwarded, and arguments the model sends are type-checked.
  - A gateway denial goes back to the model as `DENIED: <reason>` and the loop continues.
  - Unit tests use a fake LLM (no network). `docs/results/README.md` explains how the live runs will be recorded.
- **T5.4 Demo runner:** new `scripts/run_demo.py`.
  - It starts the control plane, gateway, resources and (once T7.1 exists) Streamlit, all on `127.0.0.1` only.
  - It waits on each `/health`, then registers the agents and enrolls the approver.
  - Ctrl+C stops all child processes.
  - It refuses to start (exit 2) on a `change-me` or short secret, or on a non-localhost URL.
  - `--reset` wipes `var/`, and `--reset-keys` also wipes `keys/`.
  - Each app module got a zero-arg `app_factory()` for `uvicorn --factory`.
- **T5.5 E2E happy path:** new `tests/e2e/test_happy_path.py`. It uses the real manifests and the real launcher, in-process, and walks through: launch → read expenses → internal email → wire with 202 and TOTP approval → complete task → the old token gets 401 `TOKEN_REVOKED` → the audit chain verifies.
- **Review fixes:**
  - The manifests now also measure `scripted/__init__.py`, `aimfa/common/dpop.py` and `aimfa/common/crypto.py`.
  - `safe_reset` only deletes `<repo>/var` or `<repo>/keys`.
  - `--reset-keys` implies `--reset`.
  - `register_agents` reports a bad `code_paths` entry instead of crashing.
  - The LLM loop's cleanup no longer hides the original error.

## Plain-English summary
In the office-building picture from [LEARNING.md §2](../LEARNING.md), Phases 2–4 built the checkpoint, the badge office, the behavior guard and the manager's sign-off. Phase 5 adds **the front desk that issues ID cards** and **the actual employees (agents)** who walk through it.

- **The front desk (T5.1).** An agent can't vouch for itself, because a tampered agent would just lie. So a trusted **launcher** fingerprints the agent (its code, its instructions, its tool list and its model) and asks the control plane for an ID card. If someone changed even one character of the agent's instructions, the fingerprint no longer matches the one registered earlier, and no ID card is issued (`ATTEST_MEASUREMENT_MISMATCH`). The agent's private key is created fresh in memory and never saved, so there's no key file to steal.
- **The employees (T5.2, T5.3).** Three scripted agents behave the same way every run, which makes the demo reliable. One of them is "tricked" by a poisoned document into trying to steal a secrets file. AIMFA blocks it, because its badge only covers `/expenses`. The LLM agent does the same job with a real model. It reads its instructions only from the fingerprinted manifest, so its instructions can't be swapped after the check.
- **One button to start (T5.4).** Everything starts with one command and listens on `127.0.0.1` only, so nobody on campus Wi-Fi can reach it. It refuses to start with the placeholder passwords from `.env.example`.
- **The whole story as one test (T5.5).** The test walks one agent through every check, from ID card to audit log.

See also the [LEARNING.md](../LEARNING.md) section "The launcher, in plain English".

## Tests
- [x] Tests were written before the implementation in each task's coding pass. For token budget, each task had one coder that wrote the tests first, instead of separate test-writer and implementer agents.
- [x] Every Accept bullet in ROADMAP has a test, except the manual ones listed below. New test files (69 tests in total):
  - `tests/integration/test_launcher.py` (17)
  - `tests/integration/test_scripted_agents.py` (10)
  - `tests/unit/test_llm_agent.py` (17)
  - `tests/unit/test_run_demo.py` (18)
  - `tests/e2e/test_happy_path.py` (7)
- [x] Each new security check has a negative test:
  - prompt edit → `ATTEST_MEASUREMENT_MISMATCH`
  - injected reads and sends → `SCOPE_DENIED`
  - old token → `TOKEN_REVOKED`
  - default secrets → refused
  - unsafe reset path → refused
- [x] `pytest` (614 passed, 1 skipped, 2 xfailed), `ruff check .`, `ruff format --check .` and `bandit -ll` all pass locally.

**Still manual (not covered by automated tests):**
- **T5.3:** one live normal run, and the injection seen in at least 1 of 3 live runs. The transcripts go in `docs/results/` and need a TAMU AI key.
- **T5.4:** a real `python scripts/run_demo.py --reset` on Windows and macOS. Steps are in `docs/DEMO.md`.

## Security checklist
- [x] JWT decode pins `EdDSA` and checks `aud` / `iss` / `exp` / `token_use` (unchanged). The launcher only signs evidence.
- [x] Randomness comes from `secrets` and `cryptography`. No new secret comparisons.
- [x] No secrets, tokens or keys in logs, responses, audit details or the diff.
  - Agent keys are never saved.
  - The `repr` of `Launcher`, `AgentClient` and `TamuAIClient` hides keys.
  - Scripts print setting names only, never values.
- [x] Inputs are validated. Manifests use `extra="forbid"`, and `prompt_file` and `code_paths` can't escape their roots. Model tool-call arguments are JSON-parsed and type-checked, with no `eval`.
- [x] Fails closed: a measurement mismatch means no ID card, and a bad secret or non-local URL means nothing starts.
- [x] The `security-reviewer` subagent has run. Fixed:
  - **M1:** measured code didn't include the agents' shared helpers.
  - **M2:** `--reset` could delete any repo subfolder.
  - **M3:** `--reset-keys` left stale registrations behind.
  - Two lows: L1 (`ValueError` in `register_agents`) and L3 (cleanup hiding the original error).

**Accepted risks:**
- **The LLM agent sends what it reads to TAMU AI.** Each result is capped at 4000 characters. This is by design for the injection demo, which uses fake data only.
- **`run_demo.py`'s children inherit the full environment,** including the service secrets. Only the services are started as children; agents run in their own shell. This is noted in the agents README.
- **`tool_schemas()` reads `policy/actions.yaml` at runtime.** The policy file isn't part of the agent's fingerprint, but it is frozen and only affects how the tools are described to the model.
- **The measurement doesn't cover the whole Python install, and a compromised launcher defeats it.** Documented in ADR-0003 and THREAT_MODEL.
- **`app_factory()` uses the cached `get_settings()`.** This is harmless for `uvicorn --factory`, which starts a fresh process each time.

## Contracts
- [x] No changes to `aimfa/common/models.py`, `docs/CONTRACTS.md` or `policy/*.yaml`.

## Docs
- [x] ROADMAP T5.1–T5.5 ticked. T5.3 and T5.4 carry notes for their manual steps.
- [x] `aimfa/agents/README.md` updated. The control-plane, gateway and resources READMEs note the new `app_factory`.
- [x] `docs/DEMO.md` has the one-command start.
- [x] ADR-0003 has the implementation note.
- [x] LEARNING.md §5 updated, plus a new "The launcher, in plain English" explainer.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
