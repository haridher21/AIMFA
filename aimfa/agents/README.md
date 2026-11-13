# aimfa/agents: the agents being protected

| Module | Responsibility | Task |
|---|---|---|
| `client.py` | `AgentClient`: holds the instance key, builds a fresh DPoP proof per request, calls the gateway, polls approvals, completes tasks. Raises `AuthError` (401), `PolicyDenied` (403/422), `ApprovalTimeout` | T3.3 (done) |
| `launcher.py` | The **trusted root**: measures an agent (code + prompt + manifest + model), makes a fresh key, attests, returns an `AgentClient` | T5.1 (done) |
| `manifests/*.yaml` | Per agent: `agent_id`, role, prompt file, tool list, model id, code paths | T5.1 (done) |
| `scripted/` | Deterministic agents, no LLM: `normal_expense`, `injected_expense`, `wire_bot`. Each exposes `AGENT_ID`, `ROLE`, `SCOPES`, `TASK`, `run(session) -> list[TranscriptEntry]` | T5.2 (done) |
| `llm.py` | `LLMClient` protocol, `TamuAIClient` (OpenAI-compatible, native tools, always `stream=False`, ADR-0005), `JsonActionClient` fallback, `tool_schemas()` built from `policy/actions.yaml` limited to the manifest's tools | T5.3 (done; live runs manual) |
| `llm_agent.py` | `run_llm_agent(session, llm, system_prompt=..., tools=..., task=..., scopes=...)`: tool loop, max 15 steps. Tools outside the manifest are never forwarded; a gateway denial goes back to the model as `DENIED: <reason_code>` and the loop continues; `complete_task()` always runs | T5.3 (done) |

**Running one live (T6.3, code done; live run waits for the Live test session):** `python scripts/run_agent.py <normal_expense|injected_expense|wire_bot|llm_expense>` launches through the real `Launcher` against the services started by `scripts/run_demo.py` and prints tool / decision / reason code only (no keys, tokens or file contents). Attack scripts that use these agents live in `attacks/`.

**Sessions.** Scripted agents only use `start_task`, `call` and `complete_task`, so the same script runs against `AgentClient` or (Phase 6) a baseline client. `scripted.step()` records a denial instead of raising, so the transcript shows every blocked step. `injected_expense` simulates a prompt-injection victim and is for the local mock stack only.

## Must never
- **Write an agent instance private key to disk.**
- **Give agents `GATEWAY_RESOURCE_SECRET`, `INTERNAL_SERVICE_SECRET` or `ADMIN_API_KEY`.**
- **Load the system prompt from anywhere except the measured manifest.** Otherwise attestation is meaningless.

**Known, accepted (Phase 5 review):**
- What the LLM agent reads (up to 4000 chars per result) is sent to the TAMU AI API. That is by design for the prompt-injection demo, so use only the fake seed data.
- Run agents in their own shell, not as children of `run_demo.py`. Its children (the services) inherit the full environment, including the service secrets.
- Measurement covers each agent's own code plus `client.py`, `dpop.py` and `crypto.py`. It does not cover the whole Python install (ADR-0003).

**Tests:** `tests/integration/test_client.py`, `test_launcher.py`, `tests/unit/test_llm_agent.py` (fake LLM)

## Manifest format (`manifests/<name>.yaml`)
`agent_id`, `role` (key in `policy/roles.yaml`), `description`, `model_id`, `prompt_file` (relative to the manifest dir, must not escape it; the ONLY source of the system prompt), `tools` (names from `policy/actions.yaml`), `code_paths` (relative to the repo root). Unknown fields are rejected. The measurement covers code file hashes, the prompt, `{tools, role}` and the model id.

Register goldens and the launcher key with `python -m scripts.register_agents [--approver ID] [--skip-missing]` (409 = already registered). The launcher's own key lives in `keys/launcher.pem` (git-ignored); agent instance keys are never saved.
