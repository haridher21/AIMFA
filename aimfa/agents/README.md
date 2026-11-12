# aimfa/agents: the agents being protected

| Module | Responsibility | Task |
|---|---|---|
| `client.py` | `AgentClient`: holds the instance key, builds DPoP proofs, calls the gateway, polls approvals, completes tasks | T3.3 |
| `launcher.py` | The **trusted root**: measures an agent (code + prompt + manifest + model), makes a fresh key, attests, returns an `AgentClient` | T5.1 |
| `manifests/*.yaml` | Per agent: `agent_id`, role, prompt file, tool list, model id, code paths | T5.1 |
| `scripted/` | Deterministic agents, no LLM: `normal_expense`, `injected_expense`, `wire_bot` | T5.2 |
| `llm.py` | `LLMClient` protocol, `TamuAIClient` (OpenAI-compatible), `JsonActionClient` fallback | T5.3 |
| `llm_agent.py` | Tool-calling loop (max 15 steps) using the attested system prompt | T5.3 |

## Must never
- **Write an agent instance private key to disk.**
- **Give agents `GATEWAY_RESOURCE_SECRET`, `INTERNAL_SERVICE_SECRET` or `ADMIN_API_KEY`.**
- **Load the system prompt from anywhere except the measured manifest.** Otherwise attestation is meaningless.

**Tests:** `tests/integration/test_client.py`, `test_launcher.py`, `tests/unit/test_llm_agent.py` (fake LLM)
