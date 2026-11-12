# aimfa/gateway: the checkpoint (:8100)

This service is the **Policy Enforcement Point**. Every agent tool call goes through `POST /tool`. The ordered pipeline is specified in [docs/CONTRACTS.md](../../docs/CONTRACTS.md#gateway-8100).

| Module | Responsibility | Task |
|---|---|---|
| `app.py` | `create_app(settings, control_plane_client=None)`; mode switch | T3.1 |
| `pipeline.py` | The checks, as small functions in order: token → DPoP → introspect → resolve → scope → risk → tier → approval | T3.1, T4.2 |
| `proxy.py` | tool → resource HTTP call with `X-Gateway-Secret`, using the **normalized** arguments | T3.1 |
| `baseline.py` | "the old way": static `X-API-Key` check only | T3.2 |

## Must never
- **Forward a request** that failed any check. Errors fail closed.
- **Use the raw path from the agent after authorizing the normalized one.** Authorize and access the same normalized value.
- **Leak `GATEWAY_RESOURCE_SECRET`** or internal error details to agents. Return the `ReasonCode` only.
- **Skip the audit record** for any decision.

**Tests:** `tests/integration/test_gateway.py`, `test_gateway_risk.py`, `test_baseline.py`
