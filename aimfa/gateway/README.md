# aimfa/gateway: the checkpoint (:8100)

This service is the **Policy Enforcement Point**. Every agent tool call goes through `POST /tool`. The ordered pipeline is specified in [docs/CONTRACTS.md](../../docs/CONTRACTS.md#gateway-8100).

| Module | Responsibility | Task |
|---|---|---|
| `app.py` | `create_app(settings, *, control_plane_client=None, resources_http=None, monitor=None, clock=None)`; thin routes; mode switch | T3.1 |
| `cp_client.py` | `ControlPlaneClient` protocol + `HttpControlPlaneClient`: JWKS, introspect, audit, create/consume approval (relative paths, `X-Internal-Secret`) | T3.1 |
| `pipeline.py` | The checks, as small functions in order: token → DPoP → introspect → resolve → scope → risk → tier → approval | T3.1, T4.2 |
| `proxy.py` | tool → resource HTTP call with `X-Gateway-Secret`, using the **normalized** arguments. `TOOL_ROUTES` is the only tool-to-URL mapping; none reaches `/admin/*`. Resource failures become `502 UPSTREAM_ERROR` | T3.1 |
| `baseline.py` | "the old way": static `X-API-Key` check only (still audited) | T3.2 |

**Status:** T3.1 and T3.2 done. The monitor is a stub (`StubMonitor`, score 0) until T4.2; the real one plugs in through the `monitor=` argument.

The decision is audited BEFORE anything is forwarded; if the audit write fails, the call is refused.

## Must never
- **Forward a request** that failed any check. Errors fail closed.
- **Use the raw path from the agent after authorizing the normalized one.** Authorize and access the same normalized value.
- **Leak `GATEWAY_RESOURCE_SECRET`** or internal error details to agents. Return the `ReasonCode` only.
- **Skip the audit record** for any decision.

**Tests:** `tests/integration/test_gateway.py`, `test_gateway_risk.py`, `test_baseline.py`
