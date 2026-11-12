# aimfa/control_plane: identity, tokens, monitor, approvals, audit (:8000)

This service is the **Policy Decision Point** and the identity provider. Its endpoints are listed in [docs/CONTRACTS.md](../../docs/CONTRACTS.md#control-plane-8000).

| Module | Responsibility | Task |
|---|---|---|
| `app.py` | `create_app(settings)` factory; routers; error → `ErrorResponse` mapping | T2.1 |
| `registry.py` | launchers, agents, approvers (admin API) | T2.1 |
| `attestation.py` | nonce challenge, evidence verification, identity credential issuance, JWKS | T2.2 |
| `sts.py` | identity + DPoP → scoped, short-lived, key-bound access token; task completion | T2.3 |
| `revocation.py` | revoke by jti / task / agent; introspection for the gateway | T2.3 |
| `monitor.py` | risk rules, decay, step-up flag, auto-revoke + quarantine | T4.1 |
| `approvals.py` | create / decide (TOTP) / consume (action hash, single use) / expire | T4.3 |
| `notify.py` | ntfy push. Failures are logged, and never block an approval. | T4.3 |
| `audit.py` | hash-chained append-only log + verify | T1.3 |

## Must never
- **Issue a token** with scopes beyond the role, or without verifying the DPoP proof's key.
- **Return or log** TOTP seeds, private keys or tokens. Audit entries contain token `jti`s only.
- **Accept a nonce or approval twice.** Use atomic DB updates.

**Tests:** `tests/unit/test_audit.py`, `tests/unit/test_monitor.py`, `tests/integration/test_{admin,attestation,sts,approvals}.py`
