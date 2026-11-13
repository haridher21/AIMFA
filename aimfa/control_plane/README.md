# aimfa/control_plane: identity, tokens, monitor, approvals, audit (:8000)

This service is the **Policy Decision Point** and the identity provider. Its endpoints are listed in [docs/CONTRACTS.md](../../docs/CONTRACTS.md#control-plane-8000).

| Module | Responsibility | Task |
|---|---|---|
| `app.py` | `create_app(settings)` factory; routers; error → `ErrorResponse` mapping | T2.1 |
| `registry.py` | launchers, agents, approvers (admin API) | T2.1 |
| `attestation.py` | nonce challenge, evidence verification, identity credential issuance, JWKS | T2.2 |
| `sts.py` | identity + DPoP → scoped, short-lived, key-bound access token; task completion | T2.3 |
| `revocation.py` | revoke by jti / task / agent; introspection for the gateway | T2.3 |
| `monitor.py` | `score_event` (pure rules), `RiskMonitor` (stored events, per-contribution linear decay on the injected clock, quarantine + token revoke + audit at the revoke threshold), routes `POST /internal/events` and `GET /admin/risk`. Events are re-stamped with the monitor's own clock | T4.1 |
| `approvals.py` | create (duplicate pending action returns the same approval, no second push) / decide (TOTP, once per approver; 5 wrong codes lock the approval; a deny records an `APPROVAL_DENIED` risk event) / consume (action hash, single use) / expire, plus the agent's status poll and the gateway's `POST /internal/audit` | T3.1, T4.3 |
| `notify.py` | `Notifier` protocol, `NtfyNotifier`, pure `build_notification`. The push has agent, tool, risk and a `DASHBOARD_URL` link only: no args, never a code request. Failures are logged at WARNING and never block an approval. `create_app(settings, *, clock=None, notifier=None)` | T4.3 |
| `state.py` | shared `CPState` (db, audit, policy, signing key, injected clock), admin/internal secret guards | T2.1 |
| `audit.py` | hash-chained append-only log + verify | T1.3 |

## Must never
- **Issue a token** with scopes beyond the role, or without verifying the DPoP proof's key.
- **Return or log** TOTP seeds, private keys or tokens. Audit entries contain token `jti`s only.
- **Accept a nonce or approval twice.** Use atomic DB updates.

**Status:** T4.1-T4.3 done. Approver enrollment: `python scripts/enroll_approver.py <approver_id>` prints the TOTP QR once and saves a PNG under `var/`.

**Accepted risks:** the wrong-code counter is in memory (a restart resets it; the approval expires in minutes anyway). The risk score is recomputed from stored events on each read (fine at prototype scale).

**Tests:** `tests/unit/test_audit.py`, `tests/unit/test_monitor.py`, `tests/integration/test_{admin,attestation,sts,approvals,approval_routes,monitor_api}.py`
