# aimfa/common: shared library

| Module | Responsibility | Task | Status |
|---|---|---|---|
| `models.py` | **Frozen contracts**: every request/response, enum and `ReasonCode` | T0.3 | written; awaiting sign-off |
| `config.py` | `Settings` loaded from `.env` | T0.1 | done |
| `crypto.py` | Ed25519 keys, JWK + RFC 7638 thumbprint, EdDSA JWT sign/verify, `measure()`, `canonical_json()` | T1.1 | todo |
| `dpop.py` | DPoP proof create/verify, `ReplayCache` | T1.2 | todo |
| `policy.py` | Load `policy/*.yaml`, resolve tool → scope target / tier / category, scope matching | T1.4 | todo |
| `db.py` | SQLite schema + repository functions. Security-relevant state changes are single conditional `UPDATE`s: use `consume_nonce`, `activate_agent`, `quarantine_agent`, `clear_quarantine`, `decide_approval`, `consume_approval` rather than the low-level setters | T1.5 | done |

## Rules for this package
- **Pure and synchronous where possible.** No FastAPI imports here, so everything is unit-testable without servers.
- **Raise typed errors** that carry a `ReasonCode`, e.g. `DPoPError(ReasonCode.DPOP_REPLAY)`. Callers map them to HTTP responses.
- **Never** log keys, tokens or secrets.

**Tests:** `tests/unit/test_<module>.py`
