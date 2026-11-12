# AIMFA API Contracts

**Status: FROZEN.** The team approved it on 2026-11-12 (ROADMAP T0.3). This file and [`aimfa/common/models.py`](../aimfa/common/models.py) change only through a `contract-change` PR.

The pydantic models in `models.py` are the source of truth for request/response bodies. This file covers the parts code can't express on its own: endpoints, headers, status codes, and which `ReasonCode` each failure returns.

## Conventions
- **Bodies:** all JSON. Unknown fields are rejected with 422 (pydantic `extra="forbid"`).
- **Errors:** every non-2xx body is an `ErrorResponse {reason_code, message, request_id}`.
- **Time:** timestamps are ISO-8601 UTC in bodies; JWT `iat`/`exp` are Unix seconds.
- **Signatures:** all signatures (JWTs, DPoP proofs, attestation evidence) are **EdDSA / Ed25519**. Verifiers MUST pin `algorithms=["EdDSA"]`.
- **Token types:** a token's `token_use` claim (`identity` | `access`) and its `aud` (`aimfa-sts` | `aimfa-gateway`) MUST both be checked. This prevents one token type from being used as the other.
- **Scope strings:** `"<service>:<verb>:<target>"`. See [`policy/roles.yaml`](../policy/roles.yaml) for the grammar and [`policy/actions.yaml`](../policy/actions.yaml) for tools.

### Headers
| Header | Used on | Meaning |
|---|---|---|
| `Authorization: DPoP <access_token>` | gateway `/tool`, CP `/tasks/*`, CP `GET /approvals/{id}` | Access token (sender-constrained) |
| `DPoP: <proof JWT>` | every request that carries an access token, plus CP `/token` | Proof of possession of the agent key (RFC 9449). Header has `typ=dpop+jwt`, `alg=EdDSA`, `jwk=<agent public key>`. Claims are `DPoPProofClaims`. |
| `X-Admin-Key` | CP `/admin/*`, CP `/approvals/{id}/decide` | Admin / dashboard secret (`ADMIN_API_KEY`) |
| `X-Internal-Secret` | CP `/internal/*` | Gateway → control plane secret (`INTERNAL_SERVICE_SECRET`) |
| `X-Gateway-Secret` | all resources endpoints | Gateway → resources secret (`GATEWAY_RESOURCE_SECRET`). Agents never have it. |
| `X-API-Key` | gateway `/tool` in **baseline mode only** | Static master key (`BASELINE_API_KEY`) |
| `X-Request-ID` | all responses | Correlates with the audit log |

### DPoP proof rules (RFC 9449, simplified)
A proof is valid only if **all** of the following hold. Each failure has its own reason code:

| Rule | Reason code on failure |
|---|---|
| It is a compact JWS with header `typ=dpop+jwt`, `alg=EdDSA`, and an embedded public `jwk` | `DPOP_MALFORMED` |
| The signature verifies with that embedded `jwk` | `DPOP_BAD_SIGNATURE` |
| The RFC 7638 thumbprint of the `jwk` equals the token's `cnf.jkt` (or, at `/token`, the thumbprint of the identity credential's `cnf.jwk`) | `DPOP_KEY_MISMATCH` |
| `htm` equals the request method | `DPOP_HTM_MISMATCH` |
| `htu` equals the configured public URL of the endpoint, with no query or fragment | `DPOP_HTU_MISMATCH` |
| `iat` is within `DPOP_MAX_AGE_SECONDS` of now, in either direction | `DPOP_STALE` |
| `jti` has not been seen in the replay window | `DPOP_REPLAY` |
| When an access token is presented, `ath` = base64url(SHA-256(access_token)) | `DPOP_ATH_MISMATCH` |

---

## Control plane: `:8000`

### Public (agent / launcher facing)
| Method & path | Auth | Request → Response | Errors |
|---|---|---|---|
| `GET /health` | none | → `{"status":"ok"}` | |
| `GET /.well-known/jwks.json` | none | → `JWKS` (control-plane signing public key) | |
| `POST /attest/challenge` | none | `AttestationChallengeRequest` → `AttestationChallenge` | 404 `ATTEST_UNKNOWN_AGENT` |
| `POST /attest` | launcher signature inside the body | `AttestationRequest` (JWS of `AttestationEvidence`, signed by launcher key) → `IdentityCredentialResponse` | 401 `ATTEST_UNKNOWN_LAUNCHER` / `ATTEST_BAD_SIGNATURE` / `ATTEST_NONCE_INVALID` / `ATTEST_MEASUREMENT_MISMATCH`; 404 `ATTEST_UNKNOWN_AGENT`; 403 `AGENT_QUARANTINED` |
| `POST /token` | `DPoP` header (proof key = identity `cnf.jwk`) | `TokenRequest` → `TokenResponse` | 401 `STS_IDENTITY_INVALID` / `DPOP_*`; 403 `STS_SCOPE_ESCALATION` / `AGENT_QUARANTINED` |
| `POST /tasks/{task_id}/complete` | `Authorization: DPoP` + `DPoP` | → 204. Revokes that task's token(s). | 401 `TOKEN_*` / `DPOP_*`; 403 if `task_id` ≠ token's task |
| `GET /approvals/{approval_id}` | `Authorization: DPoP` + `DPoP` (must be the same agent + task) | → `ApprovalStatusView` | 404 `APPROVAL_NOT_FOUND` |

**Attestation checks, in order:**
1. Agent exists.
2. Launcher exists and matches the agent's registered `launcher_id`.
3. JWS signature is valid under the launcher key.
4. Nonce exists, was issued for this `agent_id`, is unexpired, and is unused. It is consumed atomically.
5. `measurement == golden_measurement` (constant-time compare).
6. Agent is not quarantined.

On success the control plane issues an identity credential with `cnf.jwk = agent_public_jwk` and sets the agent's status to `active`.

**Token service checks:**
1. The identity credential is valid: `aud=aimfa-sts`, `token_use=identity`, not expired.
2. The DPoP proof is signed by the identity credential's `cnf.jwk`.
3. Every `requested_scope` is covered by the role's `allowed_scopes`.
4. Agent is not quarantined.

On success it issues an access token with TTL `ACCESS_TOKEN_TTL_SECONDS`, a new `task_id` and `jti`, and `cnf.jkt` = thumbprint of the agent key. The token's `jti` is stored for revocation.

### Admin (dashboard / setup scripts), header `X-Admin-Key`
| Method & path | Request → Response |
|---|---|
| `POST /admin/launchers` | `LauncherRegistration` → 201 `LauncherRegistration` |
| `POST /admin/approvers` | `ApproverEnrollmentRequest` → 201 `ApproverEnrollment` (otpauth URI shown **once**) |
| `POST /admin/agents` | `AgentRegistration` → 201 `AgentRecord` |
| `GET /admin/agents` | → `list[AgentRecord]` |
| `POST /admin/agents/{agent_id}/revoke` | → 204. Revokes all of the agent's tokens (kill switch). |
| `POST /admin/agents/{agent_id}/clear-quarantine` | → `AgentRecord` (status → `registered`, risk reset) |
| `GET /admin/tokens` | → `list[ActiveTokenView]` |
| `GET /admin/risk` | → `list[RiskScore]` |
| `GET /admin/approvals?status=pending` | → `list[ApprovalRecord]` |
| `POST /approvals/{approval_id}/decide` | `ApprovalDecisionRequest` → `ApprovalRecord`. Errors: 401 `APPROVAL_INVALID_TOTP`; 409 if already decided / expired. |
| `GET /admin/audit?after_seq=N&limit=M` | → `list[AuditRecord]` |
| `GET /admin/audit/verify` | → `AuditVerifyResult` |
| `POST /admin/reset` | → 204. Demo only: wipes state. Allowed only when `DATA_DIR` is the demo dir. |

Missing or wrong `X-Admin-Key` → 401 `UNAUTHORIZED`.

**Approval decisions:**
- The `approver_id` must equal the approval's assigned approver, and `totp_code` must verify for that approver (pyotp, `valid_window=1`).
- **A TOTP code can be used only once per approver**, which blocks replay of an observed code.
- `approve=false` → `denied`, and a `APPROVAL_DENIED` risk event is recorded.

### Internal (gateway only), header `X-Internal-Secret`
| Method & path | Request → Response |
|---|---|
| `POST /internal/introspect` | `IntrospectRequest` → `IntrospectResponse` (`active=false` + `TOKEN_REVOKED` / `AGENT_QUARANTINED`) |
| `POST /internal/events` | `RiskEvent` → `RiskScore` (the monitor may quarantine + revoke as a side effect) |
| `POST /internal/approvals` | `ApprovalCreate` → 201 `ApprovalRecord` (also sends the ntfy push) |
| `POST /internal/approvals/{approval_id}/consume` | `ApprovalConsumeRequest` → 200 `ApprovalRecord` (status → `used`). Errors: `APPROVAL_STILL_PENDING`, `APPROVAL_DENIED`, `APPROVAL_EXPIRED`, `APPROVAL_ALREADY_USED`, `APPROVAL_MISMATCH` (hash differs), `APPROVAL_NOT_FOUND`. |
| `POST /internal/audit` | `AuditAppend` → `AuditRecord` |

**Action hash:** `sha256( canonical_json({"agent_id", "task_id", "tool", "args"}) )`. Canonical JSON means `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` encoded as UTF-8. The same rule is used for audit record hashing.

---

## Gateway: `:8100`
| Method & path | Auth | Request → Response |
|---|---|---|
| `GET /health` | none | → `{"status":"ok","mode":"aimfa"\|"baseline"}` |
| `POST /tool` | **aimfa:** `Authorization: DPoP` + `DPoP` · **baseline:** `X-API-Key` | `ToolCall` → `ToolCallResponse` |

**Status codes for `POST /tool`:**
| Status | Meaning | Reason codes |
|---|---|---|
| 200 | allowed and executed; `result` holds the resource's response | `OK` |
| 202 | pending human approval; `decision.approval_id` is set. The agent polls `GET /approvals/{id}` on the control plane, then retries the **identical** `ToolCall` with `approval_id`. | `PENDING_APPROVAL` |
| 401 | token or proof problem | `TOKEN_*`, `DPOP_*`, `BASELINE_API_KEY_INVALID` |
| 403 | authorization problem | `SCOPE_DENIED`, `ACTION_FORBIDDEN`, `AGENT_QUARANTINED`, `RATE_LIMITED`, `APPROVAL_*` |
| 422 | bad arguments | `INVALID_ARGUMENTS` |
| 502 | resource failure | `UPSTREAM_ERROR` |

**Pipeline order (aimfa mode).** Each step fails closed and is audited.
1. Parse the `Authorization: DPoP` header (`TOKEN_MISSING`).
2. Verify the access token: EdDSA signature with the JWKS key, `iss`, `aud=aimfa-gateway`, `token_use=access`, `exp` (`TOKEN_INVALID` / `TOKEN_EXPIRED`).
3. Verify the DPoP proof against `cnf.jkt`, `htm=POST`, `htu=GATEWAY_URL/tool`, and `ath` (`DPOP_*`).
4. Introspect: is the token revoked or the agent quarantined? (`TOKEN_REVOKED` / `AGENT_QUARANTINED`)
5. Resolve the tool from `actions.yaml` (`ACTION_FORBIDDEN`), validate its args (`INVALID_ARGUMENTS`), and normalize paths.
6. Scope check: `<service>:<verb>:<target>` against the token's scopes (`SCOPE_DENIED`).
7. Report a `RiskEvent` and receive the `RiskScore`.
8. Apply the tier:
   - `forbidden` → deny
   - `high` → approval needed
   - `medium` with `step_up_required` → approval needed
   - `low`/`medium` → allow
9. If approval is needed:
   - with no `approval_id`, create an approval and return 202
   - with an `approval_id`, consume it with the recomputed action hash
10. Forward to resources with `X-Gateway-Secret` and return 200.

**Baseline mode:** only the `X-API-Key` comparison, then forward. This is intentionally weak; it's what attacks are compared against.

---

## Mock resources: `:8200` (header `X-Gateway-Secret` on every call)
| Method & path | Request → Response |
|---|---|
| `GET /health` | → `{"status":"ok"}` (no secret needed) |
| `GET /files?dir=/expenses` | → `{"dir": str, "entries": [str]}` |
| `GET /files/{path}` | → `{"path": str, "content": str}` |
| `PUT /files/{path}` | `{"content": str}` → `{"path": str, "bytes": int}` |
| `POST /email/send` | `{"to","subject","body"}` → `{"message_id": str}` (appended to `var/outbox.jsonl`) |
| `POST /bank/wire` | `{"to_account","amount","memo"}` → `{"transfer_id": str, "balance": float}` |
| `GET /db/{table}` | → `{"table": str, "rows": [...]}` |
| `DELETE /db/{table}` | → `{"table": str, "deleted": true}` |
| `POST /admin/reset` | → 204. Re-seeds the fake data. |

Missing or wrong `X-Gateway-Secret` → 403 `UNAUTHORIZED`.

### Tool → resource mapping (gateway `proxy.py`)
| Tool | Resource call | Scope target |
|---|---|---|
| `list_files {dir}` | `GET /files?dir=` | normalized `dir` |
| `read_file {path}` | `GET /files/{path}` | normalized `path` |
| `write_file {path, content}` | `PUT /files/{path}` | normalized `path` |
| `send_email {to, subject, body}` | `POST /email/send` | `internal` if the recipient domain is in `internal_email_domains`, else `external` |
| `wire_transfer {to_account, amount, memo}` | `POST /bank/wire` | `*` |
| `query_db {table}` | `GET /db/{table}` | `table` |
| `delete_table {table}` | `DELETE /db/{table}` | `table` |
