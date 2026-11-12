# AIMFA Threat Model

**Status:** skeleton. It is finalized in ROADMAP **T8.2**. Update it whenever a design decision changes a mitigation.

**Method:** STRIDE per component, then a mapping from concrete attacks (A1–A9) to mitigations. References: OWASP Top 10 for Agentic Applications 2026 (ASI02 Tool Misuse, ASI03 Identity & Privilege Abuse, ASI10 Rogue Agents) and OWASP Top 10 for LLM Applications (LLM01 Prompt Injection, LLM06 Excessive Agency).

## 1. Assets
| Asset | Why it matters |
|---|---|
| Engineering secrets (`/engineering/secrets.env`) | Confidentiality: the target of exfiltration |
| Company money (bank) and data (db tables) | Integrity / availability: wire transfer, table deletion |
| Control-plane signing key | Anyone holding it can mint tokens for any agent |
| Launcher key | Anyone holding it can attest a tampered agent |
| Agent instance private keys | Can use that agent's tokens until they expire |
| Approver TOTP seeds | Can approve risky actions |
| Audit log | Accountability; attackers want to erase their tracks |

## 2. Actors
| Actor | Capability |
|---|---|
| **External attacker (passive)** | Can read leaked logs or network traffic, and so obtain tokens or captured requests |
| **Content attacker** | Can plant text the agent will read (a poisoned document): **prompt injection** |
| **Supply-chain / insider attacker** | Can modify an agent's code, prompt or tool manifest at rest |
| **Hijacked agent** | A legitimate agent following an attacker's instructions. It holds a valid identity, key and token. |
| **Malicious local process** | Runs on the same machine. It can call the services but holds no secrets. |

## 3. Assumptions (explicitly trusted)
- **The launcher, the control plane and their keys are not compromised** (ADR-0003). In production, hardware attestation (TPM/TEE) and SPIRE would harden this.
- **The gateway is the only network path to resources.** Agents don't know `GATEWAY_RESOURCE_SECRET`. In production this is enforced with network policy.
- **The human approver's phone and authenticator are not compromised.**
- **Localhost:** we don't use TLS or mTLS. Traffic sniffing is modeled as "the attacker obtains a token / request" (A2, A3) instead.

## 4. STRIDE per component (fill in during T8.2)
| Component | **S**poofing | **T**ampering | **R**epudiation | **I**nfo disclosure | **D**oS | **E**levation |
|---|---|---|---|---|---|---|
| Control plane / attestation | Fake agent → launcher signature + nonce + measurement | Modified agent → measurement | Audit chain | Signing key on disk (`keys/`, git-ignored) | Out of scope | – |
| Control plane / STS | Stolen identity token → DPoP on `/token` | Token claims → EdDSA signature | Audit | Tokens never logged (`jti` only) | – | Scope escalation → `role_permits` |
| Gateway | Stolen access token → DPoP | Request replay → `jti` cache + `iat` window | Audit with reason codes | Errors reveal only reason codes | Rate limit + monitor | Out-of-scope / forbidden tool → scope + tier |
| Approvals | Fake approver → TOTP + approver id | Approval reused for another action → action hash | Audit (`approver:<id>`) | Push contains no secrets. TOTP seeds sit in plaintext in `var/aimfa.db` (git-ignored); accepted, since TOTP needs the raw seed and a local attacker with disk access is out of scope | Approval spam → out of scope | – |
| Audit log | – | Edit / delete / reorder → hash chain | – | – | – | – |
| Resources | Direct access bypassing the gateway → gateway secret | Path traversal → normalize + re-check | – | – | – | – |

## 5. Attack → mitigation mapping (the evaluation)
| # | Attack (OWASP ref) | Attacker | Baseline result | AIMFA control(s) | Expected reason code |
|---|---|---|---|---|---|
| A1 | Tampered agent prompt/code | supply chain | runs with full key | attestation | `ATTEST_MEASUREMENT_MISMATCH` |
| A2 | Stolen access token reused (ASI03) | passive | works | DPoP key binding | `DPOP_KEY_MISMATCH` / `DPOP_MISSING` |
| A3 | Replayed captured request | passive | works | DPoP `jti` cache | `DPOP_REPLAY` |
| A4 | Prompt injection → read secrets + email out (LLM01, ASI02) | content | exfiltrates | scope, monitor (out-of-profile, exfil), step-up, quarantine | `SCOPE_DENIED`, then `PENDING_APPROVAL` / `AGENT_QUARANTINED` |
| A5 | Unauthorized wire transfer (LLM06) | hijacked agent | works | high tier → human step-up, deny | `APPROVAL_DENIED` |
| A6 | Expired / finished-task token | passive | key never expires | TTL + revocation | `TOKEN_EXPIRED` / `TOKEN_REVOKED` |
| A7 | Scope escalation at token request | hijacked agent | n/a (key is all-powerful) | STS role policy | `STS_SCOPE_ESCALATION` |
| A8 | Audit tampering | insider | undetected | hash chain | `AUDIT_CHAIN_BROKEN` |
| A9 | Approval without TOTP / reused for different args | local process | n/a | TOTP + action hash + single use | `APPROVAL_INVALID_TOTP` / `APPROVAL_MISMATCH` |

## 6. Residual risks / limitations (keep honest)
- **In-scope misuse.** An injected agent can still misuse what it is allowed to do, for example write a misleading expense summary. AIMFA *contains* prompt injection; it doesn't prevent it.
- **Simulated attestation.** A compromised launcher defeats factor 1.
- **Heuristic monitoring.** It has false positives and false negatives. Thresholds are hand-tuned.
- **Approval fatigue.** Humans may rubber-stamp requests. We keep the high tier rare, and the push shows the tool and the risk.
- **Shared-secret service auth and no TLS.** Acceptable for localhost only.
- **In-memory replay cache.** It is lost on gateway restart. This is mitigated by the 60-second `iat` window.
- **Bypass via fresh tasks.** A hijacked agent could request a fresh task token. The monitor's score is per **agent**, not per task, so its risk carries over.
