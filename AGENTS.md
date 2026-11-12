# AGENTS.md — instructions for AI coding agents

This file is the single source of truth for **any** AI agent working in this repo (Claude Code, Codex, Cursor, Copilot…). `CLAUDE.md` imports it. Humans should read it too.

## What this project is
AIMFA ("MFA for AI Agents") is a localhost prototype for a security course. A **zero-trust gateway** checks every tool call an AI agent makes. Each call must pass four independent checks:

1. **What the agent IS.** Attestation: the agent's code, prompt, tool manifest and model are hashed and compared to a registered "golden" value.
2. **What the agent HAS.** A short-lived, scoped access token bound to the agent's private key (DPoP, RFC 9449).
3. **What the agent DOES.** A behavioral risk score; a high score triggers step-up, then revocation and quarantine.
4. **A HUMAN for risky actions.** A push notification, then approval with a TOTP code, bound to the exact action.

Everything runs locally with fake data. Read [docs/LEARNING.md](docs/LEARNING.md) for a plain-English explanation and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design.

## Map
| Service / package | Port | Responsibility |
|---|---|---|
| `aimfa/control_plane` | 8000 | agent registry, attestation, token service (STS), revocation, approvals + ntfy + TOTP, risk monitor, audit chain, admin API |
| `aimfa/gateway` | 8100 | the policy enforcement point; every agent tool call goes here |
| `aimfa/resources` | 8200 | mock company systems (files, email outbox, bank, db); only accepts calls from the gateway |
| `aimfa/dashboard` | 8501 | Streamlit admin and approver console + attack lab |
| `aimfa/agents` | – | launcher (measures + attests), client SDK (DPoP), scripted agents, TAMU AI agent |
| `aimfa/common` | – | **contracts (`models.py`)**, config, crypto, DPoP, policy engine, db |
| `policy/` | – | `roles.yaml` (who may do what), `actions.yaml` (tools, tiers, categories) |
| `attacks/` | – | attack scripts A1–A9; `run_all.py` compares baseline and AIMFA |

## Commands
```bash
# one-time setup
python -m venv .venv
.venv\Scripts\activate            # Windows (PowerShell: .venv\Scripts\Activate.ps1)
source .venv/bin/activate         # macOS/Linux
pip install -e ".[dev]"
copy .env.example .env            # then fill in secrets (cp on macOS/Linux)

# every change
pytest                            # all tests
pytest tests/unit -q              # fast subset
ruff check . && ruff format --check .
bandit -q -ll -r aimfa -c pyproject.toml
```

## How work is organized
- **[docs/ROADMAP.md](docs/ROADMAP.md) is the task board.** Each task has an ID (e.g. `T2.3`), dependencies, files and **acceptance criteria**. Only start a task whose dependencies are checked off.
- **Branches:** one branch per task (`feat/T2.3-sts`), one PR per task, and the PR title starts with the task ID. **Or** use `/build-phase <N>`: one branch per phase (`phase-N-…`), one commit per task.
- **Three-role loop. Each role runs in a separate agent context:**
  1. **test-writer** (`.claude/agents/test-writer.md`): turns the acceptance criteria and `docs/CONTRACTS.md` into failing tests. It does not read the implementation.
  2. **implementer** (`.claude/agents/implementer.md`): makes those tests pass **without editing the tests**.
  3. **security-reviewer** (`.claude/agents/security-reviewer.md`) plus `/code-review`: reviews the diff. The implementer fixes the findings.
- **The PR description includes a plain-English summary** (“what this does, explained to a classmate new to security”). The team learns from these.

## Hard rules
### Contracts and tests
- **`aimfa/common/models.py` and `docs/CONTRACTS.md` are frozen.** Don't change them inside a feature task. If a contract is wrong or missing something, stop and propose a separate `contract-change` PR that explains why.
- **Implementers don't edit tests written by the test-writer.** If a test looks wrong, stop and report it. Never "fix" a test to make it pass.
- **Don't add a dependency without an ADR** in `docs/adr/`. Use what's in `pyproject.toml`.

### Security rules (this is a security project, so violations are bugs)
1. **Never weaken, skip or bypass a security check to make something work.** No `if testing: return True`, no catch-all `except: allow`. Checks fail **closed**: on error, deny.
2. **JWT decoding always pins the algorithm and checks the claims.** Use `algorithms=["EdDSA"]` explicitly. Always verify `aud`, `iss`, `exp` and our `token_use` claim. Never decode with `verify_signature=False` except to read a header before verifying.
3. **Compare secrets, hashes and codes with `hmac.compare_digest`**, never `==`.
4. **Generate randomness with the `secrets` module only.** That covers nonces, `jti` values, ids and TOTP seeds. Never use `random`.
5. **Never log or return secrets.** That includes private keys, tokens, TOTP seeds and API keys. Config secrets are `SecretStr`. Audit records store token `jti`s, never tokens.
6. **Never commit secrets.** `.env`, `keys/` and `var/` are git-ignored. Example values go in `.env.example`.
7. **Normalize file paths before authorization.** Use `posixpath.normpath`, require a leading `/`, and reject anything escaping its root. Authorize the *normalized* path, then use that same normalized path for the actual access.
8. **SQL uses parameterized queries only.** No f-strings in SQL.
9. **The gateway is the only path to resources.** Resources must reject requests without `X-Gateway-Secret`. Agents must never receive that secret.
10. **Every allow, deny or pending decision is written to the audit chain** with a `ReasonCode`.
11. **Validate HTTP inputs with the pydantic models from `models.py`.** Unknown fields are rejected (`extra="forbid"`).
12. **Services bind to `127.0.0.1` only, never `0.0.0.0`.** Nothing should be reachable from the network the laptop is on.

### Code conventions
- **Language:** Python 3.11+ with type hints everywhere, FastAPI + pydantic v2, `httpx` for HTTP.
- **Config:** read through `aimfa.common.config.Settings`. **Don't read `os.environ` directly.**
- **Small pure functions** for the security logic (verify, match, score), kept separate from FastAPI route handlers. This makes them unit-testable without a server.
- **Error responses** use the `ErrorResponse` model and a specific `ReasonCode`.
- **Docstrings:** keep them short. Explain *why* a check exists. This is a teaching codebase.

### Tests
- **Location:** `tests/unit/` (pure functions), `tests/integration/` (FastAPI `TestClient`, services in-process), `tests/e2e/` (full flow).
- **Determinism:** no network calls in unit or integration tests. Mock ntfy and TAMU AI. Use a temp `DATA_DIR`. For time-based logic (TTL, decay, TOTP windows), inject the clock or use short TTLs. Don't `sleep()` for long.
- **Coverage:** every security check needs a **negative test** proving it rejects bad input with the right `ReasonCode`.

## Definition of done (per task)
- All acceptance criteria in ROADMAP have tests, and they pass: `pytest`.
- `ruff check .` is clean, and `bandit` has no new high/medium findings.
- The security reviewer's findings are fixed, or explicitly accepted with a reason in the PR.
- If behavior changed, update the package `README.md` and [docs/LEARNING.md](docs/LEARNING.md).
- Tick the task in `docs/ROADMAP.md` in the same PR.
