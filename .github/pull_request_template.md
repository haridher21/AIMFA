## Task
`T?.?` — <title from docs/ROADMAP.md>

## What changed
-

## Plain-English summary
<!-- Explain this change to a classmate who is new to security. What does it protect against, and how? Link to docs/LEARNING.md terms. -->

## Tests
- [ ] Tests were written by the test-writer **before** implementation, and the implementer did not edit them
- [ ] Every Accept bullet in ROADMAP has a test
- [ ] Each new security check has a negative test asserting the specific `ReasonCode`
- [ ] `pytest`, `ruff check .`, `ruff format --check .` and `bandit -ll` all pass locally

## Security checklist
- [ ] JWT decode pins `EdDSA` and checks `aud` / `iss` / `exp` / `token_use`
- [ ] Secrets compared with `hmac.compare_digest`; randomness from `secrets`
- [ ] No secrets, tokens or keys in logs, responses, audit details or the diff
- [ ] Inputs validated with `models.py`; paths normalized before authorization
- [ ] Fails closed; every decision audited with a `ReasonCode`
- [ ] `/security-review` (or the `security-reviewer` subagent) has run. Findings fixed, or accepted below:

**Accepted risks (if any):**

## Contracts
- [ ] No changes to `aimfa/common/models.py`, `docs/CONTRACTS.md` or `policy/*.yaml`. **If changed, this must be a `contract-change` PR explaining why.**

## Docs
- [ ] ROADMAP task ticked · package README updated · LEARNING.md updated (if a new concept appeared)
