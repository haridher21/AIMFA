# Phase 7: Dashboard (T7.1)

## Task
- `T7.1`: Streamlit dashboard. The code and tests are done. The manual walkthrough of `docs/DEMO.md` happens in the **Live test session**.
- **Not in this PR (manual):** the Live test session, and `T7.2` (demo rehearsals and the backup video).

## What changed

### T7.1: Streamlit dashboard (`aimfa/dashboard/`)
- **`admin_client.py`: `AdminClient`.**
  - The dashboard's **only** data source. It calls the control plane's admin API and returns the `models.py` types.
  - Failures become typed errors: `AdminApiError(status, reason_code)` and `ControlPlaneUnavailable`.
  - The admin key is sent only as a request header, never in `repr` or error text.
  - It refuses a control plane URL that isn't localhost, ignores `HTTP_PROXY` (`trust_env=False`) and never follows redirects.
  - Ids are encoded as one path segment, and `.` and `..` are refused.
  - The TOTP code is checked to be exactly 6 digits before anything is sent.
- **`views.py`:** pure helpers with an injected `now`. They build the token TTL countdown, risk chart data, recent rule hits, approval rows, audit rows and attack result cards.
  - A token is identified only by a truncated `jti`.
  - `redact()` removes every configured secret from displayed text.
  - The audit live tail (`AuditTail`) fetches only new records. It catches up on a long log in one poll and restarts by itself when the chain is reset.
- **`pages/`:** six thin pages that auto-refresh every 2.5 s with `st.fragment(run_every=…)`, so no new dependency:
  - **Agents:** status; clear quarantine; revoke (the kill switch).
  - **Tokens:** TTL countdown; revoke all of an agent's tokens. The contract has no per-token revoke, and the page says so.
  - **Risk:** bar chart and recent rule hits.
  - **Approvals:** pending requests. Approve and Deny both need the human to type the TOTP.
  - **Audit:** live tail plus a **Verify chain** button.
  - **Attack Lab:** A1–A9 and "Run all", with a baseline ↔ AIMFA toggle. A9 shows N/A in baseline mode, the same as `docs/results.md`.
- **`ui.py`:** shared glue for the pages.
  - Friendly errors with no tracebacks or headers. Pydantic errors are shown generically because their text can echo input values.
  - Action results stay on screen after the auto-refresh, so a "wrong code" error doesn't vanish.
  - The fixed repo root is added to `sys.path` so `import attacks` works under `streamlit run`.
- **`scripts/run_demo.py`:** Streamlit now also starts with `--browser.gatherUsageStats false`. It was already bound to `127.0.0.1` and headless.

### Fix: relative directories in `.env` (`aimfa/common/config.py`)
- **Bug:** `.env.example` sets `DATA_DIR=./var` and `KEYS_DIR=./keys`, and those were resolved against the *current folder*. So `python run_demo.py --reset` run from `scripts/` targeted `scripts/var`.
  - `safe_reset` correctly refused to delete it, but the run crashed.
  - Worse, a process started from another folder would silently use a different database and keys.
- **Fix:** relative `data_dir`, `keys_dir` and `policy_dir` are now anchored at the repo root. `tests/unit/test_config.py` covers it.

### Fix: `run_demo.py` start-up order (found in the first real run)
- **Bug:** agents were registered *before* their approver was enrolled. The control plane correctly rejects an agent whose approver doesn't exist yet (422 "unknown approver"), so every registration failed.
- **Fix:** the approver is now enrolled first. `register_agents.py` failures now print the reason code and message.
- **Test:** `tests/unit/test_run_demo.py` checks the order.

### Docs
- `aimfa/dashboard/README.md` maps each page to its endpoints, says how to run the dashboard, and explains the Attack Lab isolation.
- `docs/LEARNING.md` has a new "dashboard in plain English" section and a §5 row.
- `docs/ROADMAP.md`: T7.1 is ticked, with a note that the walkthrough is manual.

## Plain-English summary
Phases 0–6 built the checkpoint and proved it stops attacks, but only from the command line. This phase builds the **guard's control room**: one web page where the human watches and decides.

- **Watch.** You can see which agents exist and whether any is quarantined. You can see which badges (tokens) are alive, with a countdown until each one expires, and how suspicious each agent looks (the risk chart). Every log line appears as it happens.
- **Decide.** When an agent wants to do something risky (like wire money), your phone buzzes and the request shows up on the Approvals page. You approve or deny it by typing the 6-digit code from your authenticator app, and **only here**. The push notification never asks for the code, so a fake notification has nothing to steal. See `docs/LEARNING.md` ("push, then TOTP").
- **Check the log.** The **Verify chain** button re-checks the tamper-evident audit log and points at the exact row that was edited, if any.
- **Show the attacks.** The **Attack Lab** replays the nine attacks in a *separate, throwaway* copy of the system, so the demo can flip between "the old way" and AIMFA without breaking the live demo.

**Why "admin API only"?** The dashboard never opens the database. Every button goes through the same authenticated, audited API, so the console can't become a back door around the checks.

## Tests
- [ ] Tests were written by the test-writer **before** implementation. *This phase used one coder for both tests and code to save tokens.*
- [x] Every automatable Accept bullet has a test:
  - "the admin key is never displayed": tests cover the client `repr`/errors, the rendered pages (via `streamlit.testing.AppTest`) and the page source
  - "uses only the admin API": a test greps the dashboard source for `aimfa.common.db` and `sqlite3`
  - The DEMO.md walkthrough is manual.
- [x] Negative tests:
  - a non-6-digit TOTP is refused before sending
  - a non-localhost control plane URL is refused
  - proxy settings from the environment are ignored
  - `..` and `.` ids are refused
  - the control plane being down shows a friendly error without the key
- [x] `pytest`: 701 passed, 1 skipped, 2 xfailed (52 new tests).
- [x] `ruff check .`, `ruff format --check .` and `bandit -q -ll -r aimfa scripts` are clean.
- [x] `streamlit run aimfa/dashboard/app.py` boots headless on 127.0.0.1 and answers `/_stcore/health`.

## Security checklist
- [x] Never displays `ADMIN_API_KEY`, TOTP seeds or tokens.
- [x] Never approves without a human-typed TOTP code.
- [x] No direct database access.
- [x] No `unsafe_allow_html`. Agent-controlled attack evidence is shown with `st.text`, which renders no markdown.
- [x] Binds to 127.0.0.1. The admin key is only sent to localhost, never through a proxy, and never follows a redirect.
- [x] `security-reviewer` ran: 0 critical, 0 high, 1 medium, 7 low.
  - The medium (the admin key could leak through an `HTTP_PROXY`) is fixed.
  - Five lows are fixed: localhost-only URL, generic pydantic errors, no markdown in attack evidence, Streamlit telemetry off, `sys.path.append` instead of `insert`.
- [x] `/code-review` (medium) found 10 items, and 8 are fixed:
  - the audit tail went stale after a chain reset and was slow on long logs
  - `.`/`..` ids could change the endpoint
  - action messages vanished on auto-refresh
  - A9 showed as "succeeded" in baseline mode
  - `TypeAdapter` was rebuilt on every poll
  - the `(x, True)[1]` idiom
  - raw string status comparisons

**Accepted risks / not fixed:**
- **The typed TOTP stays in its input box** until the approval disappears from the list, which happens on the next refresh. The code is single-use on the server, so it can't be replayed.
- **The Revoke (kill switch) button has no confirmation step.** It is one click by design, for the demo. A mis-click only cancels tokens; the agent re-attests to continue.
- **`st.dataframe(use_container_width=True)` is deprecated** in newer Streamlit, but `width="stretch"` doesn't exist in our minimum version (1.38). Revisit if we pin a newer Streamlit.
- **The dashboard process holds the admin key.** It runs on localhost only, the same as `run_demo.py`. Revisit in T8.1 along with the Phase 6 note about splitting agent-side settings.

## Contracts
- [x] No changes to `aimfa/common/models.py`, `docs/CONTRACTS.md` or `policy/*.yaml`.

## Docs
- [x] ROADMAP T7.1 is ticked. `aimfa/dashboard/README.md` and `docs/LEARNING.md` (§5 and the dashboard section) are updated.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
