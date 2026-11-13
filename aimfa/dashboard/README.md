# aimfa/dashboard: admin + approver console (:8501)

A Streamlit app, and the **stage for the live demo**. It talks to the control plane **only** through the admin API (`X-Admin-Key`), never to the DB (a test greps the source for `aimfa.common.db` / `sqlite3`).

| Page (`pages/`) | Shows | Admin endpoints used |
|---|---|---|
| `app.py` (home) | agent counts by status | `GET /admin/agents` |
| 1 Agents | status list; **Clear quarantine**; **Revoke (kill switch)** | `GET /admin/agents`, `POST /admin/agents/{id}/clear-quarantine`, `POST /admin/agents/{id}/revoke` |
| 2 Tokens | active tokens, TTL countdown (truncated `jti` only); revoke = kill switch for that agent (the contract has no per-token revoke) | `GET /admin/tokens`, `POST /admin/agents/{id}/revoke` |
| 3 Risk | per-agent score bar chart, step-up/revoke thresholds, recent rule hits | `GET /admin/risk` |
| 4 Approvals | pending approvals (agent, tool, args, risk, expires-in); approve/deny each needs a typed 6-digit TOTP | `GET /admin/approvals?status=pending`, `POST /approvals/{id}/decide` |
| 5 Audit | live tail (only fetches `after_seq`), **Verify chain** (ok / first_bad_seq) | `GET /admin/audit`, `GET /admin/audit/verify` |
| 6 Attack Lab | mode toggle aimfa/baseline, A1-A9 + Run all, result cards | none (see below) |

Live pages refresh every ~2.5 s with `st.fragment(run_every=...)`.

**Attack Lab isolation:** attacks run through the `attacks` package in their OWN in-process temp stack (temp dir, random secrets, fake data). They never touch the live services shown on the other pages. `ui.ensure_repo_root_on_path()` adds the repo root to `sys.path` so `import attacks` works under `streamlit run`.

## Layout
- `admin_client.py`: `AdminClient` (httpx, typed models, `AdminApiError`, `ControlPlaneUnavailable`, TOTP format check). Pure, no streamlit.
- `views.py`: pure row/chart helpers with injected `now`, `AuditTail`, `redact()`.
- `ui.py`: thin streamlit glue (cached client, friendly errors).

## Must never
- **Display `ADMIN_API_KEY`**, TOTP seeds or tokens (the key only lives in the client's request header; `repr()` and errors omit it; `redact()` scrubs configured secrets from rendered text).
- **Approve or deny without a TOTP code** typed by the human (client rejects non-6-digit codes before sending).

If the control plane is down, pages show a friendly warning instead of a traceback.

**Run:** `streamlit run aimfa/dashboard/app.py` from the repo root. Normally `scripts/run_demo.py` starts it.

**Status:** T7.1 done.
