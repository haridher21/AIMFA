# aimfa/dashboard: admin + approver console (:8501)

A small FastAPI web app (server-rendered HTML, our own CSS and JS; see [ADR 0006](../../docs/adr/0006-dashboard-fastapi-jinja2.md)), and the **stage for the live demo**. It talks to the control plane **only** through the admin API (`X-Admin-Key`), never to the DB (a test greps the source for `aimfa.common.db` / `sqlite3`). The admin key stays on the server; the browser never sees it.

| Page | Shows | Admin endpoints used |
|---|---|---|
| `/` Home | agent counts by status, the four checks | `GET /admin/agents` |
| `/agents` | status table; **Clear quarantine**; **Revoke (kill switch)** | `GET /admin/agents`, `POST /admin/agents/{id}/clear-quarantine`, `POST /admin/agents/{id}/revoke` |
| `/tokens` | active tokens, TTL bar (truncated `jti` only); revoke = kill switch for that agent (the contract has no per-token revoke) | `GET /admin/tokens`, `POST /admin/agents/{id}/revoke` |
| `/risk` | per-agent score bars colored by zone, dashed step-up/revoke lines, recent rule hits | `GET /admin/risk` |
| `/approvals` | pending approvals (agent, tool, args, risk, expires-in); approve/deny each needs a typed 6-digit TOTP | `GET /admin/approvals?status=pending`, `POST /approvals/{id}/decide` |
| `/audit` | live tail (only fetches `after_seq`), **Verify chain** (ok / first_bad_seq) | `GET /admin/audit`, `GET /admin/audit/verify` |
| `/attack-lab` | mode toggle aimfa/baseline, one button per attack + Run all, result cards | none (see below) |

**How a page works:**
1. The route renders the whole page once.
2. `static/app.js` re-fetches only the live part (`GET /partials/<name>`) every 2.5 s and swaps it in. Text typed in the TOTP box survives the swap.
3. Buttons `POST` JSON to `/api/...`. The answer shows as a toast, and the live part refreshes right away.
4. Column header labels and hover help are plain dicts in `views.py` (`AGENT_COLUMNS`, `TOKEN_COLUMNS`, …).

**Attack Lab isolation:** attacks run through the `attacks` package in their OWN in-process temp stack (temp dir, random secrets, fake data). They never touch the live services shown on the other pages. Runs are serialized (one at a time). The attacks package is imported in the background at startup, so the page opens fast.

## Layout
- `admin_client.py`: `AdminClient` (httpx, typed models, `AdminApiError`, `ControlPlaneUnavailable`, TOTP format check). Pure.
- `views.py`: pure row/chart helpers with injected `now`, `AuditTail`, `redact()`, column help text.
- `security.py`: CSRF check, security headers, Host allow-list, safe error text. Pure.
- `app.py`: `create_app()` / `app_factory()`, the routes. `templates/` (Jinja2, autoescaped) and `static/` (CSS + JS).

## Browser safety (what a normal web app must do itself)
- **CSRF:** every `POST` needs the per-process token from the page's `<meta name="csrf-token">` in an `X-CSRF-Token` header. If the browser sends `Origin` / `Sec-Fetch-Site`, they must be ours. Another website can't read the token or set that header, so it can't press our buttons.
- **Host allow-list:** only `127.0.0.1` / `localhost` (blocks DNS rebinding).
- **Headers:** a strict Content-Security-Policy (our own scripts and styles only, no framing), `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `no-store`.
- **Escaping:** Jinja2 autoescapes every value; never use `|safe`. Toasts use `textContent`.
- **Inputs:** request bodies are pydantic models with `extra="forbid"`. The approver id for a decision is looked up server-side, never taken from the browser.

## Must never
- **Display `ADMIN_API_KEY`**, TOTP seeds or tokens. The key only lives in the client's request header; `repr()` and errors omit it; `redact()` scrubs configured secrets from rendered text.
- **Approve or deny without a TOTP code** typed by the human. The client rejects non-6-digit codes before sending.

If the control plane is down, pages show a friendly warning instead of an error page.

**Run:** `uvicorn aimfa.dashboard.app:app_factory --factory --host 127.0.0.1 --port 8501` from the repo root. Normally `scripts/run_demo.py` (or `scripts/demo_autoplay.py`) starts it.

**Design prototype:** [`design/decision-console.html`](../../design/README.md) is a static mockup of a decision-trace view and a richer approval card. It is a spec, not code: nothing imports it.

**Status:** T7.1 done; moved from Streamlit to FastAPI + Jinja2 (ADR 0006).
