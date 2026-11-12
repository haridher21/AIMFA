# aimfa/dashboard: admin + approver console (:8501)

This is a Streamlit app, and the **stage for the live demo**. It talks to the control plane **only** through the admin API, never to the DB directly.

| Page | Shows | Task |
|---|---|---|
| Agents | registered / active / quarantined; clear quarantine | T7.1 |
| Tokens | active tokens with TTL countdown; revoke button | T7.1 |
| Risk | per-agent risk score chart; recent rule hits | T7.1 |
| Approvals | pending approvals: agent, tool, args, risk; approve/deny + TOTP field | T7.1 |
| Audit | live tail; **Verify chain** button | T7.1 |
| Attack Lab | buttons for A1–A9; Baseline ↔ AIMFA toggle; result cards | T7.1 |

## Must never
- **Display `ADMIN_API_KEY`**, TOTP seeds or tokens.
- **Approve without a TOTP code** typed by the human.

**Run:** `streamlit run aimfa/dashboard/app.py`. Normally `scripts/run_demo.py` starts it.
