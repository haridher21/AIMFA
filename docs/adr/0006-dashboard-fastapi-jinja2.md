# ADR-0006: Dashboard as a plain FastAPI + Jinja2 web app (replacing Streamlit)

- **Status:** accepted
- **Date:** 2026-11-27
- **Deciders:** team

## Context
The T7.1 dashboard was built with Streamlit. It worked, but tabs took 1-4 s to open:
- Streamlit imports each page's libraries the first time the page is opened (pandas/pyarrow ~1.3 s, Altair ~0.8 s, the attacks package ~2.3 s).
- It reruns the whole page script on every visit and streams the result over a websocket.

On a live demo that delay is visible on every tab switch.

## Decision
Rebuild the dashboard as an ordinary web app using what the other services already run on:
- FastAPI and uvicorn serve the pages.
- **Jinja2** templates render the HTML. Jinja2 is the only added dependency, and it was already installed as a Streamlit sub-dependency.
- Our own CSS and about 150 lines of our own JavaScript provide the live refresh and the buttons.

Streamlit and Altair are removed. The port, page names, buttons and admin-API-only data path are unchanged.

## Alternatives considered
- **Keep Streamlit and warm up the imports**: removes the first-visit delay but not the rerun-per-visit cost.
- **A JavaScript framework (React, htmx)**: adds third-party JavaScript we would have to vet. React also needs an npm build step. For six tables and a few buttons, about 150 lines of our own JS is enough.
- **Flask or Django**: a second web framework next to FastAPI, for no gain.

## Consequences
- **Gained:**
  - Pages render in a few milliseconds.
  - There are fewer dependencies (minus Streamlit, Altair and their tree).
  - Tests use FastAPI's `TestClient` like every other service.
- **Must do:** Streamlit used to provide some browser-safety work for us. We now do it ourselves in `aimfa/dashboard/security.py`:
  - A CSRF token on every POST, plus an `Origin` / `Sec-Fetch-Site` check.
  - A Host allow-list against DNS rebinding.
  - A strict Content-Security-Policy and `X-Frame-Options: DENY`.
  - Jinja2 autoescaping, never `|safe`.
- **Accepted risk:** the dashboard has no login, the same as before. Anyone who can reach 127.0.0.1:8501 on the laptop can use it. Approvals still need the approver's TOTP code.
