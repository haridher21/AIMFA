# ADR-0004: SQLite for all control-plane state

- **Status:** accepted
- **Date:** 2026-11-10
- **Deciders:** team

## Context
We need persistent state for the registry, nonces, tokens, approvals, risk events and audit records. We need it with zero setup on Windows and macOS.

## Decision
Use **SQLite** (the standard library `sqlite3` module) in `var/aimfa.db`:
- WAL mode
- one connection per operation
- parameterized queries only
- atomic single-statement updates for "consume once" operations (nonces, approvals)

## Alternatives considered
- **Postgres.** Needs a server or Docker. Unnecessary at our scale.
- **In-memory dicts.** No persistence across restarts, which the demo and dashboard need.
- **An ORM (SQLAlchemy/SQLModel).** An extra dependency and an extra thing to learn. The schema is small.

## Consequences
- **Gained:** simple, inspectable files; trivial reset (`--reset` deletes `var/`).
- **Limitation:** single-host only, which is fine for localhost.
