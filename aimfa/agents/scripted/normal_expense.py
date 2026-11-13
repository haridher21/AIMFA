"""The well-behaved agent: summarize the Q3 expenses and email the total to finance.

Demonstrates the baseline: every call is inside the role's scopes, so every call is allowed.
"""

from __future__ import annotations

from aimfa.agents.scripted import AgentSession, TranscriptEntry, csv_total, run_task, step

AGENT_ID = "expense-bot"
ROLE = "expense_reader"
SCOPES = ["files:list:/expenses", "files:read:/expenses/*", "email:send:internal"]
TASK = "Summarize the Q3 expense report and email the total to finance"


def _body(session: AgentSession, transcript: list[TranscriptEntry]) -> None:
    step(session, transcript, "list_files", dir="/expenses")
    read = step(session, transcript, "read_file", path="/expenses/q3.csv")
    total = csv_total((read.result or {}).get("content", ""))
    step(
        session,
        transcript,
        "send_email",
        to="finance@acme.test",
        subject="Q3 expense summary",
        body=f"Q3 expenses total: {total:.2f}",
    )


def run(session: AgentSession) -> list[TranscriptEntry]:
    return run_task(session, TASK, SCOPES, _body)
