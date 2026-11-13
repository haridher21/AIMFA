"""Finance agent that pays an approved vendor: the high-risk action needs a human.

Reads the invoice CSV, looks up vendors, and wires money to the first approved one. The wire is
high tier, so the gateway answers 202 and the client waits for a human to approve with a TOTP
code. Approved: executed. Denied or timed out: nothing moves.
"""

from __future__ import annotations

from aimfa.agents.scripted import AgentSession, TranscriptEntry, run_task, step

AGENT_ID = "wire-bot"
ROLE = "finance_ops"
SCOPES = ["files:read:/expenses/*", "db:read:vendors", "bank:wire:*"]
TASK = "Pay the first approved vendor its Q3 invoice"


def _amount_for(csv_text: str, vendor: str) -> float | None:
    """Amount of the first CSV row for ``vendor`` (columns: date,vendor,category,amount)."""
    for line in csv_text.splitlines()[1:]:
        parts = line.split(",")
        if len(parts) >= 4 and parts[1] == vendor:
            try:
                return float(parts[3])
            except ValueError:
                return None
    return None


def _body(session: AgentSession, transcript: list[TranscriptEntry]) -> None:
    csv = step(session, transcript, "read_file", path="/expenses/q3.csv")
    vendors = step(session, transcript, "query_db", table="vendors")
    rows = (vendors.result or {}).get("rows", [])
    chosen = next((v for v in rows if v.get("approved")), None)
    if chosen is None:
        return
    amount = _amount_for((csv.result or {}).get("content", ""), chosen["name"])
    if amount is None:
        return
    step(
        session,
        transcript,
        "wire_transfer",
        to_account=chosen["account"],
        amount=amount,
        memo=f"Q3 invoice {chosen['name']}",
    )


def run(session: AgentSession) -> list[TranscriptEntry]:
    return run_task(session, TASK, SCOPES, _body)
