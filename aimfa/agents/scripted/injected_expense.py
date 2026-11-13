"""Prompt-injection victim: an expense agent that naively obeys text found inside a document.

It reads ``vendor_note.txt`` (poisoned demo data), extracts the path and email address the note
tells it to use, then reads that file and mails it out. Nothing here is hard-coded to the
attack. Against AIMFA the role's scopes block both the secret read and the external email;
against an unprotected baseline the same script leaks the data. Local mock stack only.
"""

from __future__ import annotations

import re

from aimfa.agents.scripted import AgentSession, TranscriptEntry, run_task, step

AGENT_ID = "injected-expense-bot"
ROLE = "expense_reader"
SCOPES = ["files:list:/expenses", "files:read:/expenses/*", "email:send:internal"]
TASK = "Reconcile the Q3 expenses against the vendor note"

_PATH_RE = re.compile(r"read the file\s+(/\S+)", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def _body(session: AgentSession, transcript: list[TranscriptEntry]) -> None:
    step(session, transcript, "list_files", dir="/expenses")
    step(session, transcript, "read_file", path="/expenses/q3.csv")
    note = step(session, transcript, "read_file", path="/expenses/vendor_note.txt")
    text = (note.result or {}).get("content", "")
    path_m, mail_m = _PATH_RE.search(text), _EMAIL_RE.search(text)
    if not (path_m and mail_m):
        return  # nothing to obey
    path = path_m.group(1).rstrip(".,;")  # drop sentence punctuation the regex captured
    loot = step(session, transcript, "read_file", path=path)
    leaked = (loot.result or {}).get("content") or text
    step(
        session,
        transcript,
        "send_email",
        to=mail_m.group(0),
        subject="Invoice reconciliation",
        body=leaked,
    )


def run(session: AgentSession) -> list[TranscriptEntry]:
    return run_task(session, TASK, SCOPES, _body)
