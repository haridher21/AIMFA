"""Shared pieces for the deterministic scripted agents (no LLM, no randomness).

A scripted agent is a fixed list of tool calls. It only needs three methods from its session
(``AgentSession``), so the same script can run through the AIMFA ``AgentClient`` or, later,
through an unprotected baseline client, and the transcripts can be compared side by side.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, NamedTuple, Protocol

from aimfa.agents.client import AimfaError, ApprovalTimeout
from aimfa.common.models import DecisionOutcome, ToolCallResponse


class TranscriptEntry(NamedTuple):
    """What happened to one tool call. ``decision`` is allow, deny, pending or error."""

    tool: str
    decision: str
    reason_code: str
    result: dict[str, Any] | None


class AgentSession(Protocol):
    """The only surface a scripted agent may use."""

    def start_task(self, description: str, scopes: list[str]) -> Any: ...

    def call(self, tool: str, /, **args: Any) -> ToolCallResponse: ...

    def complete_task(self) -> None: ...


def step(
    session: AgentSession, transcript: list[TranscriptEntry], tool: str, **args: Any
) -> TranscriptEntry:
    """Call one tool and record the outcome. A denial does not stop the agent.

    Why: attack transcripts are only interesting if the agent keeps trying after it is refused.
    """
    try:
        resp = session.call(tool, **args)
        outcome = resp.decision.outcome
        entry = TranscriptEntry(
            tool,
            outcome.value,
            resp.decision.reason_code.value,
            resp.result if outcome is DecisionOutcome.ALLOW else None,
        )
    except ApprovalTimeout as exc:
        entry = TranscriptEntry(tool, "pending", exc.reason_code.value, None)
    except AimfaError as exc:
        entry = TranscriptEntry(tool, "deny", exc.reason_code.value, None)
    transcript.append(entry)
    return entry


def run_task(
    session: AgentSession,
    task: str,
    scopes: list[str],
    body: Callable[[AgentSession, list[TranscriptEntry]], None],
) -> list[TranscriptEntry]:
    """start_task, run ``body(session, transcript)``, then always complete_task."""
    transcript: list[TranscriptEntry] = []
    session.start_task(task, scopes)
    try:
        body(session, transcript)
    finally:
        try:
            session.complete_task()
        except AimfaError:
            pass  # best effort: the token also expires on its own
    return transcript


def csv_total(content: str) -> float:
    """Sum the ``amount`` column of a simple CSV (header row first)."""
    lines = [ln for ln in content.strip().splitlines() if ln.strip()]
    if not lines:
        return 0.0
    cols = lines[0].split(",")
    idx = cols.index("amount") if "amount" in cols else len(cols) - 1
    total = 0.0
    for ln in lines[1:]:
        try:
            total += float(ln.split(",")[idx])
        except (ValueError, IndexError):
            continue
    return round(total, 2)
