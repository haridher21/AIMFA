"""Pure view helpers: turn API models into plain rows for the Streamlit pages.

Why separate: they take ``now`` as a parameter and import no streamlit, so they are
unit-tested without a browser. They also decide what is SAFE to show: tokens are never
shown (only a truncated ``jti``) and ``redact`` scrubs configured secrets from any text.
"""

from __future__ import annotations

import hmac
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from aimfa.common.config import Settings
from aimfa.common.models import (
    ActiveTokenView,
    ApprovalRecord,
    AuditRecord,
    RiskScore,
)

JTI_SHOWN = 8
MIN_REDACT_LEN = 4  # don't "redact" 1-2 char values: it would mangle all text
REDACTED = "[redacted]"


def secret_values(settings: Settings) -> list[str]:
    """Every configured secret, so we can make sure none is ever rendered."""
    secrets_ = (
        settings.admin_api_key,
        settings.internal_service_secret,
        settings.gateway_resource_secret,
        settings.baseline_api_key,
        settings.tamu_ai_api_key,
    )
    return [s.get_secret_value() for s in secrets_ if s.get_secret_value()]


def redact(text: str, secrets_: Iterable[str]) -> str:
    """Replace any secret value inside ``text``. Longest first so overlaps are fully removed."""
    for value in sorted(set(secrets_), key=len, reverse=True):
        if len(value) >= MIN_REDACT_LEN:
            text = text.replace(value, REDACTED)
    return text


def seconds_left(expires_at: datetime, now: datetime) -> int:
    """Whole seconds until expiry, never negative."""
    return max(0, int((expires_at - now).total_seconds()))


def ttl_label(seconds: int) -> str:
    if seconds <= 0:
        return "expired"
    minutes, secs = divmod(seconds, 60)
    return f"{minutes}m {secs:02d}s" if minutes else f"{secs}s"


def token_rows(tokens: Iterable[ActiveTokenView], now: datetime) -> list[dict[str, Any]]:
    """Token table. Only a truncated ``jti`` identifies a token; the token is never known."""
    rows = []
    for tok in tokens:
        left = seconds_left(tok.expires_at, now)
        state = "revoked" if tok.revoked else ("expired" if left == 0 else "active")
        rows.append(
            {
                "jti": tok.jti[:JTI_SHOWN] + "...",
                "agent": tok.agent_id,
                "task": tok.task_id,
                "scopes": ", ".join(tok.scopes),
                "ttl_seconds": left,
                "ttl": ttl_label(left),
                "state": state,
            }
        )
    return rows


def risk_chart(scores: Iterable[RiskScore], settings: Settings) -> dict[str, Any]:
    return {
        "scores": {s.agent_id: s.score for s in scores},
        "step_up": settings.risk_step_up_threshold,
        "revoke": settings.risk_revoke_threshold,
    }


def rule_hits(scores: Iterable[RiskScore], limit: int = 20) -> list[dict[str, Any]]:
    """Most recent rule contributions across agents, newest first."""
    hits = [
        {"agent": s.agent_id, "rule": c.rule, "points": c.points, "at": c.at}
        for s in scores
        for c in s.recent
    ]
    hits.sort(key=lambda h: h["at"], reverse=True)
    return hits[:limit]


def approval_rows(records: Iterable[ApprovalRecord], now: datetime) -> list[dict[str, Any]]:
    return [
        {
            "approval_id": r.approval_id,
            "approver_id": r.approver_id,
            "agent": r.agent_id,
            "tool": r.tool,
            "args": r.args,
            "reason": r.reason.value,
            "risk": r.risk_score,
            "expires_in": ttl_label(seconds_left(r.expires_at, now)),
        }
        for r in records
    ]


def audit_rows(records: Iterable[AuditRecord]) -> list[dict[str, Any]]:
    return [
        {
            "seq": r.seq,
            "time": r.timestamp,
            "component": r.component,
            "actor": r.actor,
            "event": r.event,
            "outcome": str(r.outcome),
            "reason": r.reason_code.value,
        }
        for r in records
    ]


class AuditTail:
    """Remembers the last seen record so each refresh fetches only newer ones.

    Each poll re-fetches the last record it already has (the "anchor"). If that record is
    gone or its hash changed, the chain was reset (e.g. ``run_demo.py --reset``), so the tail
    starts over instead of silently waiting for ``seq`` to catch up. Pages are fetched until
    a short one arrives, so opening the page on a long log jumps straight to the live end.
    """

    def __init__(self, max_rows: int = 500) -> None:
        self.last_seq = -1
        self.records: list[AuditRecord] = []
        self._max = max_rows

    def reset(self) -> None:
        self.last_seq = -1
        self.records = []

    def update(self, new: Iterable[AuditRecord]) -> int:
        added = 0
        for rec in new:
            if rec.seq > self.last_seq:  # ignore anything already seen
                self.records.append(rec)
                self.last_seq = rec.seq
                added += 1
        self.records = self.records[-self._max :]
        return added

    def poll(self, client: Any, limit: int = 500, max_pages: int = 20) -> int:
        added = 0
        for _ in range(max_pages):
            anchor = self.records[-1] if self.records else None
            batch = client.audit(after_seq=anchor.seq - 1 if anchor else -1, limit=limit)
            full_page = len(batch) >= limit
            if anchor is not None:
                head = batch[0] if batch else None
                if (
                    head is None
                    or head.seq != anchor.seq
                    or not hmac.compare_digest(head.hash, anchor.hash)
                ):
                    self.reset()  # chain was reset or replaced: start over from seq 0
                    continue
                batch = batch[1:]
            added += self.update(batch)
            if not full_page:
                break
        return added


# run_all.py reports A9 as N/A in baseline: there is no human-approval step to attack.
NOT_APPLICABLE_IN_BASELINE = ("A9",)


def attack_cards(results: Iterable[Any]) -> list[dict[str, Any]]:
    """One card per ``AttackResult``: did the attack work, and which layer stopped it."""
    return [
        {
            "name": r.name,
            "mode": r.mode,
            "succeeded": r.succeeded,
            "not_applicable": r.mode == "baseline"
            and r.name.startswith(NOT_APPLICABLE_IN_BASELINE),
            "verdict": "ATTACK SUCCEEDED" if r.succeeded else "blocked",
            "blocked_by": r.blocked_by or "-",
            "reason_code": r.reason_code.value if r.reason_code else "-",
            "evidence": r.evidence,
        }
        for r in results
    ]
