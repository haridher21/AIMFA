"""Pure view helpers: turn API models into plain rows for the dashboard templates.

Why separate: they take ``now`` as a parameter and import no web framework, so they are
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


def risk_zone(score: float, step_up: float, revoke: float) -> str:
    """Same ``>=`` boundaries the monitor uses for step-up and quarantine."""
    return "revoke" if score >= revoke else "step-up" if score >= step_up else "normal"


def risk_bars(chart: dict[str, Any]) -> dict[str, Any]:
    """Bar lengths (0-100 %) for the risk chart, scaled so the revoke line is always visible."""
    step_up, revoke = chart["step_up"], chart["revoke"]
    top = max([revoke * 1.15, *chart["scores"].values()]) or 1.0
    return {
        "bars": [
            {
                "agent": agent,
                "score": score,
                "zone": risk_zone(score, step_up, revoke),
                "pct": round(max(0.0, score) / top * 100, 1),
            }
            for agent, score in chart["scores"].items()
        ],
        "step_up": step_up,
        "revoke": revoke,
        "step_pct": round(step_up / top * 100, 1),
        "revoke_pct": round(revoke / top * 100, 1),
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


# Column header labels and hover help for each table: row key -> (label, help).
# Display text only. The row helpers above decide what is safe to show.
ColumnHelp = dict[str, tuple[str, str]]

AGENT_COLUMNS: ColumnHelp = {
    "agent": ("Agent", "The agent's registered id."),
    "role": ("Role", "Its role in policy/roles.yaml. The role caps which scopes it can ever get."),
    "status": (
        "Status",
        "registered = known but not attested yet. active = holds a valid identity credential. "
        "quarantined = risk got too high, so all its tokens were revoked until an admin clears it.",
    ),
    "approver": (
        "Approver",
        "The human who must approve this agent's risky actions with a TOTP code.",
    ),
}

TOKEN_COLUMNS: ColumnHelp = {
    "jti": (
        "Token ID",
        "The token's unique id (jti), cut short. The dashboard never sees the token itself.",
    ),
    "agent": ("Agent", "The agent the token was issued to."),
    "task": ("Task", "The task the token was issued for. A token is scoped to one task."),
    "scopes": (
        "Scopes",
        "Exactly what this token allows, e.g. files:read:/expenses/*. Anything else is denied.",
    ),
    "ttl_seconds": ("Time left", "Seconds until the token expires on its own."),
    "ttl": ("Expires in", "The same countdown, easier to read."),
    "state": (
        "State",
        "active = usable. expired = its time ran out. revoked = cancelled early (task done, "
        "kill switch or quarantine).",
    ),
}

RULE_HIT_COLUMNS: ColumnHelp = {
    "agent": ("Agent", "The agent whose behavior triggered the rule."),
    "rule": (
        "Rule",
        "The behavior rule that fired, e.g. out_of_profile (unusual for its role), "
        "rate_above_limit (too many calls) or exfil_sequence (read a secret, then sent data out).",
    ),
    "points": (
        "Points",
        "How much this hit added to the agent's risk score. Scores decay over time.",
    ),
    "at": ("When", "When the rule fired."),
}

AUDIT_COLUMNS: ColumnHelp = {
    "seq": (
        "#",
        "Position in the hash chain. Each record includes the previous record's hash, so "
        "editing one breaks every record after it.",
    ),
    "time": ("Time", "When the event was recorded."),
    "component": ("Component", "Which service wrote it: control plane, gateway, etc."),
    "actor": ("Actor", "Who did it: an agent id, an approver or the admin."),
    "event": ("Event", "What happened, e.g. a tool call, token issued or approval decided."),
    "outcome": ("Outcome", "allow, deny or pending (waiting for a human)."),
    "reason": ("Reason", "The ReasonCode: the machine-readable 'why' behind the outcome."),
}


# Hover help per attack, keyed by the attack's module name.
ATTACK_HELP = {
    "a1_tampered_agent": "A modified agent build tries to get an identity. Stopped by attestation.",
    "a2_stolen_token": "A thief uses a stolen token without the agent's private key. "
    "Stopped by DPoP.",
    "a3_replay": "A captured request is sent a second time. Stopped by DPoP replay protection.",
    "a4_prompt_injection": "A poisoned document tells the agent to read secrets and email them "
    "out. Stopped by scopes.",
    "a5_unauthorized_wire": "The agent tries a bank wire with no human approval. "
    "Stopped by step-up.",
    "a6_expired_token": "A token is used after its task ended or its time ran out. Stopped by TTL "
    "and revocation.",
    "a7_scope_escalation": "The agent asks for more scopes than its role allows. Stopped by the "
    "token service's policy.",
    "a8_audit_tamper": "Someone edits an audit record in the database. Caught by the hash chain.",
    "a9_fake_approval": "Approval with a wrong TOTP code, or reused for a different amount. "
    "Stopped by TOTP and action binding.",
    "a10_silent_exfil": "Reads payroll from the database and emails it out, staying inside its "
    "scopes. Tests whether the risk monitor notices (a known gap; the human approval still "
    "stands).",
}


def attack_buttons(attacks: Iterable[Any]) -> list[dict[str, Any]]:
    """Label and hover help per attack function, from its module name (e.g. a3_replay)."""
    out = []
    for i, fn in enumerate(attacks):
        module = getattr(fn, "__module__", "").rsplit(".", 1)[-1]
        words = module.split("_", 1)[1].replace("_", " ") if "_" in module else ""
        out.append(
            {"index": i, "label": f"A{i + 1} {words}".strip(), "help": ATTACK_HELP.get(module, "")}
        )
    return out


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
