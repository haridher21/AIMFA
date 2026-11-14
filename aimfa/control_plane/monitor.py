"""Behavioral monitor (factor 3: what the agent DOES).

Stolen or hijacked agents often still hold valid credentials, so we also watch behavior.
Each suspicious event adds risk points; points fade linearly over time. At the step-up
threshold risky actions need a human; at the revoke threshold the agent is quarantined and
all its tokens are revoked.

``score_event`` is a pure function (easy to unit test); ``RiskMonitor`` adds storage,
decay, quarantine and audit; ``make_router`` exposes it over HTTP.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends

from aimfa.common.config import Settings
from aimfa.common.db import Database
from aimfa.common.http import ApiError
from aimfa.common.models import (
    AgentStatus,
    AuditAppend,
    DecisionOutcome,
    EventType,
    ReasonCode,
    RiskContribution,
    RiskEvent,
    RiskScore,
)
from aimfa.common.policy import Policy
from aimfa.control_plane.audit import AuditLog

OUT_OF_PROFILE_POINTS = 50.0
DENIAL_POINTS = 30.0
RATE_POINTS = 20.0
EXFIL_POINTS = 60.0
FAILURE_POINTS = 15.0
APPROVAL_DENIED_POINTS = 25.0
MAX_EVENT_POINTS = OUT_OF_PROFILE_POINTS + RATE_POINTS + EXFIL_POINTS
RATE_WINDOW = timedelta(seconds=60)
# How far back an egress looks for a sensitive read by the SAME AGENT. It is not scoped to
# one task: an agent ends and starts its own tasks, so a task-scoped rule is evaded by
# reading in one task and sending in the next (A10). Two access-token lifetimes of slack.
EXFIL_WINDOW = timedelta(minutes=30)

_TYPE_POINTS: dict[EventType, tuple[str, float]] = {
    EventType.OUT_OF_PROFILE: ("out_of_profile", OUT_OF_PROFILE_POINTS),
    EventType.SCOPE_DENIED: ("scope_denied", DENIAL_POINTS),
    EventType.ACTION_FORBIDDEN: ("action_forbidden", DENIAL_POINTS),
    EventType.RATE_EXCEEDED: ("rate_exceeded", RATE_POINTS),
    EventType.DPOP_FAILURE: ("dpop_failure", FAILURE_POINTS),
    EventType.TOKEN_FAILURE: ("token_failure", FAILURE_POINTS),
    EventType.APPROVAL_DENIED: ("approval_denied", APPROVAL_DENIED_POINTS),
}


# ------------------------------------------------------------------ pure scoring


def _is_sensitive(event: RiskEvent) -> bool:
    return event.event_type is EventType.SENSITIVE_READ or event.details.get("sensitive") is True


def _is_egress(event: RiskEvent) -> bool:
    """Did this action send data out of the company?

    Decided by policy (``egress`` in actions.yaml) and reported by the gateway, not guessed
    from the category here: a wire and an ordinary ``db:read`` are both ``finance``.
    """
    return event.event_type is EventType.EXTERNAL_EGRESS or event.details.get("egress") is True


def score_event(
    event: RiskEvent,
    *,
    history: Sequence[RiskEvent],
    profile: Iterable[str],
    rate_limit_per_minute: int,
) -> list[RiskContribution]:
    """Risk points ONE new event earns, given the agent's EARLIER events.

    Why each rule exists: touching things outside the role's normal profile, being refused,
    calling too fast, failing proof checks, or a human saying "no" all look like a
    compromised agent; reading a secret and then sending data out looks like exfiltration.
    """
    at = event.timestamp
    found: list[tuple[str, float]] = []

    category = event.details.get("category")
    if event.event_type is EventType.OUT_OF_PROFILE or (
        isinstance(category, str) and category not in set(profile)
    ):
        found.append(_TYPE_POINTS[EventType.OUT_OF_PROFILE])  # at most once per event
    if event.event_type in _TYPE_POINTS and event.event_type is not EventType.OUT_OF_PROFILE:
        found.append(_TYPE_POINTS[event.event_type])

    recent = 0
    for h in reversed(history):  # newest first: stop as soon as we leave the 60 s window
        age = at - h.timestamp
        if age >= RATE_WINDOW:
            break
        recent += age >= timedelta(0)
    if recent + 1 > rate_limit_per_minute:
        found.append(("rate_above_limit", RATE_POINTS))

    # Per agent, within EXFIL_WINDOW, and the sensitive read must come first. Newest first,
    # so we stop as soon as we leave the window.
    if _is_egress(event):
        for h in reversed(history):
            if at - h.timestamp > EXFIL_WINDOW:
                break
            if h.timestamp <= at and _is_sensitive(h):
                found.append(("exfil_sequence", EXFIL_POINTS))
                break

    return [RiskContribution(rule=rule, points=pts, at=at) for rule, pts in found]


class _Prefix(Sequence[RiskEvent]):
    """The first ``n`` events of a list, without copying it (avoids quadratic copying)."""

    def __init__(self, events: Sequence[RiskEvent], n: int) -> None:
        self._events, self._n = events, n

    def __len__(self) -> int:
        return self._n

    def __getitem__(self, i):  # noqa: ANN001, ANN204
        if isinstance(i, slice):
            return [self[j] for j in range(*i.indices(self._n))]
        if not -self._n <= i < self._n:
            raise IndexError(i)
        return self._events[i if i >= 0 else self._n + i]


def decayed(contribs: Iterable[RiskContribution], now: datetime, per_minute: float) -> float:
    """Total score now: each contribution fades linearly and never goes below zero."""
    total = 0.0
    for c in contribs:
        age_min = max((now - c.at).total_seconds(), 0.0) / 60
        total += max(c.points - per_minute * age_min, 0.0)
    return total


# ------------------------------------------------------------------ stateful monitor


class RiskMonitor:
    """Stores events, computes the decayed score, and quarantines at the revoke threshold."""

    def __init__(
        self,
        *,
        db: Database,
        policy: Policy,
        settings: Settings,
        audit_log: AuditLog,
        clock: Callable[[], datetime],
    ) -> None:
        self._db, self._policy, self._settings = db, policy, settings
        self._audit, self._clock = audit_log, clock

    def _horizon(self, now: datetime) -> datetime | None:
        """Events older than this can no longer add points (None = decay off, keep all).

        The biggest single event is worth 130 points (50 + 20 + 60), so after
        ``130 / decay`` minutes it has faded to zero. Bounding what we load keeps the work
        small however long an agent has existed.

        We also never load less than ``EXFIL_WINDOW``: a faded-to-zero sensitive read still
        has to be visible to an egress that arrives later, or the exfil rule would go quiet
        again for exactly the slow attacker it is meant to catch.
        """
        decay = self._settings.risk_decay_per_minute
        if decay <= 0:
            return None
        return now - max(timedelta(minutes=MAX_EVENT_POINTS / decay), EXFIL_WINDOW)

    def _contributions(self, agent_id: str, now: datetime) -> list[RiskContribution]:
        agent = self._db.get_agent(agent_id)
        if agent is None:
            raise LookupError("unknown agent")
        role = self._policy.role(agent.role)  # unknown role raises: fail closed
        events = self._db.list_risk_events(agent_id, since=self._horizon(now))
        out: list[RiskContribution] = []
        for i, ev in enumerate(events):
            out += score_event(
                ev,
                history=_Prefix(events, i),
                profile=role.profile,
                rate_limit_per_minute=role.rate_limit_per_minute,
            )
        return out

    def _view(self, agent_id: str, now: datetime) -> RiskScore:
        contribs = self._contributions(agent_id, now)
        agent = self._db.get_agent(agent_id)
        if agent is None:
            raise LookupError("unknown agent")
        score = decayed(contribs, now, self._settings.risk_decay_per_minute)
        return RiskScore(
            agent_id=agent_id,
            score=score,
            status=agent.status,
            step_up_required=score >= self._settings.risk_step_up_threshold,
            recent=[c for c in contribs if c.points > 0][-10:],
        )

    def current(self, agent_id: str) -> RiskScore:
        return self._view(agent_id, self._clock())

    def record(self, event: RiskEvent) -> RiskScore:
        """Store one event (stamped with OUR clock, not the sender's) and re-score."""
        now = self._clock()
        agent = self._db.get_agent(event.agent_id)
        if agent is None:
            raise LookupError("unknown agent")
        if agent.status is AgentStatus.QUARANTINED:
            # Already contained: storing more events would only let a noisy caller grow the DB.
            return self._view(event.agent_id, now)
        self._db.add_risk_event(event.model_copy(update={"timestamp": now}))
        view = self._view(event.agent_id, now)
        if view.score >= self._settings.risk_revoke_threshold and (
            view.status is not AgentStatus.QUARANTINED
        ):
            self._quarantine(event.agent_id, view.score, now)
            view = self._view(event.agent_id, now)
        return view

    def _quarantine(self, agent_id: str, score: float, now: datetime) -> None:
        """Kill switch: tokens revoked and agent quarantined in one transaction, then audited."""
        revoked = self._db.quarantine_agent(agent_id, at=now)
        self._audit.append(
            AuditAppend(
                component="control_plane",
                actor="system",
                event="monitor.quarantined",
                outcome=DecisionOutcome.DENY,
                reason_code=ReasonCode.AGENT_QUARANTINED,
                details={"agent_id": agent_id, "score": round(score, 1), "tokens_revoked": revoked},
            )
        )

    def reset(self, agent_id: str) -> None:
        """Forget the agent's history (used when an admin clears a quarantine)."""
        self._db.delete_risk_events(agent_id)


# ------------------------------------------------------------------ routes


def make_router(
    db: Database,
    monitor: RiskMonitor,
    require_admin: Callable[..., None],
    require_internal: Callable[..., None],
) -> APIRouter:
    router = APIRouter()

    @router.post("/internal/events", dependencies=[Depends(require_internal)])
    def post_event(event: RiskEvent) -> RiskScore:
        if db.get_agent(event.agent_id) is None:
            raise ApiError(404, ReasonCode.ATTEST_UNKNOWN_AGENT, "unknown agent")
        return monitor.record(event)

    @router.get("/admin/risk", dependencies=[Depends(require_admin)])
    def list_risk() -> list[RiskScore]:
        return [monitor.current(a.agent_id) for a in db.list_agents()]

    return router
