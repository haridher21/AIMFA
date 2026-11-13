"""Push notifications to the approver's phone via ntfy.

The push is only a doorbell. It names the agent, the tool and the risk, and links to OUR
dashboard (``DASHBOARD_URL``, localhost). It never carries the action's arguments and never
asks for a code: the TOTP is typed only in the dashboard, so a spoofed notification has
nothing to phish. A push failure must never block or fail an approval.
"""

from __future__ import annotations

import logging
import re
from typing import Protocol
from urllib.parse import quote

import httpx

from aimfa.common.config import Settings
from aimfa.common.models import ApprovalRecord

logger = logging.getLogger(__name__)

_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]")
_MAX_FIELD = 64


class Notifier(Protocol):
    def send(self, approval: ApprovalRecord) -> None: ...


def _plain(value: str) -> str:
    """Keep ids/tool names to harmless ASCII so they cannot inject headers or fake text."""
    return _UNSAFE.sub("?", value)[:_MAX_FIELD]


def build_notification(approval: ApprovalRecord, dashboard_url: str) -> dict[str, str]:
    """Pure: the title, message and click link for one approval. No args, no secrets."""
    agent, tool = _plain(approval.agent_id), _plain(approval.tool)
    return {
        "title": "AIMFA approval needed",
        "message": (
            f"Agent {agent} wants to run {tool} (risk {approval.risk_score:.0f}). "
            "Open the dashboard to review."
        ),
        "click": dashboard_url,
    }


class NtfyNotifier:
    """POSTs the notification to ``{NTFY_SERVER}/{NTFY_TOPIC}``. Never raises."""

    def __init__(self, settings: Settings, http: httpx.Client) -> None:
        self._settings, self._http = settings, http

    def send(self, approval: ApprovalRecord) -> None:
        s = self._settings
        if not s.ntfy_enabled or not s.ntfy_topic:
            return
        note = build_notification(approval, s.dashboard_url)
        url = f"{s.ntfy_server.rstrip('/')}/{quote(s.ntfy_topic, safe='')}"
        try:
            resp = self._http.post(
                url,
                content=note["message"].encode("utf-8"),
                headers={"Title": note["title"], "Click": note["click"]},
            )
            if resp.status_code >= 300:
                logger.warning("ntfy push rejected (HTTP %s)", resp.status_code)
        except Exception as err:  # best effort; the topic is in the URL, so log only the type
            logger.warning("ntfy push failed (%s)", type(err).__name__)
