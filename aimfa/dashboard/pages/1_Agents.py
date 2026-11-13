"""Agents: status list, clear quarantine, and the revoke (kill switch) button."""

from __future__ import annotations

import streamlit as st

from aimfa.common.models import AgentStatus
from aimfa.dashboard import ui


def main() -> None:
    ui.page_setup("Agents")
    client = ui.get_client()

    @st.fragment(run_every=ui.REFRESH_SECONDS)
    def live() -> None:
        ui.show_flash("agents")
        agents = ui.guarded(client.agents)
        if agents is None:
            return
        ui.show_table(
            [
                {
                    "agent": a.agent_id,
                    "role": a.role,
                    "status": a.status.value,
                    "approver": a.approver_id,
                }
                for a in agents
            ],
            "No agents registered.",
        )
        for a in agents:
            c1, c2, c3 = st.columns([3, 1, 1])
            c1.write(f"**{a.agent_id}** ({a.status.value})")
            if a.status is AgentStatus.QUARANTINED and c2.button(
                "Clear quarantine", key=f"cq-{a.agent_id}"
            ):
                ui.act(
                    lambda a=a: client.clear_quarantine(a.agent_id),
                    f"Cleared {a.agent_id}",
                    "agents",
                )
            if c3.button("Revoke (kill switch)", key=f"rv-{a.agent_id}"):
                ui.act(
                    lambda a=a: client.revoke_agent(a.agent_id),
                    f"Revoked all tokens of {a.agent_id}",
                    "agents",
                )

    live()


main()
