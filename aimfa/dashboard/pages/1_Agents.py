"""Agents: status list, clear quarantine, and the revoke (kill switch) button."""

from __future__ import annotations

import streamlit as st

from aimfa.common.models import AgentStatus
from aimfa.dashboard import ui
from aimfa.dashboard.views import AGENT_COLUMNS


def main() -> None:
    ui.page_setup(
        "Agents",
        "smart_toy",
        "Every registered AI agent, its role and its current state. Revoke is the kill switch: "
        "it cancels all of the agent's tokens at once.",
    )
    client = ui.get_client()

    @st.fragment(run_every=ui.REFRESH_SECONDS)
    def live() -> None:
        ui.show_flash("agents")
        agents = ui.guarded(client.agents)
        if agents is None:
            return
        rows = [
            {
                "agent": a.agent_id,
                "role": a.role,
                "status": a.status.value,
                "approver": a.approver_id,
            }
            for a in agents
        ]
        ui.show_table(ui.with_dots(rows, "status"), "No agents registered.", AGENT_COLUMNS)
        if agents:
            st.subheader("Actions")
        for a in agents:
            with st.container(border=True):
                c1, c2, c3 = st.columns([3, 1, 1], vertical_alignment="center")
                with c1:
                    st.markdown(f"**{a.agent_id}** · {a.role}")
                    st.badge(a.status.value, color=ui.STATUS_COLORS.get(a.status.value, "gray"))
                if a.status is AgentStatus.QUARANTINED and c2.button(
                    "Clear quarantine",
                    key=f"cq-{a.agent_id}",
                    icon=":material/lock_open:",
                    help="Let the agent work again after an admin has looked into it.",
                ):
                    ui.act(
                        lambda a=a: client.clear_quarantine(a.agent_id),
                        f"Cleared {a.agent_id}",
                        "agents",
                    )
                if c3.button(
                    "Revoke (kill switch)",
                    key=f"rv-{a.agent_id}",
                    icon=":material/block:",
                    help="Cancel every token this agent holds, immediately.",
                ):
                    ui.act(
                        lambda a=a: client.revoke_agent(a.agent_id),
                        f"Revoked all tokens of {a.agent_id}",
                        "agents",
                    )

    live()


main()
