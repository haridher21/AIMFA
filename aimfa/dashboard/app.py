"""AIMFA dashboard home. Run: streamlit run aimfa/dashboard/app.py (pages are in pages/)."""

from __future__ import annotations

from collections import Counter

import streamlit as st

from aimfa.common.models import AgentStatus
from aimfa.dashboard import ui


def main() -> None:
    ui.page_setup("AIMFA admin console")
    st.write(
        "Admin and approver console. Everything here goes through the control plane's "
        "admin API; this app never reads the database. Use the pages in the sidebar."
    )

    @st.fragment(run_every=ui.REFRESH_SECONDS)
    def overview() -> None:
        agents = ui.guarded(ui.get_client().agents)
        if agents is None:
            return
        counts = Counter(a.status for a in agents)
        cols = st.columns(len(AgentStatus))
        for col, status in zip(cols, AgentStatus, strict=True):
            col.metric(status.value, counts.get(status, 0))

    overview()


main()
