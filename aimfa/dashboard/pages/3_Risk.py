"""Risk: per-agent score against the step-up / revoke thresholds, plus recent rule hits."""

from __future__ import annotations

import streamlit as st

from aimfa.dashboard import ui
from aimfa.dashboard.views import risk_chart, rule_hits


def main() -> None:
    ui.page_setup("Risk")
    client = ui.get_client()

    @st.fragment(run_every=ui.REFRESH_SECONDS)
    def live() -> None:
        scores = ui.guarded(client.risk)
        if scores is None:
            return
        chart = risk_chart(scores, ui.get_settings())
        st.caption(f"Step-up at {chart['step_up']:g}, revoke + quarantine at {chart['revoke']:g}")
        if chart["scores"]:
            st.bar_chart(chart["scores"])
        else:
            st.info("No risk scores yet.")
        ui.show_table(rule_hits(scores), "No rule hits yet.")

    live()


main()
