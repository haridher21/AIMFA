"""Risk: per-agent score against the step-up / revoke thresholds, plus recent rule hits."""

from __future__ import annotations

from typing import Any

import altair as alt
import streamlit as st

from aimfa.dashboard import ui
from aimfa.dashboard.views import RULE_HIT_COLUMNS, risk_chart, rule_hits

ZONES = ("normal", "step-up", "revoke")
ZONE_COLORS = ("#1f6f9e", "#c8891a", "#ad2f26")


def zone(score: float, step_up: float, revoke: float) -> str:
    return ZONES[2] if score >= revoke else ZONES[1] if score >= step_up else ZONES[0]


def score_chart(chart: dict[str, Any]) -> alt.LayerChart:
    """Bars colored by zone, with dashed lines at the two thresholds."""
    step_up, revoke = chart["step_up"], chart["revoke"]
    data = alt.Data(
        values=[
            {"agent": agent, "score": score, "zone": zone(score, step_up, revoke)}
            for agent, score in chart["scores"].items()
        ]
    )
    top = max([revoke * 1.15, *chart["scores"].values()])
    bars = (
        alt.Chart(data)
        .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
        .encode(
            x=alt.X("agent:N", title=None, axis=alt.Axis(labelAngle=0)),
            y=alt.Y("score:Q", title="risk score", scale=alt.Scale(domain=[0, top])),
            color=alt.Color(
                "zone:N",
                scale=alt.Scale(domain=list(ZONES), range=list(ZONE_COLORS)),
                legend=alt.Legend(title=None, orient="top"),
            ),
            tooltip=["agent:N", alt.Tooltip("score:Q", format=".1f"), "zone:N"],
        )
    )
    lines = alt.Data(
        values=[
            {"y": step_up, "label": f"step-up {step_up:g}", "zone": ZONES[1]},
            {"y": revoke, "label": f"revoke {revoke:g}", "zone": ZONES[2]},
        ]
    )
    rules = alt.Chart(lines).mark_rule(strokeDash=[6, 4], strokeWidth=1.5)
    labels = alt.Chart(lines).mark_text(align="left", dx=4, dy=-6, fontWeight="bold")
    color = alt.Color("zone:N", scale=alt.Scale(domain=list(ZONES), range=list(ZONE_COLORS)))
    overlay = [
        rules.encode(y="y:Q", color=color),
        labels.encode(y="y:Q", text="label:N", color=color, x=alt.value(0)),
    ]
    return alt.layer(bars, *overlay).properties(height=320)


def main() -> None:
    ui.page_setup(
        "Risk",
        "monitoring",
        "How suspicious each agent's behavior looks. Each rule hit adds points, and points fade "
        "over time. Above the step-up line, actions need a human. At the revoke line, the agent "
        "is cut off and quarantined.",
    )
    client = ui.get_client()

    @st.fragment(run_every=ui.REFRESH_SECONDS)
    def live() -> None:
        scores = ui.guarded(client.risk)
        if scores is None:
            return
        chart = risk_chart(scores, ui.get_settings())
        st.caption(f"Step-up at {chart['step_up']:g}, revoke + quarantine at {chart['revoke']:g}")
        if chart["scores"]:
            with st.container(border=True):
                st.altair_chart(score_chart(chart), width="stretch")
        else:
            st.info("No risk scores yet.")
        st.subheader("Recent rule hits")
        ui.show_table(rule_hits(scores), "No rule hits yet.", RULE_HIT_COLUMNS)

    live()


main()
