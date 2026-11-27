"""AIMFA dashboard home. Run: streamlit run aimfa/dashboard/app.py (pages are in pages/)."""

from __future__ import annotations

from collections import Counter

import streamlit as st

from aimfa.common.models import AgentStatus
from aimfa.dashboard import ui

STATUS_CARDS = {
    AgentStatus.REGISTERED: ("app_registration", "Known, but not attested yet."),
    AgentStatus.ACTIVE: ("verified", "Attested: holds a valid identity credential."),
    AgentStatus.QUARANTINED: (
        "gpp_bad",
        "Risk too high. All tokens revoked until an admin clears it.",
    ),
}

# The four independent checks every tool call must pass (see docs/LEARNING.md).
CHECKS = (
    (
        "fingerprint",
        "What the agent IS",
        "Its code, prompt, tools and model are hashed and must "
        "match the registered 'golden' value (attestation).",
    ),
    (
        "key",
        "What the agent HAS",
        "A short-lived, scoped token that only works together with the agent's private key (DPoP).",
    ),
    (
        "monitoring",
        "What the agent DOES",
        "A behavior risk score. High scores force step-up; "
        "very high scores revoke the agent and quarantine it.",
    ),
    (
        "person_check",
        "A HUMAN for risky actions",
        "A phone push, then approval with a 6-digit TOTP code, bound to that exact action.",
    ),
)


def main() -> None:
    ui.page_setup(
        "AIMFA admin console",
        "admin_panel_settings",
        "The control room for the zero-trust gateway. Watch agents, tokens, risk and the audit "
        "log live, and approve risky actions. Everything goes through the control plane's admin "
        "API: this app never reads the database.",
    )

    st.subheader("Agents right now")

    @st.fragment(run_every=ui.REFRESH_SECONDS)
    def overview() -> None:
        agents = ui.guarded(ui.get_client().agents)
        if agents is None:
            return
        counts = Counter(a.status for a in agents)
        cols = st.columns(len(AgentStatus))
        for col, status in zip(cols, AgentStatus, strict=True):
            icon, help_text = STATUS_CARDS.get(status, ("help", ""))
            col.metric(
                status.value.capitalize(),
                counts.get(status, 0),
                icon=f":material/{icon}:",
                help=help_text,
                border=True,
            )

    overview()

    st.subheader("The four checks on every tool call")
    for col, (icon, name, text) in zip(st.columns(len(CHECKS)), CHECKS, strict=True):
        with col.container(border=True, height="stretch"):
            st.markdown(f"**:material/{icon}: {name}**")
            st.caption(text)
    st.caption(
        "New to this? `docs/LEARNING.md` explains each check in plain English. "
        "Use the pages in the sidebar to see each one in action."
    )


main()
