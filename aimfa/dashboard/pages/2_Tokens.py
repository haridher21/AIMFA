"""Tokens: active access tokens with TTL countdown. Revoke = the agent kill switch."""

from __future__ import annotations

import streamlit as st

from aimfa.dashboard import ui
from aimfa.dashboard.views import token_rows


def main() -> None:
    ui.page_setup("Tokens")
    st.caption(
        "The contract has no per-token revoke, so the button revokes ALL tokens of the agent."
    )
    client = ui.get_client()

    @st.fragment(run_every=ui.REFRESH_SECONDS)
    def live() -> None:
        ui.show_flash("tokens")
        tokens = ui.guarded(client.tokens)
        if tokens is None:
            return
        ui.show_table(token_rows(tokens, ui.now()), "No tokens issued.")
        for agent in sorted({t.agent_id for t in tokens if not t.revoked}):
            if st.button(f"Revoke all tokens of {agent}", key=f"rt-{agent}"):
                ui.act(lambda agent=agent: client.revoke_agent(agent), f"Revoked {agent}", "tokens")

    live()


main()
