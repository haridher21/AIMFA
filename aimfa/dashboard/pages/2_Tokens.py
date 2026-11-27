"""Tokens: active access tokens with TTL countdown. Revoke = the agent kill switch."""

from __future__ import annotations

from functools import partial

import streamlit as st

from aimfa.dashboard import ui
from aimfa.dashboard.views import TOKEN_COLUMNS, token_rows


def main() -> None:
    ui.page_setup(
        "Tokens",
        "key",
        "Short-lived access tokens issued to agents. Each one is limited to one task and its "
        "scopes, works only with the agent's private key (DPoP), and expires on its own.",
    )
    st.caption(
        "The contract has no per-token revoke, so the button revokes ALL tokens of the agent."
    )
    client = ui.get_client()
    ttl_bar = partial(
        st.column_config.ProgressColumn,
        min_value=0,
        max_value=ui.get_settings().access_token_ttl_seconds,
        format="%d s",
    )

    @st.fragment(run_every=ui.REFRESH_SECONDS)
    def live() -> None:
        ui.show_flash("tokens")
        tokens = ui.guarded(client.tokens)
        if tokens is None:
            return
        ui.show_table(
            ui.with_dots(token_rows(tokens, ui.now()), "state"),
            "No tokens issued.",
            TOKEN_COLUMNS,
            {"ttl_seconds": ttl_bar},
        )
        live_agents = sorted({t.agent_id for t in tokens if not t.revoked})
        if live_agents:
            st.subheader("Kill switch")
        cols = st.columns(3)
        for i, agent in enumerate(live_agents):
            if cols[i % 3].button(
                f"Revoke all tokens of {agent}",
                key=f"rt-{agent}",
                icon=":material/block:",
                width="stretch",
            ):
                ui.act(lambda agent=agent: client.revoke_agent(agent), f"Revoked {agent}", "tokens")

    live()


main()
