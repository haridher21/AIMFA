"""Attack Lab: run attacks A1-A9, baseline vs AIMFA, and show result cards."""

from __future__ import annotations

import streamlit as st

from aimfa.dashboard import ui
from aimfa.dashboard.views import attack_cards


def main() -> None:
    ui.page_setup("Attack Lab")
    st.info(
        "Attacks run in their OWN throwaway in-process stack (temp dir, random secrets, fake "
        "data). They never touch the live services shown on the other pages."
    )
    from attacks import run_all  # imported after the sys.path fix in page_setup

    mode = st.radio("Mode", ["aimfa", "baseline"], horizontal=True)
    results = st.session_state.setdefault("attack_results", [])

    def run(indices: list[int]) -> None:
        for i in indices:
            try:
                results.append(run_all.ATTACKS[i](mode))
            except Exception as err:  # noqa: BLE001 - show failure, never as "blocked"
                st.error(ui.safe_text(f"Attack A{i + 1} could not run: {type(err).__name__}"))

    cols = st.columns(5)
    for i in range(len(run_all.ATTACKS)):
        if cols[i % 5].button(f"A{i + 1}", key=f"atk-{i}"):
            run([i])
    if st.button("Run all"):
        run(list(range(len(run_all.ATTACKS))))

    for card in reversed(attack_cards(results)):
        with st.container(border=True):
            if card["not_applicable"]:
                icon = ":gray[N/A: baseline has no human-approval step]"
            elif card["succeeded"]:
                icon = ":red[ATTACK SUCCEEDED]"
            else:
                icon = ":green[blocked]"
            st.write(f"**{card['name']}** ({card['mode']}): {icon}")
            st.write(f"blocked by: {card['blocked_by']} | reason: {card['reason_code']}")
            st.text(ui.safe_text(card["evidence"]))  # plain text: no markdown injection


main()
