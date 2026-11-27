"""Attack Lab: run the attack scripts, baseline vs AIMFA, and show result cards."""

from __future__ import annotations

import streamlit as st

from aimfa.dashboard import ui
from aimfa.dashboard.views import attack_cards

# Hover help per attack, keyed by the attack's module name.
ATTACK_HELP = {
    "a1_tampered_agent": "A modified agent build tries to get an identity. Stopped by attestation.",
    "a2_stolen_token": "A thief uses a stolen token without the agent's private key. "
    "Stopped by DPoP.",
    "a3_replay": "A captured request is sent a second time. Stopped by DPoP replay protection.",
    "a4_prompt_injection": "A poisoned document tells the agent to read secrets and email them "
    "out. Stopped by scopes.",
    "a5_unauthorized_wire": "The agent tries a bank wire with no human approval. "
    "Stopped by step-up.",
    "a6_expired_token": "A token is used after its task ended or its time ran out. Stopped by TTL "
    "and revocation.",
    "a7_scope_escalation": "The agent asks for more scopes than its role allows. Stopped by the "
    "token service's policy.",
    "a8_audit_tamper": "Someone edits an audit record in the database. Caught by the hash chain.",
    "a9_fake_approval": "Approval with a wrong TOTP code, or reused for a different amount. "
    "Stopped by TOTP and action binding.",
    "a10_silent_exfil": "Reads payroll from the database and emails it out, staying inside its "
    "scopes. Tests whether the risk monitor notices (a known gap; the human approval still "
    "stands).",
}


def attack_label(fn: object, i: int) -> tuple[str, str]:
    """Button label and hover help, from the attack's module name (e.g. a3_replay)."""
    module = getattr(fn, "__module__", "").rsplit(".", 1)[-1]
    words = module.split("_", 1)[1].replace("_", " ") if "_" in module else ""
    return f"A{i + 1} {words}".strip(), ATTACK_HELP.get(module, "")


def main() -> None:
    ui.page_setup(
        "Attack Lab",
        "bug_report",
        "Run real attacks against the system twice: once with only a shared password "
        "(baseline) and once with AIMFA. Each card shows whether the attack worked, and if not, "
        "which check stopped it.",
    )
    st.info(
        "Attacks run in their OWN throwaway in-process stack (temp dir, random secrets, fake "
        "data). They never touch the live services shown on the other pages.",
        icon=":material/science:",
    )
    from attacks import run_all  # imported after the sys.path fix in page_setup

    mode = st.radio(
        "Mode",
        ["aimfa", "baseline"],
        horizontal=True,
        help="baseline = one shared API key, no other checks. aimfa = all four checks on.",
    )
    results = st.session_state.setdefault("attack_results", [])

    def run(indices: list[int]) -> None:
        for i in indices:
            try:
                results.append(run_all.ATTACKS[i](mode))
            except Exception as err:  # noqa: BLE001 - show failure, never as "blocked"
                st.error(ui.safe_text(f"Attack A{i + 1} could not run: {type(err).__name__}"))

    with st.container(border=True):
        cols = st.columns(5)
        for i, fn in enumerate(run_all.ATTACKS):
            label, help_text = attack_label(fn, i)
            if cols[i % 5].button(label, key=f"atk-{i}", help=help_text or None, width="stretch"):
                run([i])
        if st.button("Run all", type="primary", icon=":material/play_arrow:"):
            run(list(range(len(run_all.ATTACKS))))

    cards = attack_cards(results)
    if cards:
        blocked = sum(not c["succeeded"] and not c["not_applicable"] for c in cards)
        worked = sum(c["succeeded"] and not c["not_applicable"] for c in cards)
        m1, m2, m3 = st.columns(3)
        m1.metric("Runs", len(cards), border=True, icon=":material/science:")
        m2.metric("Blocked", blocked, border=True, icon=":material/shield:")
        m3.metric("Attack succeeded", worked, border=True, icon=":material/warning:")

    for card in reversed(cards):
        with st.container(border=True):
            if card["not_applicable"]:
                badge = ("N/A: baseline has no human-approval step", "gray", ":material/remove:")
            elif card["succeeded"]:
                badge = ("ATTACK SUCCEEDED", "red", ":material/warning:")
            else:
                badge = ("blocked", "green", ":material/shield:")
            head, tag = st.columns([3, 2], vertical_alignment="center")
            head.markdown(f"**{card['name']}** · {card['mode']}")
            tag.badge(badge[0], color=badge[1], icon=badge[2])
            st.caption(f"blocked by: {card['blocked_by']} | reason: {card['reason_code']}")
            st.text(ui.safe_text(card["evidence"]))  # plain text: no markdown injection


main()
