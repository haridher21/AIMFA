"""Approvals: pending human approvals. Approve/deny needs a TOTP code typed by the human."""

from __future__ import annotations

import json

import streamlit as st

from aimfa.dashboard import ui
from aimfa.dashboard.views import approval_rows

TOTP_HELP = (
    "Open the approver's authenticator app and type the current 6-digit code. The code is "
    "bound to this exact action, so it can't be reused for a different one."
)


def main() -> None:
    ui.page_setup(
        "Approvals",
        "how_to_reg",
        "Risky actions an agent is waiting to do. Nothing happens until a human approves with "
        "a TOTP code. Each request expires if nobody answers.",
    )
    st.caption(
        "The 6-digit code comes from the approver's authenticator app. It is typed here by "
        "the human and nowhere else: this console never holds a TOTP seed."
    )
    client = ui.get_client()

    @st.fragment(run_every=ui.REFRESH_SECONDS)
    def live() -> None:
        ui.show_flash("approvals")
        pending = ui.guarded(lambda: client.approvals("pending"))
        if pending is None:
            return
        if not pending:
            st.info("No pending approvals.", icon=":material/task_alt:")
        for rec, row in zip(pending, approval_rows(pending, ui.now()), strict=True):
            with st.container(border=True):
                head, meta = st.columns([3, 2], vertical_alignment="center")
                head.markdown(f"**{row['agent']}** wants to run `{row['tool']}`")
                with meta:
                    st.badge(
                        f"risk {row['risk']:g}",
                        icon=":material/monitoring:",
                        color="orange",
                        help="The agent's risk score when it asked.",
                    )
                    st.badge(
                        f"expires in {row['expires_in']}",
                        icon=":material/timer:",
                        color="gray",
                        help="After this, the request expires and the action never runs.",
                    )
                st.caption("Exact arguments this approval is bound to:")
                st.code(ui.safe_text(json.dumps(row["args"], indent=2, default=str)))
                code = st.text_input(
                    f"TOTP code for {rec.approver_id}",
                    key=f"code-{rec.approval_id}",
                    max_chars=6,
                    autocomplete="off",
                    help=TOTP_HELP,
                    placeholder="123456",
                )
                c1, c2 = st.columns(2)
                buttons = (
                    (c1, True, "Approve", "primary", ":material/check_circle:"),
                    (c2, False, "Deny", "secondary", ":material/cancel:"),
                )
                for col, approve, label, kind, icon in buttons:
                    if col.button(
                        label,
                        key=f"{label}-{rec.approval_id}",
                        type=kind,
                        icon=icon,
                        width="stretch",
                    ):
                        ui.act(
                            lambda rec=rec, approve=approve, code=code: client.decide(
                                rec.approval_id, rec.approver_id, approve, code
                            ),
                            f"{label}d: {rec.tool} for {rec.agent_id}",
                            "approvals",
                        )

    live()


main()
