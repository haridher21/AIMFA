"""Approvals: pending human approvals. Approve/deny needs a TOTP code typed by the human."""

from __future__ import annotations

import json

import streamlit as st

from aimfa.dashboard import ui
from aimfa.dashboard.views import approval_rows


def main() -> None:
    ui.page_setup("Approvals")
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
            st.info("No pending approvals.")
        for rec, row in zip(pending, approval_rows(pending, ui.now()), strict=True):
            with st.container(border=True):
                st.write(
                    f"**{row['agent']}** wants `{row['tool']}` (risk {row['risk']:g}, "
                    f"expires in {row['expires_in']})"
                )
                st.code(ui.safe_text(json.dumps(row["args"], indent=2, default=str)))
                code = st.text_input(
                    f"TOTP code for {rec.approver_id}",
                    key=f"code-{rec.approval_id}",
                    max_chars=6,
                    autocomplete="off",
                )
                c1, c2 = st.columns(2)
                for col, approve, label in ((c1, True, "Approve"), (c2, False, "Deny")):
                    if col.button(label, key=f"{label}-{rec.approval_id}"):
                        ui.act(
                            lambda rec=rec, approve=approve, code=code: client.decide(
                                rec.approval_id, rec.approver_id, approve, code
                            ),
                            f"{label}d: {rec.tool} for {rec.agent_id}",
                            "approvals",
                        )

    live()


main()
