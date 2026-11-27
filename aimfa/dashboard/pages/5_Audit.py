"""Audit: live tail of the hash chain, and a Verify chain button."""

from __future__ import annotations

import streamlit as st

from aimfa.dashboard import ui
from aimfa.dashboard.views import AUDIT_COLUMNS, AuditTail, audit_rows


def main() -> None:
    ui.page_setup(
        "Audit",
        "receipt_long",
        "Every allow, deny and pending decision, as it happens. Records are hash-chained, so "
        "editing or deleting one afterwards is detectable. Verify chain re-checks every link.",
    )
    client = ui.get_client()
    tail = st.session_state.setdefault("audit_tail", AuditTail())

    if st.button(
        "Verify chain",
        type="primary",
        icon=":material/verified:",
        help="Recompute every record's hash and check that it links to the one before it.",
    ):
        res = ui.guarded(client.verify_audit)
        if res is not None and res.ok:
            st.success(
                f"Chain OK ({res.records_checked} records checked)", icon=":material/verified:"
            )
        elif res is not None:
            st.error(
                f"Chain BROKEN at seq {res.first_bad_seq} ({res.reason_code.value})",
                icon=":material/gpp_bad:",
            )
    st.caption("Live tail: newest first. It restarts on its own if the chain is reset.")

    @st.fragment(run_every=ui.REFRESH_SECONDS)
    def live() -> None:
        if ui.guarded(lambda: tail.poll(client)) is not None:
            rows = audit_rows(reversed(tail.records))
            ui.show_table(ui.with_dots(rows, "outcome"), "Audit log is empty.", AUDIT_COLUMNS)

    live()


main()
