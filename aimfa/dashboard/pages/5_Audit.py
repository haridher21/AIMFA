"""Audit: live tail of the hash chain, and a Verify chain button."""

from __future__ import annotations

import streamlit as st

from aimfa.dashboard import ui
from aimfa.dashboard.views import AuditTail, audit_rows


def main() -> None:
    ui.page_setup("Audit")
    client = ui.get_client()
    tail = st.session_state.setdefault("audit_tail", AuditTail())

    if st.button("Verify chain"):
        res = ui.guarded(client.verify_audit)
        if res is not None and res.ok:
            st.success(f"Chain OK ({res.records_checked} records checked)")
        elif res is not None:
            st.error(f"Chain BROKEN at seq {res.first_bad_seq} ({res.reason_code.value})")
    st.caption("Live tail: newest first. It restarts on its own if the chain is reset.")

    @st.fragment(run_every=ui.REFRESH_SECONDS)
    def live() -> None:
        if ui.guarded(lambda: tail.poll(client)) is not None:
            ui.show_table(audit_rows(reversed(tail.records)), "Audit log is empty.")

    live()


main()
