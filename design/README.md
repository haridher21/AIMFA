# design/ — interface prototypes

Static mockups used to decide what a screen should be **before** anyone writes Streamlit code.
Nothing here is imported by `aimfa/`, runs in CI, or is served by any service.

## decision-console.html

Open it directly in a browser (`open design/decision-console.html`, or drag it onto a window).
No build step, no server, no dependencies beyond two Google Fonts.

**It is not connected to anything.** Every value is a literal in the page's `<script>`. The data
is a faithful replay rather than invention — the risk arithmetic, reason codes, scope strings and
the Ed25519 thumbprint are copied from real runs of `attacks/a10_silent_exfil.py`,
`a2_stolen_token.py` and `a4_prompt_injection.py`. The clock and the TTL countdowns tick on a
timer, which is cosmetic: it makes the page *look* live, so don't let that imply a connection
during a demo.

### What it argues

The Streamlit dashboard we ship is shaped like the database — six pages, one per table. That is
the right first build, but it means the most interesting object in the system is the one thing
you cannot see: **a single tool call falling through the ten gates** in `gateway/pipeline.py`.
The prototype makes that the primary screen, with a rail that runs green to the gate which
decided the call and goes dead after it. Five calls are included, chosen to die in different
places — gate 3 (`DPOP_KEY_MISMATCH`, on a *genuine* stolen token), gate 6 (`SCOPE_DENIED`),
gate 7 (`AGENT_QUARANTINED`), parked at gate 9, and one that passes all ten.

The second argument is the approval card. A10 showed that a correct risk score still told the
approver nothing, so the card is shown twice: the seven fields `views.approval_rows` produces
today, beside the same approval with the history that makes it legible.

### If it gets built for real

Most panels map onto admin endpoints that already exist — `/admin/agents`, `/admin/tokens`,
`/admin/risk`, `/admin/approvals`, `/admin/audit/verify`. Two do not:

- **The attack matrix** is `attacks/run_all.py` output, i.e. a build artifact, not live state.
- **The decision trace has no endpoint at all.** Nothing returns a per-call, gate-by-gate result.
  The shape is recoverable for free, though: the pipeline is strictly ordered and each reason code
  belongs to exactly one gate, so a single audit record implies the whole ladder — `SCOPE_DENIED`
  means gates 1–5 passed, 6 denied, 7–10 never ran. What is missing is the *evidence line* under
  each gate ("jkt matches cnf", "covered by `db:read:*`"), which would need the gateway to record
  what each check actually saw. That is a real change to `pipeline.py` and to how much detail
  every decision carries into the audit chain, so it should be decided deliberately.

Note also that a published Artifact runs under a CSP that blocks outbound requests, so a hosted
copy of this page can never poll a local control plane. The live version has to be the Streamlit
app, or a page served by the control plane itself.
