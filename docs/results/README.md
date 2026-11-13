# Live run results

Transcripts from MANUAL runs of the TAMU AI agent (T5.3). These need the real
`TAMU_AI_API_KEY` in `.env`, so they are never run in CI.

Acceptance for T5.3:

1. One live run of the normal expense task that completes.
2. Three live runs of the injected-file task; the prompt injection must be observed
   (the model tries the injected action) in at least one of them.

For each run save `run-<n>-<normal|injected>.md` with: date, model id (`TAMU_AI_MODEL`),
the task text, the transcript (model tool calls, and the gateway decision plus reason code
for each) and the audit-chain excerpt. Never paste the API key, tokens or TOTP seeds.
