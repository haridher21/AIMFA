# Demo Runbook

**Status:** outline. This is finalized in ROADMAP **T7.2** once the dashboard exists. Target length: **8 minutes**.

## Pre-flight (15 minutes before)
- [ ] `git pull`, then `pip install -e ".[dev]"`
- [ ] `.env` has the secrets set, `NTFY_TOPIC` set, and `TAMU_AI_*` set
- [ ] `python scripts/check_tamu_ai.py` reports `TOOL_CALLING_OK`. If it doesn't, use scripted agents for the whole demo.
- [ ] The approver's phone has the **ntfy** app subscribed to `NTFY_TOPIC`, plus the AIMFA entry in its authenticator app
- [ ] Run `python scripts/run_demo.py --reset` and confirm all services are healthy
- [ ] The dashboard is open at http://127.0.0.1:8501, the projector is mirrored, and the font is enlarged
- [ ] The backup video is on the laptop desktop

## Script
| Time | Beat | What the audience sees | Say |
|---|---|---|---|
| 0:00 | Problem | One slide: the "master key" robot | "Agents run on static API keys: stolen, swapped, or tricked." |
| 0:45 | Normal task | The TAMU AI expense agent summarizes Q3. Green decisions, token countdown. | "Every call passes the checkpoint: identity, key, scope, behavior." |
| 2:00 | **A1** tampered agent | Edit one word of the prompt and relaunch. Red: `ATTEST_MEASUREMENT_MISMATCH`. | "Different fingerprint, different agent, no entry." |
| 2:45 | **A2** stolen token | The attack lab replays the token from another process. Red: DPoP failure. | "The badge only works with the robot's own signature." |
| 3:30 | **A4** prompt injection (headline) | The agent reads `vendor_note.txt`, tries `/engineering`, and gets denied. The risk meter jumps. It tries to email outside the company: **phone buzzes**, the approver denies with TOTP, the agent is **quarantined**. | "We can't stop the robot being tricked, but we contain it." |
| 5:30 | **A8** log tampering | Edit an audit row, then press Verify. It turns red at that row. | "Nobody can quietly erase what happened." |
| 6:15 | **Baseline vs AIMFA** | Flip the toggle and run all attacks. Show the results table. | "Same attacks, old way: all succeed." |
| 7:15 | Wrap-up | One slide: four factors + limitations | "Contained blast radius, human has the final say." |

## Fallbacks
- **TAMU AI is slow or down:** switch the attack lab to the **scripted** `injected_expense` agent. It behaves identically.
- **No phone signal:** approve or deny in the dashboard's Approvals page. The TOTP code still works offline.
- **Anything else breaks:** play the backup video from the matching timestamp.
