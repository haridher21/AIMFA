# ADR-0005: TAMU AI behind an LLMClient interface, with scripted agents as fallback

- **Status:** accepted (T0.5 verified 2026-11-12)
- **Date:** 2026-11-10
- **Deciders:** team

## Context
The demo needs a real LLM agent to make prompt injection convincing. TAMU AI is free to us and offers an OpenAI-compatible API. Tool-calling support and rate limits were unverified when this was written. A live demo must not depend on a flaky network service.

## Decision
- Use the `openai` SDK with `base_url = TAMU_AI_BASE_URL`, behind an `LLMClient` protocol (`aimfa/agents/llm.py`).
- If native tool calling is unavailable, use a `JsonActionClient`: the model replies with `{"tool": ..., "args": ...}` and we parse it.
- **Scripted agents** (no LLM) produce identical gateway traffic. They are used by all automated tests and are the demo fallback.
- The model id is part of the agent's attested measurement.

## T0.5 result (2026-11-12)
- **Base URL:** `https://chat-api.tamu.ai/openai`. Paths are `/chat/completions` and `/models`. The `/v1/...` paths return 403 ("Direct API passthrough is disabled").
- **Model:** `protected.Claude-Opus-5`
- **Result:** `TOOL_CALLING_OK`. Native OpenAI-style tool calls work, so the JSON-action fallback is not needed (keep it only as a safety net).
- **Gotcha:** the server **streams by default** (`text/event-stream`) unless the request explicitly sends `"stream": false`. The `openai` SDK omits the field by default, so every call MUST pass `stream=False`. Otherwise the SDK returns a raw string.

## Consequences
- **Gained:** tests are deterministic and offline. The demo survives an outage.
- **Must do:** the API key lives only in `.env`. Never log prompts that contain secrets. TAMU AI is approved for University-Confidential data and below, and our data is all fake.
