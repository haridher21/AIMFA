"""Smoke test: can we reach TAMU AI and does it support tool (function) calling?

Usage:
    python scripts/check_tamu_ai.py            # uses TAMU_AI_* from .env
    python scripts/check_tamu_ai.py --list     # also list the models your key can use

Outcomes:
    TOOL_CALLING_OK   -> the LLM agent can use native tool calling.
    NO_TOOL_CALLS     -> reachable, but the model answered in text. Use the JSON-action
                         fallback in aimfa/agents/llm.py (or try another model).
    ERROR             -> check TAMU_AI_BASE_URL / TAMU_AI_API_KEY / TAMU_AI_MODEL
                         (see https://docs.tamus.ai/).
The API key is never printed.
"""

from __future__ import annotations

import argparse
import json
import sys

from openai import OpenAI

from aimfa.common.config import get_settings

TOOL = {
    "type": "function",
    "function": {
        "name": "read_file",
        "description": "Read a file from the company file share.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Absolute path"}},
            "required": ["path"],
        },
    },
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="list available models")
    opts = parser.parse_args()

    s = get_settings()
    key = s.tamu_ai_api_key.get_secret_value()
    if not key:
        print("ERROR: TAMU_AI_API_KEY is empty. Put it in .env (never commit it).")
        return 2
    client = OpenAI(base_url=s.tamu_ai_base_url, api_key=key, timeout=60)
    print(f"Base URL: {s.tamu_ai_base_url}")

    try:
        if opts.list or not s.tamu_ai_model:
            models = sorted(mdl.id for mdl in client.models.list())
            print("Models available to this key:")
            for mdl in models:
                print(f"  - {mdl}")
            if not s.tamu_ai_model:
                print("ERROR: set TAMU_AI_MODEL in .env to one of the models above.")
                return 2

        print(f"Model:    {s.tamu_ai_model}")
        resp = client.chat.completions.create(
            model=s.tamu_ai_model,
            messages=[
                {"role": "system", "content": "You are a file assistant. Use tools."},
                {"role": "user", "content": "Read the file /expenses/q3.csv"},
            ],
            tools=[TOOL],
            # TAMU AI streams (text/event-stream) unless stream=false is sent explicitly,
            # and the openai SDK omits the field by default. See ADR-0005.
            stream=False,
        )
    except Exception as exc:  # noqa: BLE001 - surface any client/HTTP error to the user
        print(f"ERROR: {type(exc).__name__}: {exc}")
        return 1

    msg = resp.choices[0].message
    if msg.tool_calls:
        call = msg.tool_calls[0]
        print(f"TOOL_CALLING_OK: {call.function.name}({json.loads(call.function.arguments)})")
        return 0
    print("NO_TOOL_CALLS: model replied with text instead:")
    print((msg.content or "")[:500])
    return 3


if __name__ == "__main__":
    sys.exit(main())
