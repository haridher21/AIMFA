"""The LLM tool loop: the model proposes tool calls, AIMFA decides.

The model is untrusted (it may be prompt-injected by file contents). It never touches
resources directly: every call goes through ``session.call`` -> gateway, which applies all
four checks. This loop adds one more local rule: only tools in the manifest are forwarded.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass
from typing import Any, Protocol

from aimfa.agents.client import AimfaError
from aimfa.agents.llm import LLMClient, tool_schemas

MAX_STEPS = 15
MAX_RESULT_CHARS = 4000


class Session(Protocol):
    def start_task(self, description: str, scopes: list[str]) -> Any: ...
    def call(self, tool: str, /, **args: Any) -> Any: ...
    def complete_task(self) -> None: ...


@dataclass(frozen=True)
class LLMStep:
    tool: str
    decision: str  # "allow" | "denied" | "not_in_manifest" | "bad_arguments" | "max_steps"
    reason_code: str | None = None


def _tool_message(call_id: str, content: str) -> dict[str, Any]:
    return {"role": "tool", "tool_call_id": call_id, "content": content}


def run_llm_agent(
    session: Session,
    llm: LLMClient,
    *,
    system_prompt: str,
    tools: list[str],
    task: str,
    scopes: list[str],
    max_steps: int = MAX_STEPS,
) -> list[LLMStep]:
    """Run one task. ``system_prompt`` and ``tools`` MUST come from the attested manifest.

    Never hard-code or load a prompt from elsewhere: attestation hashes the manifest, so a
    different prompt here would be an unattested behavior change.
    """
    allowed = set(tools)
    schemas = tool_schemas(tools)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": task},
    ]
    steps: list[LLMStep] = []
    session.start_task(task, scopes)
    try:
        for _ in range(max_steps):
            reply = llm.complete(messages, schemas)
            if not reply.tool_calls:
                return steps  # final text answer
            messages.append(
                {
                    "role": "assistant",
                    "content": reply.text or "",
                    "tool_calls": [
                        {
                            "id": c.id,
                            "type": "function",
                            "function": {"name": c.name, "arguments": json.dumps(c.arguments)},
                        }
                        for c in reply.tool_calls
                    ],
                }
            )
            for c in reply.tool_calls:
                messages.append(_tool_message(c.id, _handle(session, c, allowed, steps)))
        steps.append(LLMStep(tool="-", decision="max_steps"))
        return steps
    finally:
        # Always revoke the task token, but don't let a failure here hide the real error.
        with contextlib.suppress(AimfaError):
            session.complete_task()


def _handle(session: Session, call: Any, allowed: set[str], steps: list[LLMStep]) -> str:
    name = call.name
    if name not in allowed:
        steps.append(LLMStep(name, "not_in_manifest"))
        return f"ERROR: tool {name!r} is not available"
    args = call.arguments
    if not isinstance(args, dict) or not all(isinstance(k, str) for k in args):
        steps.append(LLMStep(name, "bad_arguments"))
        return "ERROR: arguments must be a JSON object"
    try:
        resp = session.call(name, **args)
    except AimfaError as exc:
        steps.append(LLMStep(name, "denied", exc.reason_code.value))
        return f"DENIED: {exc.reason_code.value}"
    except TypeError:
        steps.append(LLMStep(name, "bad_arguments"))
        return "ERROR: invalid arguments"
    steps.append(LLMStep(name, "allow", resp.decision.reason_code.value))
    return json.dumps(resp.result, default=str)[:MAX_RESULT_CHARS]
