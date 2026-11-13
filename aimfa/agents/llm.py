"""LLM clients for the TAMU AI agent.

Two interchangeable clients behind the ``LLMClient`` protocol:

* ``TamuAIClient``: OpenAI-compatible chat API with native tool calls. Always sends
  ``stream=False`` (ADR-0005: TAMU AI streams unless told not to).
* ``JsonActionClient``: fallback for models without native tool calls; the model is asked
  to answer with one JSON object and we parse it.

Whatever the model returns is UNTRUSTED text. Nothing here executes it; the loop in
``llm_agent.py`` forwards only whitelisted tools, and the gateway still checks every call.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import yaml
from openai import OpenAI

from aimfa.common.config import Settings


@dataclass(frozen=True)
class LLMToolCall:
    id: str
    name: str
    arguments: Any  # parsed JSON; the loop checks it is a dict. None = unparseable.


@dataclass(frozen=True)
class LLMReply:
    text: str | None = None
    tool_calls: list[LLMToolCall] = field(default_factory=list)


class LLMClient(Protocol):
    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMReply: ...


# ---------------------------------------------------------------- tool schemas


def tool_schemas(tool_names: list[str], policy_dir: Path | None = None) -> list[dict[str, Any]]:
    """OpenAI function-tool schemas for ``tool_names``, built from policy/actions.yaml.

    Only the tools the (attested) manifest lists are exposed to the model. Every arg is a
    required string, except ``amount`` which is a number.
    """
    if policy_dir is None:
        from aimfa.common.config import get_settings

        policy_dir = get_settings().policy_dir
    doc = yaml.safe_load((Path(policy_dir) / "actions.yaml").read_text(encoding="utf-8"))
    known: dict[str, Any] = doc["tools"]
    schemas: list[dict[str, Any]] = []
    for name in tool_names:
        spec = known.get(name)
        if spec is None:
            continue  # unknown tool: the model never sees it
        args = list(spec["args"])
        schemas.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": f"{spec['service']}:{spec['verb']} (tool '{name}')",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            a: {"type": "number" if a == "amount" else "string"} for a in args
                        },
                        "required": args,
                    },
                },
            }
        )
    return schemas


# ---------------------------------------------------------------- TAMU AI


class TamuAIClient:
    def __init__(self, settings: Settings, *, client: Any | None = None, model: str = "") -> None:
        key = settings.tamu_ai_api_key.get_secret_value()
        if not key:
            raise ValueError("TAMU_AI_API_KEY is empty; set it in .env (never commit it)")
        self._model = model or settings.tamu_ai_model
        if not self._model:
            raise ValueError("TAMU_AI_MODEL is empty; set it in .env")
        self._client = client or OpenAI(base_url=settings.tamu_ai_base_url, api_key=key, timeout=60)

    def __repr__(self) -> str:  # never show the API key
        return f"TamuAIClient(model={self._model!r})"

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMReply:
        kwargs: dict[str, Any] = {"model": self._model, "messages": messages, "stream": False}
        if tools:
            kwargs["tools"] = tools
        resp = self._client.chat.completions.create(**kwargs)
        msg = resp.choices[0].message
        calls: list[LLMToolCall] = []
        for tc in msg.tool_calls or []:
            try:
                args: Any = json.loads(tc.function.arguments)
            except (TypeError, ValueError):
                args = None
            calls.append(LLMToolCall(id=tc.id, name=tc.function.name, arguments=args))
        return LLMReply(text=msg.content or None, tool_calls=calls)


# ---------------------------------------------------------------- JSON fallback

_JSON_INSTRUCTIONS = (
    "\n\nYou can call tools. Reply with EXACTLY ONE JSON object and nothing else: "
    '{"tool": "<tool name>", "args": {...}} to call a tool, or {"final": "<answer>"} when '
    "done. Available tools: "
)


def _first_json_object(text: str) -> Any:
    """Parse the first balanced ``{...}`` block in ``text``; None if there is none."""
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except ValueError:
                        break
        start = text.find("{", start + 1)
    return None


class JsonActionClient:
    """Wraps a plain text-completion function: ``text_fn(messages) -> str``."""

    def __init__(self, text_fn: Callable[[list[dict[str, Any]]], str]) -> None:
        self._text_fn = text_fn

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMReply:
        names = ", ".join(t["function"]["name"] for t in tools)
        patched = [dict(m) for m in messages]
        if patched and patched[0].get("role") == "system":
            patched[0]["content"] = f"{patched[0].get('content', '')}{_JSON_INSTRUCTIONS}{names}"
        raw = self._text_fn(patched)
        obj = _first_json_object(raw) if isinstance(raw, str) else None
        if isinstance(obj, dict) and isinstance(obj.get("tool"), str):
            args = obj.get("args", {})
            return LLMReply(tool_calls=[LLMToolCall(id="json-1", name=obj["tool"], arguments=args)])
        if isinstance(obj, dict) and isinstance(obj.get("final"), str):
            return LLMReply(text=obj["final"])
        return LLMReply(text=raw if isinstance(raw, str) else "")  # garbage: end the loop
