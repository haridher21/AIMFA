"""T5.3: LLM tool loop, TamuAIClient and JsonActionClient. No network."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import SecretStr

from aimfa.agents.client import PolicyDenied
from aimfa.agents.llm import (
    JsonActionClient,
    LLMReply,
    LLMToolCall,
    TamuAIClient,
    tool_schemas,
)
from aimfa.agents.llm_agent import MAX_STEPS, run_llm_agent
from aimfa.common.config import Settings
from aimfa.common.models import ReasonCode

TOOLS = ["list_files", "read_file", "send_email"]


def tc(name: str, args: Any, id_: str = "c1") -> LLMToolCall:
    return LLMToolCall(id=id_, name=name, arguments=args)


class FakeLLM:
    def __init__(self, replies: list[LLMReply], repeat_last: bool = False) -> None:
        self.replies, self.repeat_last = list(replies), repeat_last
        self.seen: list[list[dict[str, Any]]] = []

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMReply:
        self.seen.append([dict(m) for m in messages])
        if self.repeat_last and len(self.replies) == 1:
            return self.replies[0]
        return self.replies.pop(0)


class FakeSession:
    def __init__(self, deny: set[str] | None = None) -> None:
        self.deny = deny or set()
        self.events: list[Any] = []

    def start_task(self, description: str, scopes: list[str]) -> None:
        self.events.append(("start", description, scopes))

    def call(self, tool: str, /, **args: Any) -> Any:
        self.events.append(("call", tool, args))
        if tool in self.deny:
            raise PolicyDenied(ReasonCode.SCOPE_DENIED, 403)
        decision = SimpleNamespace(reason_code=ReasonCode.OK)
        return SimpleNamespace(decision=decision, result={"data": "x" * 5000})

    def complete_task(self) -> None:
        self.events.append(("complete",))

    @property
    def calls(self) -> list[str]:
        return [e[1] for e in self.events if e[0] == "call"]


def run(llm: FakeLLM, session: Any, **kw: Any) -> Any:
    return run_llm_agent(
        session, llm, system_prompt="SYS", tools=TOOLS, task="do it", scopes=["s"], **kw
    )


def test_normal_task_flow() -> None:
    mail = {"to": "a@acme.test", "subject": "s", "body": "b"}
    llm = FakeLLM(
        [
            LLMReply(tool_calls=[tc("list_files", {"dir": "/expenses"})]),
            LLMReply(tool_calls=[tc("read_file", {"path": "/expenses/q3.csv"})]),
            LLMReply(tool_calls=[tc("send_email", mail)]),
            LLMReply(text="done"),
        ]
    )
    s = FakeSession()
    steps = run(llm, s)
    assert s.calls == ["list_files", "read_file", "send_email"]
    assert s.events[0][0] == "start" and s.events[-1] == ("complete",)
    assert [x.decision for x in steps] == ["allow"] * 3


def test_attested_system_prompt_is_first_message() -> None:
    llm = FakeLLM([LLMReply(text="hi")])
    run(llm, FakeSession())
    assert llm.seen[0][0] == {"role": "system", "content": "SYS"}


def test_denied_call_fed_back_and_loop_continues() -> None:
    mail = {"to": "x", "subject": "s", "body": "b"}
    llm = FakeLLM([LLMReply(tool_calls=[tc("send_email", mail)]), LLMReply(text="ok")])
    steps = run(llm, FakeSession(deny={"send_email"}))
    assert steps[0].decision == "denied" and steps[0].reason_code == "SCOPE_DENIED"
    tool_msgs = [m for m in llm.seen[1] if m["role"] == "tool"]
    assert "SCOPE_DENIED" in tool_msgs[0]["content"]


def test_tool_outside_manifest_never_forwarded() -> None:
    llm = FakeLLM([LLMReply(tool_calls=[tc("wire_transfer", {"amount": 1})]), LLMReply(text="x")])
    s = FakeSession()
    steps = run(llm, s)
    assert s.calls == []
    assert steps[0].decision == "not_in_manifest"


def test_max_steps_cap_and_complete_task() -> None:
    llm = FakeLLM([LLMReply(tool_calls=[tc("list_files", {"dir": "/"})])], repeat_last=True)
    s = FakeSession()
    steps = run(llm, s)
    assert s.calls.count("list_files") == MAX_STEPS == 15
    assert steps[-1].decision == "max_steps"
    assert s.events[-1] == ("complete",)


@pytest.mark.parametrize("bad", [None, ["a"], "str", {1: "x"}])
def test_malformed_arguments_not_forwarded(bad: Any) -> None:
    llm = FakeLLM([LLMReply(tool_calls=[tc("read_file", bad)]), LLMReply(text="x")])
    s = FakeSession()
    steps = run(llm, s)
    assert s.calls == [] and steps[0].decision == "bad_arguments"


def test_wrong_kwargs_do_not_crash() -> None:
    class Strict(FakeSession):
        def call(self, tool: str, /, **args: Any) -> Any:
            raise TypeError("boom")

    llm = FakeLLM([LLMReply(tool_calls=[tc("read_file", {"path": "/a"})]), LLMReply(text="x")])
    assert run(llm, Strict())[0].decision == "bad_arguments"


def test_long_result_truncated() -> None:
    llm = FakeLLM([LLMReply(tool_calls=[tc("read_file", {"path": "/a"})]), LLMReply(text="x")])
    run(llm, FakeSession())
    tool_msg = [m for m in llm.seen[1] if m["role"] == "tool"][0]
    assert len(tool_msg["content"]) <= 4000


# ---------------------------------------------------------------- TamuAIClient


def _settings(key: str = "sekrit-key") -> Settings:
    return Settings(tamu_ai_api_key=SecretStr(key), tamu_ai_model="m1")


class FakeOpenAI:
    def __init__(self, message: Any) -> None:
        self.kwargs: dict[str, Any] = {}
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))
        self._message = message

    def _create(self, **kw: Any) -> Any:
        self.kwargs = kw
        return SimpleNamespace(choices=[SimpleNamespace(message=self._message)])


def _msg(calls: list[Any] | None, content: str | None = None) -> Any:
    return SimpleNamespace(content=content, tool_calls=calls)


def _fn(name: str, args: str) -> Any:
    return SimpleNamespace(id="id1", function=SimpleNamespace(name=name, arguments=args))


def test_tamu_client_request_and_parse() -> None:
    fake = FakeOpenAI(_msg([_fn("read_file", '{"path": "/a"}')]))
    schemas = tool_schemas(["read_file"])
    client = TamuAIClient(_settings(), client=fake)
    reply = client.complete([{"role": "user", "content": "x"}], schemas)
    assert fake.kwargs["stream"] is False
    assert fake.kwargs["model"] == "m1" and fake.kwargs["tools"] == schemas
    assert reply.tool_calls == [LLMToolCall("id1", "read_file", {"path": "/a"})]


def test_tamu_client_bad_json_arguments_become_none() -> None:
    fake = FakeOpenAI(_msg([_fn("read_file", "{not json")]))
    reply = TamuAIClient(_settings(), client=fake).complete([], [])
    assert reply.tool_calls[0].arguments is None


def test_tamu_client_empty_key_raises_and_repr_hides_key() -> None:
    with pytest.raises(ValueError):
        TamuAIClient(_settings(""), client=object())
    c = TamuAIClient(_settings(), client=object())
    assert "sekrit-key" not in repr(c) and "sekrit-key" not in str(c)


# ---------------------------------------------------------------- JsonActionClient


def test_json_client_tool_action_and_prompt_extension() -> None:
    seen: list[Any] = []

    def fn(messages: list[dict[str, Any]]) -> str:
        seen.append(messages)
        return 'Sure! {"tool": "read_file", "args": {"path": "/a"}} thanks'

    reply = JsonActionClient(fn).complete(
        [{"role": "system", "content": "SYS"}], tool_schemas(["read_file"])
    )
    call = reply.tool_calls[0]
    assert call.name == "read_file" and call.arguments == {"path": "/a"}
    assert seen[0][0]["content"].startswith("SYS") and "read_file" in seen[0][0]["content"]


def test_json_client_final_and_garbage() -> None:
    assert JsonActionClient(lambda m: '{"final": "all done"}').complete([], []).text == "all done"
    garbage = JsonActionClient(lambda m: "no json {{ here").complete([], [])
    assert garbage.tool_calls == [] and garbage.text


# ---------------------------------------------------------------- schemas


def test_tool_schemas_required_args() -> None:
    (schema,) = tool_schemas(["send_email"])
    params = schema["function"]["parameters"]
    assert set(params["required"]) == {"to", "subject", "body"}
    wire = tool_schemas(["wire_transfer"])[0]["function"]["parameters"]["properties"]
    assert wire["amount"]["type"] == "number"
    assert tool_schemas(["nope"]) == []
