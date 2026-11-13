"""T6.3: scripts/run_agent.py argument parsing and agent selection. No network, no live run."""

from __future__ import annotations

import httpx
import pytest

from aimfa.agents.launcher import load_manifest
from aimfa.common.config import Settings
from scripts import run_agent

NAMES = ["normal_expense", "injected_expense", "wire_bot", "llm_expense"]


@pytest.mark.parametrize("name", NAMES)
def test_every_choice_selects_a_real_manifest(name):
    spec = run_agent.select_agent(name)
    manifest = load_manifest(spec.manifest_path)
    assert spec.name == name and manifest.system_prompt
    assert (spec.module is None) == (name == "llm_expense")


def test_unknown_agent_is_rejected_by_select_and_parser(capsys):
    with pytest.raises(ValueError):
        run_agent.select_agent("../../etc/passwd")
    with pytest.raises(SystemExit) as exc:
        run_agent.parse_args(["not_an_agent"])
    assert exc.value.code == 2


def test_parse_args_defaults_and_options():
    args = run_agent.parse_args(["wire_bot", "--poll-timeout", "5"])
    assert (args.manifest, args.poll_timeout) == ("wire_bot", 5.0)
    assert run_agent.parse_args(["llm_expense"]).task == run_agent.LLM_TASK


def test_non_positive_poll_timeout_is_rejected():
    with pytest.raises(SystemExit):
        run_agent.parse_args(["wire_bot", "--poll-timeout", "0"])


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com:8100",
        "http://127.0.0.1.evil.com:8100",
        "http://localhost@evil.com:8100",
    ],
)
def test_non_localhost_services_are_refused_before_any_network(monkeypatch, capsys, url):
    def boom(*a, **k):
        raise AssertionError("network touched")

    monkeypatch.setattr(httpx.Client, "send", boom)
    settings = Settings(_env_file=None, gateway_url=url)
    assert run_agent.main(["normal_expense"], settings=settings) == 2
    assert "non-localhost" in capsys.readouterr().err


def test_unreachable_services_give_a_hint_and_nonzero_exit(monkeypatch, capsys):
    def refused(self, request, *a, **k):
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(httpx.Client, "send", refused)  # no real network in unit tests
    settings = Settings(_env_file=None)
    assert run_agent.main(["normal_expense", "--poll-timeout", "1"], settings=settings) != 0
    assert "start scripts/run_demo.py" in capsys.readouterr().err
