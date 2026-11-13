"""T5.4: demo runner safety checks (no processes, no network)."""

from __future__ import annotations

import importlib
import subprocess

import pytest

from aimfa.common.config import Settings
from scripts import run_demo

GOOD = "x" * 32


def _settings(**over) -> Settings:
    base = {
        "admin_api_key": GOOD,
        "internal_service_secret": GOOD + "1",
        "gateway_resource_secret": GOOD + "2",
        "baseline_api_key": GOOD + "3",
    }
    return Settings(_env_file=None, **{**base, **over})


def test_default_secrets_refused_names_only(capsys):
    s = Settings(_env_file=None)
    assert set(run_demo.check_secrets(s)) == {
        "admin_api_key",
        "internal_service_secret",
        "gateway_resource_secret",
        "baseline_api_key",
    }
    assert run_demo.main([], settings=s) == 2
    out = capsys.readouterr()
    text = out.out + out.err
    assert "ADMIN_API_KEY" in text and "token_urlsafe" in text
    assert "change-me" not in text


def test_approver_is_enrolled_before_agents_are_registered(monkeypatch):
    """Agents name their approver; registering them first gets 422 "unknown approver"."""
    calls: list[str] = []
    monkeypatch.setattr(run_demo, "service_commands", lambda s, m: [])
    monkeypatch.setattr(run_demo, "_enroll_approver", lambda s: calls.append("enroll") or True)
    monkeypatch.setattr(
        run_demo.register_agents, "main", lambda *a, **k: calls.append("register") or 1
    )
    assert run_demo.main([], settings=_settings()) == 1  # register "fails" so main returns
    assert calls == ["enroll", "register"]


def test_short_secret_refused_and_good_pass():
    assert run_demo.check_secrets(_settings(admin_api_key="short")) == ["admin_api_key"]
    assert run_demo.check_secrets(_settings()) == []


def test_bad_secrets_start_no_process(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("Popen must not be called")

    monkeypatch.setattr(subprocess, "Popen", boom)
    assert run_demo.main([], settings=Settings(_env_file=None)) == 2


def test_commands_bind_localhost_only(monkeypatch, tmp_path):
    app = tmp_path / "app.py"
    app.write_text("")
    monkeypatch.setattr(run_demo, "DASHBOARD_APP", app)
    services = run_demo.service_commands(_settings(), "baseline")
    assert [n for n, _, _ in services] == ["control-plane", "gateway", "resources", "dashboard"]
    for _, argv, health in services:
        assert "0.0.0.0" not in " ".join(argv)  # noqa: S104 - asserting it is absent
        assert "127.0.0.1" in argv
        assert health.startswith("http://127.0.0.1:")
    assert "--factory" in services[0][1] and "8000" in services[0][1]


def test_dashboard_omitted_when_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(run_demo, "DASHBOARD_APP", tmp_path / "nope.py")
    names = [n for n, _, _ in run_demo.service_commands(_settings(), "aimfa")]
    assert "dashboard" not in names


def test_non_localhost_url_refused(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("started"))
    s = _settings(gateway_url="http://192.168.1.5:8100")
    assert run_demo.check_localhost(s) == ["gateway_url"]
    assert run_demo.main([], settings=s) == 2


def test_safe_reset(tmp_path):
    repo = tmp_path / "repo"
    var = repo / "var"
    var.mkdir(parents=True)
    (var / "aimfa.db").write_text("x")
    run_demo.safe_reset(var, repo_root=repo)
    assert not var.exists()


@pytest.mark.parametrize("bad", ["/", "~", ".."])
def test_safe_reset_refuses_dangerous(bad, tmp_path):
    from pathlib import Path

    path = Path.home() if bad == "~" else Path(bad)
    with pytest.raises(ValueError):
        run_demo.safe_reset(path, repo_root=tmp_path)


def test_safe_reset_refuses_outside_repo(tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    with pytest.raises(ValueError):
        run_demo.safe_reset(other, repo_root=tmp_path / "repo")
    assert other.exists()


@pytest.mark.parametrize("rel", ["aimfa", ".git", "var-other", "../var"])
def test_safe_reset_refuses_other_dirs_even_inside_or_named_var(rel, tmp_path):
    """Review fix: only <repo>/var and <repo>/keys may be wiped, never source dirs."""
    repo = tmp_path / "repo"
    target = repo / rel
    target.mkdir(parents=True)
    with pytest.raises(ValueError):
        run_demo.safe_reset(target, repo_root=repo)
    assert target.exists()


@pytest.mark.parametrize("mod", ["control_plane", "gateway", "resources"])
def test_zero_arg_factories_exist(mod):
    assert callable(importlib.import_module(f"aimfa.{mod}.app").app_factory)
