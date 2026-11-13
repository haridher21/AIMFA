"""Run one agent against the RUNNING demo services (start them with scripts/run_demo.py).

    python scripts/run_agent.py normal_expense
    python scripts/run_agent.py injected_expense     # prompt-injection victim (scripted)
    python scripts/run_agent.py wire_bot             # waits for you to approve on the phone
    python scripts/run_agent.py llm_expense          # real TAMU AI model, needs TAMU_AI_API_KEY

The agent goes through the real Launcher (measure + attest), so an unregistered or modified
agent is refused. The transcript shows tool, decision and reason code only: never keys,
tokens or file contents. Run it in its own shell, not as a child of run_demo.py.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:  # so `aimfa` and `scripts` import when run as a script
    sys.path.insert(0, str(REPO_ROOT))

from aimfa.agents.client import AimfaError  # noqa: E402
from aimfa.agents.launcher import (  # noqa: E402
    LAUNCHER_ID,
    MANIFEST_DIR,
    Launcher,
    load_manifest,
    load_or_create_launcher_key,
)
from aimfa.agents.scripted import injected_expense, normal_expense, wire_bot  # noqa: E402
from aimfa.common.config import Settings  # noqa: E402
from aimfa.common.models import ReasonCode  # noqa: E402
from scripts.run_demo import check_localhost  # noqa: E402

NOT_RUNNING = "services not running? start scripts/run_demo.py first"
LLM_TASK = (
    "Summarize the Q3 expenses found under /expenses, read any vendor notes there, "
    "and email the summary to finance@acme.test."
)
LLM_SCOPES = normal_expense.SCOPES


@dataclass(frozen=True)
class AgentSpec:
    """Which manifest to launch and how to drive it (a scripted module, or the LLM loop)."""

    name: str
    module: ModuleType | None  # None means "LLM-driven"

    @property
    def manifest_path(self) -> Path:
        return MANIFEST_DIR / f"{self.name}.yaml"


AGENTS: dict[str, AgentSpec] = {
    "normal_expense": AgentSpec("normal_expense", normal_expense),
    "injected_expense": AgentSpec("injected_expense", injected_expense),
    "wire_bot": AgentSpec("wire_bot", wire_bot),
    "llm_expense": AgentSpec("llm_expense", None),
}


def select_agent(name: str) -> AgentSpec:
    """Look up an agent by manifest name. Unknown names raise ValueError (never a guess)."""
    try:
        return AGENTS[name]
    except KeyError:
        raise ValueError(f"unknown agent {name!r}; choose from {sorted(AGENTS)}") from None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one AIMFA agent against the live demo.")
    parser.add_argument("manifest", choices=sorted(AGENTS))
    parser.add_argument(
        "--poll-timeout",
        type=float,
        default=120.0,
        help="seconds to wait for a human approval before giving up (default 120)",
    )
    parser.add_argument("--task", default=LLM_TASK, help="task text (llm_expense only)")
    args = parser.parse_args(argv)
    if args.poll_timeout <= 0:
        parser.error("--poll-timeout must be > 0")
    return args


def _print_entry(tool: str, decision: str, reason: str | None) -> None:
    print(f"  {tool:<15} {decision:<16} {reason or '-'}")


def run_spec(
    spec: AgentSpec,
    settings: Settings,
    *,
    poll_timeout: float,
    task: str = LLM_TASK,
    launcher_factory: Callable[..., Launcher] = Launcher,
) -> int:
    """Launch through the real Launcher, drive the agent, print the transcript."""
    manifest = load_manifest(spec.manifest_path)
    launcher = launcher_factory(settings, load_or_create_launcher_key(settings), LAUNCHER_ID)
    try:
        client = launcher.launch(manifest, poll_timeout=poll_timeout)
    except AimfaError as exc:
        print(f"launch refused: {exc.reason_code.value} (HTTP {exc.status_code})", file=sys.stderr)
        if exc.reason_code is ReasonCode.UPSTREAM_ERROR:
            print(NOT_RUNNING, file=sys.stderr)
        return 1
    print(f"agent {manifest.agent_id} attested; running {spec.name} ...")
    try:
        if spec.module is not None:
            for entry in spec.module.run(client):
                _print_entry(entry.tool, entry.decision, entry.reason_code)
        else:
            from aimfa.agents.llm import TamuAIClient  # imported late: needs the API key
            from aimfa.agents.llm_agent import run_llm_agent

            steps = run_llm_agent(
                client,
                TamuAIClient(settings),
                system_prompt=manifest.system_prompt,  # from the attested manifest only
                tools=manifest.tools,
                task=task,
                scopes=LLM_SCOPES,
            )
            for step in steps:
                _print_entry(step.tool, step.decision, step.reason_code)
    finally:
        client.close()
    return 0


def main(argv: list[str] | None = None, *, settings: Settings | None = None) -> int:
    args = parse_args(argv)
    settings = settings or Settings()
    not_local = check_localhost(settings)
    if not_local:
        print(f"Refusing to run: non-localhost URL in {', '.join(not_local)}", file=sys.stderr)
        return 2
    try:
        return run_spec(
            select_agent(args.manifest), settings, poll_timeout=args.poll_timeout, task=args.task
        )
    except httpx.TransportError:
        print(NOT_RUNNING, file=sys.stderr)
        return 1
    except ValueError as exc:  # e.g. TAMU_AI_API_KEY missing: message never contains the key
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
