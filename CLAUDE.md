@AGENTS.md

## Claude Code specifics
- **Before starting work:** read `docs/ROADMAP.md` to find the task and its acceptance criteria. Then read the package `README.md` for the package you'll touch.
- **Use the project subagents in `.claude/agents/`** for the three-role loop:
  - `test-writer`: writes failing tests from acceptance criteria. Spawn it first, in a fresh context.
  - `implementer`: makes the tests pass. It must not edit tests or contracts.
  - `security-reviewer`: read-only review of the diff against the security rules.
- **Before opening a PR:** run `/code-review` and `/security-review`, plus `pytest`, `ruff check .` and `bandit -q -ll -r aimfa -c pyproject.toml`.
- **Git:** local commits are fine. **Never `git push`, open PRs, or modify remotes.** The user does that manually.
- **Shell:** this team works on Windows. Prefer Python scripts over shell scripts, and don't assume `make` exists.
- **Writing for the team:** they are students new to security. In PR descriptions and chat summaries, explain security concepts in plain English and link to `docs/LEARNING.md`.
