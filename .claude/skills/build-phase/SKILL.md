---
name: build-phase
description: Build one AIMFA ROADMAP phase end-to-end with the test-writer → implementer → security-reviewer loop, one LOCAL commit per task (never pushes), then report to the team in plain English. Usage /build-phase <phase number>, e.g. /build-phase 1
argument-hint: "<phase number 1-8>"
disable-model-invocation: true
---

# /build-phase $ARGUMENTS

You are the **orchestrator** for one phase of AIMFA. The team are students new to security. They will read your final report to learn what was built, so write it for them.

## 0. Pre-flight (stop and ask the user if any check fails)
1. **Parse the arguments.** The first token of `$ARGUMENTS` is the phase number N.
   - **NEVER run `git push`, open a PR, or touch any remote.** The user pushes manually. Local commits only.
2. **Read the docs:** `docs/ROADMAP.md`, `AGENTS.md`, and the package READMEs for the phase's packages.
3. **Check dependencies.** Every task in phases < N must be checked off, **except** T0.6 (CI) and Phase 7–8 polish items. If an earlier core task is unchecked, stop and say which one.
4. **Check git:** run `git status`.
   - **Uncommitted changes:** show the user a summary, and **ask** whether to commit them first as `Phase <N-1> wrap-up` or stop.
   - **On `main`:** create and switch to `phase-N-<short-slug>`.
   - **Otherwise:** stay on the current branch.
5. **Check the baseline:** run `.venv\Scripts\python -m pytest -q` (or `.venv/bin/python` on macOS/Linux). If the baseline is red, stop and report.

## 1. Plan the phase
- **List the phase's unchecked tasks in dependency order.** Tasks marked **∥** whose dependencies are met can be done in parallel.
- **Tell the user the plan in 3–6 lines** (tasks, order, what gets parallelized), then proceed. Don't wait for approval; the user already asked you to build this phase.

## 2. For each task (in order; run ∥ siblings' steps in parallel where possible)
1. **Tests first.** Spawn the `test-writer` subagent:
   > Task <ID> from docs/ROADMAP.md. Write the failing tests. Report files, test count, and assumptions.

   Then check that the new tests fail only because of a missing implementation (`ImportError` / `NotImplementedError`), not because of syntax or fixture errors. Skim them for obvious spec mismatches. If a test contradicts ROADMAP or CONTRACTS, fix it via a new test-writer message, never by asking the implementer.
2. **Implement.** Spawn the `implementer` subagent:
   > Task <ID>. Tests are in <files>. Make them pass. Do not edit tests or contracts.

   If it reports that a test or contract is wrong:
   - **The test is wrong:** send it back to the test-writer with the reason.
   - **The contract is wrong:** **stop the phase** and ask the user, because contracts are frozen.
3. **Verify it yourself.** Don't trust the subagent's word; run:
   - `pytest -q` (full suite)
   - `ruff check .`
   - `ruff format --check .`
   - `bandit -q -ll -r aimfa scripts -c pyproject.toml`

   If anything fails, send the output back to the implementer.
4. **Security review.** Spawn the `security-reviewer` subagent on the uncommitted changes for this task. Tell it to use `git diff` plus the untracked files instead of `main...HEAD`.
   - **Critical, high or medium findings:** send them to the implementer (continue the same implementer via SendMessage if possible), then re-verify (step 3) and re-review once.
   - **Low findings:** fix them if cheap; otherwise list them as accepted risks in the report.
5. **Commit.** Tick the task in `docs/ROADMAP.md`. Make sure the implementer updated the package README and LEARNING.md where relevant. Then commit **only this task's files** with the message:
   ```
   T<ID>: <task title>

   <2-4 line plain-English summary>
   ```
   End it with the co-author attribution line required by the session.

**Guardrails:**
- **Never weaken a test or a security check** to get green.
- **Never edit frozen files** (`aimfa/common/models.py`, `docs/CONTRACTS.md`, `policy/*.yaml`) without the user's approval.
- **Never commit `.env`, `keys/` or `var/`.**
- **If a task fails 3 implement/verify rounds,** stop and report the blocker instead of looping.

## 3. Phase wrap-up
1. **Run the full checks once more,** plus `pytest -q --co | tail -1` for the test count.
2. **Run a correctness review:** invoke the `code-review` skill at `medium` on the phase's commits, if it's available. Fix any confirmed bugs as an extra commit `Phase N: review fixes`.
3. **Update `docs/LEARNING.md` §5** ("How to read the code") with the phase's new files.
4. **Do not push.** Instead, draft a PR description following `.github/pull_request_template.md`, with one section per task. Save it to `docs/pr/phase-N.md` so the user can paste it when they push and open the PR themselves.

## 4. Final report to the user (plain English, ≤ 40 lines)
- **What this phase built**, as an analogy first (the checkpoint / badge / guard story from LEARNING.md), then the technical names.
- **A task table:** ID, what it does, tests added, commit hash.
- **"Try it yourself":** 1–3 commands a teammate can run to see it work, e.g. a specific `pytest -k` that shows an attack being rejected.
- **Security findings:** fixed vs accepted.
- **What's next:** the next phase number, and anything the team must do first (keys, phone apps, decisions).
- **Reminder:** the branch name and commit count are ready for the user to push manually, and the PR draft is at `docs/pr/phase-N.md`.
