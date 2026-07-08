# AgentGuard Roadmap

## Reader And Action

Reader: a developer deciding the next implementation slice after the current AgentGuard milestone.

Post-read action: pick the next GitHub issue in priority order, implement it, run verification, and update `docs/task-breakdown.md`.

## Current Baseline

Completed baseline:

- MCP config scanner, metadata analyzer, policy engine, FastAPI gateway, trace recorder, replay evaluator, reports, public README, interview/resume material, project retrospective, MCP adapter design, and a stdio MCP adapter spike.
- Public repository: <https://github.com/yourskenny/AgentGuard>
- Current verification: `pytest` 102 passed, `ruff check .` passed.

## Priority Order

### P0: CI Workflow And Badge

GitHub issue: [#1 Add CI workflow and README status badge](https://github.com/yourskenny/AgentGuard/issues/1)

Why next: every later slice should have remote verification instead of relying only on local checks.

Acceptance:

- GitHub Actions runs `python -m pytest` and `python -m ruff check .`.
- Workflow passes on `main`.
- README badge links to the workflow.

### P1: Minimal End-To-End Demo Script

GitHub issue: [#2 Build minimal end-to-end demo script](https://github.com/yourskenny/AgentGuard/issues/2)

Why next: the project needs one reproducible route that demonstrates scan, policy, gateway, MCP adapter, trace, and eval behavior.

Acceptance:

- One command or documented sequence runs locally on Windows.
- Demo includes one allowed safe MCP call and one denied risky call.
- Demo output avoids secret leakage.

### P2: Release Notes And Recording Script

GitHub issue: [#3 Prepare release notes and demo recording script](https://github.com/yourskenny/AgentGuard/issues/3)

Why next: public presentation material should be synchronized with real repo behavior before sharing the project.

Acceptance:

- Release note is committed under `docs/`.
- Recording script includes exact commands and expected observations.
- Claims stay inside the implemented boundary.

### P3: MCP Adapter Lifecycle Hardening

GitHub issue: [#4 Harden MCP adapter session and process lifecycle](https://github.com/yourskenny/AgentGuard/issues/4)

Why next: the current adapter intentionally starts as a spike. Production-like reliability needs lifecycle and process hardening.

Acceptance:

- Session pooling or explicit lifecycle management exists.
- Gateway shutdown cleans up owned resources.
- Timeout, result-size, and error paths have tests.
- Existing `ToolAdapter.execute()` gateway port stays stable.

## Execution Rule

Each issue should land as a focused commit with:

- implementation or document changes;
- `pytest` and `ruff check .` evidence;
- task-breakdown progress update;
- remote SHA verification after push.

