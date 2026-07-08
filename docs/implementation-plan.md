# AgentGuard Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first runnable AgentGuard skeleton: CLI, models, scanner, policy engine, gateway, trace recorder, evaluator, reporting, examples, and tests.

**Architecture:** The codebase uses a small Python package with Pydantic models at the center. CLI, API, scanner, policy, trace, evaluator, and reports communicate through those models rather than ad hoc dicts.

**Tech Stack:** Python 3.11+, Typer, FastAPI, Pydantic, PyYAML, SQLite, pytest.

---

### Task 1: Project and Documentation Skeleton

**Files:**
- Create: project metadata, README, docs, examples, fixtures.

- [x] Create Python packaging metadata with runtime and dev dependencies.
- [x] Add README with setup, CLI, docs, and test commands.
- [x] Add architecture, API contract, threat model, and evaluation docs.
- [x] Add policy and MCP configuration examples.

### Task 2: Core Data Models

**Files:**
- Create: `agentguard/models.py`

- [x] Define normalized server, tool, risk, tool-call, policy, trace, and evaluation models.
- [x] Use stable enum values for decision, severity, and final status.
- [x] Use camelCase aliases for HTTP JSON while retaining Pythonic field names internally.

### Task 3: Scanner and Metadata Analyzer

**Files:**
- Create: `agentguard/scanner.py`
- Create: `agentguard/metadata.py`

- [x] Parse `mcpServers` and `servers` config styles.
- [x] Normalize command, args, env keys, source, and tools.
- [x] Infer static risk tags from tool names, descriptions, schemas, commands, and env keys.

### Task 4: Policy Engine

**Files:**
- Create: `agentguard/config.py`
- Create: `agentguard/policy.py`

- [x] Load YAML policy with safe defaults.
- [x] Deny sensitive files, path traversal, dangerous shell, and explicit deny tools.
- [x] Confirm network exfiltration and write operations by default.
- [x] Redact sensitive argument values.

### Task 5: Gateway, Trace, Evaluation, Reporting, CLI

**Files:**
- Create: `agentguard/gateway.py`
- Create: `agentguard/trace.py`
- Create: `agentguard/evaluator.py`
- Create: `agentguard/reporting.py`
- Create: `agentguard/cli.py`

- [x] Expose FastAPI gateway endpoints under `/v1`.
- [x] Store trace events in SQLite.
- [x] Replay JSONL evaluation cases through Policy Engine.
- [x] Render Markdown, JSON, and SARIF reports.
- [x] Wire CLI commands to all skeleton modules.

### Task 6: Verification

**Files:**
- Create: `tests/`

- [x] Add scanner, policy, evaluator, reporting, and CLI smoke tests.
- [x] Run `python -m pytest`.
- [x] Run `agentguard --help`.
- [x] Run `agentguard scan --config examples/mcp.sample.json`.
