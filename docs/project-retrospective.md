# AgentGuard Project Retrospective And Interview Q&A

## Reader And Action

Reader: a candidate or project owner preparing to present AgentGuard as an Agent infrastructure project.

Post-read action: explain the project with evidence, answer architecture and tradeoff questions, and avoid claims that are not implemented in the repository.

## Project Summary

AgentGuard is a local-first security and trajectory evaluation gateway for MCP-enabled agents. It focuses on the control plane around tool use:

- scan MCP server configuration and tool metadata before trust;
- enforce policy before runtime tool execution;
- record redacted policy, tool-call, result, and error traces;
- replay fixed safety cases and generate Markdown, JSON, and SARIF reports.

The project is intentionally not a general agent framework. It does not plan tasks, select business actions, host a production dashboard, or provide OS-level sandboxing. Its value is making tool trust, runtime enforcement, traceability, and regression evaluation explicit and testable.

## Implemented Evidence

| Area | Evidence In Repository |
|---|---|
| Config scanning | `agentguard/scanner.py`, `tests/test_scanner.py`, `examples/mcp.sample.json` |
| Metadata risk analysis | `agentguard/metadata.py`, `tests/test_metadata.py` |
| Runtime policy decisions | `agentguard/policy.py`, `tests/test_policy.py`, `examples/agentguard.yml` |
| Gateway and adapter boundary | `agentguard/gateway.py`, `agentguard/adapters.py`, `tests/test_gateway.py` |
| Redacted trace recording | `agentguard/trace.py`, gateway tests, evaluator trace coverage |
| Replay evaluation | `agentguard/evaluator.py`, `tests/fixtures/security_cases.jsonl`, `tests/test_evaluator.py` |
| Reports | `agentguard/reporting.py`, `docs/report-samples/`, `tests/test_reporting.py` |
| Public explanation | `README.md`, `docs/interview-guide.md`, `docs/resume-bullets.md` |

Current regression evidence:

- 85 replay cases across 7 safety categories.
- 99 pytest cases passing in the current local environment.
- Markdown, JSON, and SARIF sample evaluation reports.
- Gateway tests covering allow, deny, confirm, adapter error, trace order, and redaction behavior.

## Milestone Retrospective

M0 established a runnable Python package, CLI, FastAPI gateway skeleton, policy config, SQLite trace storage, evaluator, reporting module, and baseline docs.

M1 made MCP config scanning closer to real project inputs by supporting multiple config shapes, JSON/YAML, server-level risk records, and scan report formats.

M2 expanded static tool risk analysis with capability classification, description injection detection, and schema ambiguity scoring.

M3 turned risk rules into runtime policy decisions for filesystem access, shell execution, network egress, cross-tool exfiltration, and recursive secret redaction.

M4 closed the runtime loop with FastAPI contract tests, a `ToolAdapter` abstraction, mock execution, structured errors, ordered trace events, and adapter error recording.

M5 made the safety claims measurable through an 85-case replay set, category metrics, failure examples, and report samples.

M6 prepared public-facing material: README, interview guide, resume bullets, and this retrospective/Q&A document.

## Key Engineering Decisions

### Local-First Gateway

The first version stays local-first because the highest uncertainty is policy correctness and trace behavior, not distributed deployment. A local CLI plus FastAPI gateway is enough to demonstrate the core security loop and keep feedback fast.

### Rule-Based Policy Before LLM Judge

The evaluator uses deterministic cases and policy decisions instead of an LLM judge. This makes the first milestone reproducible: a path escape, dangerous shell command, or metadata host access should have a stable expected outcome.

### Mock Adapter First

The gateway uses a mock adapter by default. This avoids executing arbitrary external tools while the authorization, redaction, trace, and reporting loop is being validated. The `ToolAdapter` protocol keeps the extension point clear for a future real MCP adapter.

### Trace As Audit Layer

Trace events are not just logs. They prove whether a policy decision happened before a tool call, whether blocked requests avoided execution, whether adapter errors were captured, and whether secrets were redacted before storage.

### Reports As Reusable Evidence

Markdown helps humans review results, JSON supports automation, and SARIF leaves room for code-scanning style integrations. Reports are generated from structured results instead of handwritten summaries.

## Demo Script

Use these commands for a short local demo:

```powershell
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python -m ruff check .
.\.venv\Scripts\agentguard scan --config examples/mcp.sample.json
.\.venv\Scripts\agentguard eval --cases tests/fixtures/security_cases.jsonl --policy examples/agentguard.yml
```

The scan command should show server/tool risk distribution. The eval command should show 85 cases, aggregate metrics, and category pass rates.

## Interview Q&A

### Why did you build AgentGuard?

Tool-using agents move risk from only prompts into tools, schemas, server config, filesystem access, shell commands, and network egress. AgentGuard focuses on the layer that decides whether tools should be trusted, called, blocked, escalated, traced, and evaluated.

### What is the most important technical contribution?

The project connects four pieces into one measurable loop: static tool risk analysis, runtime policy enforcement, redacted trace recording, and replay evaluation. The important part is not a single rule; it is that policy claims are backed by tests, trace behavior, and reports.

### How does the runtime path work?

A caller sends a tool request to the gateway. The gateway creates a request id, calls the policy engine, records a policy decision, and only invokes the adapter if the action is allow or redact. Deny returns 403, confirm returns 409, and adapter failure returns 502 with a trace error event.

### How do you prevent secrets from leaking into traces?

The policy layer recursively redacts sensitive keys such as token, secret, password, and api_key in arguments and result summaries. Trace tests verify that original secrets are not stored and that redaction counts are preserved.

### How do you detect tool poisoning?

The metadata analyzer scans tool descriptions for instruction override, secret access, exfiltration, hidden prompt, system prompt, and developer message patterns. Tool-poisoning evaluation cases include tool metadata, so the evaluator can measure whether those risks are recalled.

### Why use deny, confirm, allow, and redact instead of only allow/deny?

Agent tool calls are not always binary. Some external network egress or broad write operations may be legitimate but should require confirmation. Redact keeps safe operations usable while removing sensitive values from records and downstream summaries.

### How do you control false positives?

Safe cases are included in the replay set and tracked through `FalsePositiveRate` and category pass rates. The policy also separates capability detection from risk tags so a tool can be capable of network access without automatically being treated as malicious in every context.

### How is this different from LangSmith or Langfuse?

Those tools are mainly observability and evaluation platforms for LLM applications. AgentGuard overlaps on trace and evaluation, but its center of gravity is pre-execution tool security enforcement for MCP-style tool calls.

### How is this different from MCP server safety?

MCP server safety is usually local to one server implementation. AgentGuard sits outside individual servers and applies consistent scanning, policy, trace, and evaluation behavior across multiple server configs and tools.

### What was the hardest tradeoff?

The hardest tradeoff was keeping the first version honest: use a mock adapter until policy and trace behavior are proven, instead of claiming production MCP forwarding too early. This keeps the demo narrower but makes the implemented evidence stronger.

### What would you build next?

The next practical step is a real MCP adapter spike behind the existing `ToolAdapter` protocol, followed by GitHub issues/roadmap cleanup, CI, and a small end-to-end demo that runs a safe local MCP server through the gateway.

### What should not be claimed yet?

Do not claim production deployment, real MCP forwarding, OS-level sandboxing, enterprise traffic, hosted dashboard, or LLM-judge evaluation. The current project is a local-first security gateway and replay evaluator with a mock adapter.

