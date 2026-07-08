# AgentGuard Release Notes

## Reader And Action

Reader: a project owner preparing to publish or share the current AgentGuard milestone.

Post-read action: describe what is implemented, show the verification evidence, and avoid overstating production readiness.

## Current Milestone

AgentGuard is a local-first security and trajectory evaluation gateway for MCP-enabled agents. The current milestone turns the initial research direction into a runnable project with four connected loops:

- static MCP config and tool metadata scanning;
- runtime policy decisions before tool execution;
- redacted trace capture for policy/tool/result/error events;
- replay evaluation with measurable safety metrics.

The project now also includes a stdio MCP adapter spike, a safe local MCP fixture, a CI workflow, an end-to-end demo script, report samples, and public-facing interview/resume material.

## What Is Implemented

- CLI commands for scanning MCP config, inspecting one server, starting the gateway, running replay evaluation, and generating report shells.
- Static risk analysis for sensitive environment keys, dangerous server startup commands, tool description injection, broad path/url/command schemas, and tool capability classification.
- Runtime policy handling for filesystem path scope, sensitive files, dangerous shell commands, network egress, internal network targets, cross-tool exfiltration, and recursive secret redaction.
- FastAPI gateway endpoints for authorization, tool calls, trace writes, and run trace reads.
- Adapter boundary with the default mock adapter plus an optional stdio MCP adapter spike.
- SQLite trace recording with redacted argument and result summaries.
- Replay evaluation across 85 security cases and 7 categories.
- Markdown, JSON, and SARIF reports.
- GitHub Actions CI for pytest and ruff.
- A local end-to-end demo script that exercises scan, real MCP adapter gateway call, deny behavior, trace, and eval.

## Verification Evidence

Latest local verification:

- `python -m pytest`: 102 passed, 1 upstream TestClient deprecation warning.
- `python -m ruff check .`: passed.
- `python scripts/demo_e2e.py`: generated scan, gateway, trace, and evaluation artifacts under `runs/demo/`.
- Demo output secret-value scan: no matching secret value patterns found.

Latest remote verification:

- GitHub Actions CI passed on `main`.

## Safety Boundary

AgentGuard is not a full OS sandbox, EDR, production policy service, or hosted dashboard.

The stdio MCP adapter is a local spike. It proves that an approved gateway call can reach a real MCP server through the MCP Python SDK v1.x, but it still needs session pooling, process lifecycle cleanup, startup health checks, result-size limits, and stronger timeout handling before production-like use.

Replay metrics measure configured policy behavior. They are useful regression evidence, but they do not replace human security review for new tools, policies, or MCP servers.

## Recommended Public Summary

AgentGuard is a local-first MCP tool security gateway and replay evaluator. It scans MCP configs and tool metadata, blocks or escalates risky tool calls before execution, stores redacted traces, and measures policy behavior with replayable safety cases. The current version includes a FastAPI gateway, CLI, SQLite trace store, JSON/Markdown/SARIF reports, GitHub Actions CI, and a stdio MCP adapter spike for a safe local MCP server.

## Next Work

The next engineering slice is MCP adapter lifecycle hardening: pooled sessions, process cleanup, startup health checks, timeout behavior, and result-size limits.

