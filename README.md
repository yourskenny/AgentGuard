# AgentGuard

AgentGuard is a lightweight security and evaluation gateway for MCP-enabled AI agents. It scans MCP server configuration, analyzes tool metadata, enforces runtime policy before tool execution, records tool-call traces, and evaluates safety behavior through replayable cases.

The first milestone is intentionally small: a Python CLI, local FastAPI gateway, structured risk records, JSON/Markdown/SARIF reports, and a security regression set.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .[dev]
.\.venv\Scripts\agentguard --help
.\.venv\Scripts\agentguard scan --config examples/mcp.sample.json
.\.venv\Scripts\agentguard eval --cases tests/fixtures/security_cases.jsonl --policy examples/agentguard.yml
```

## Current Skeleton

- `agentguard scan`: parse MCP configuration and produce tool/server risk findings.
- `agentguard inspect`: inspect a single server from a scanned config.
- `agentguard proxy`: start a local FastAPI policy gateway.
- `agentguard eval`: replay JSONL security cases through the policy engine.
- `agentguard report`: generate an empty or run-scoped report shell.

## Docs

- [Architecture](docs/architecture.md)
- [API Contract](docs/api-contract.md)
- [Threat Model](docs/threat-model.md)
- [Evaluation](docs/evaluation.md)
- [Implementation Plan](docs/implementation-plan.md)
- [Task Breakdown](docs/task-breakdown.md)

## Report Samples

- [Evaluation Markdown](docs/report-samples/evaluation-sample.md)
- [Evaluation JSON](docs/report-samples/evaluation-sample.json)
- [Evaluation SARIF](docs/report-samples/evaluation-sample.sarif.json)

## Development Checks

```powershell
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python -m ruff check .
```
