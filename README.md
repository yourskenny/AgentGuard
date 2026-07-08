# AgentGuard

AgentGuard is a lightweight security and trajectory evaluation gateway for MCP-enabled AI agents. It focuses on three jobs:

- Tool security gateway: scan MCP server config and tool metadata before an agent trusts them.
- Runtime trace black box: authorize tool calls, record policy decisions, and keep redacted call/result summaries.
- Replay evaluator: run safety regression cases and report measurable policy behavior.

The current milestone is intentionally local-first: a Python CLI, FastAPI gateway, SQLite trace recorder, structured risk records, JSON/Markdown/SARIF reports, and a replayable security case set.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .[dev]
.\.venv\Scripts\agentguard --help
.\.venv\Scripts\agentguard scan --config examples/mcp.sample.json
.\.venv\Scripts\agentguard eval --cases tests/fixtures/security_cases.jsonl --policy examples/agentguard.yml
```

## CLI

- `agentguard scan`: parse MCP configuration and produce tool/server risk findings.
- `agentguard inspect`: inspect a single server from a scanned config.
- `agentguard proxy`: start a local FastAPI policy gateway.
- `agentguard eval`: replay JSONL security cases through the policy engine.
- `agentguard report`: generate an empty or run-scoped report shell.

## Scan Example

```powershell
.\.venv\Scripts\agentguard scan --config examples/mcp.sample.json
```

Excerpt:

```text
- Servers: 3
- Tools: 3
- Risk tags: network_exfiltration, schema_ambiguity, secret_env_exposure, tool_description_injection

## Risk Distribution

- `network_exfiltration`: 1
- `schema_ambiguity`: 6
- `secret_env_exposure`: 1
- `tool_description_injection`: 1
```

## Eval Example

```powershell
.\.venv\Scripts\agentguard eval --cases tests/fixtures/security_cases.jsonl --policy examples/agentguard.yml
```

Excerpt:

```text
- Total cases: 85
- RiskRecall: 100.00%
- FalsePositiveRate: 0.00%
- PolicyViolationBlockRate: 100.00%
- TraceCoverage: 100.00%

## Category Metrics

- `broad_filesystem_scope`: 10/10 passed (100.00%)
- `tool_poisoning`: 20/20 passed (100.00%)
```

## Safety Boundaries

- AgentGuard is a policy gateway and evaluator, not a full OS sandbox, EDR, or container isolation layer.
- The default adapter is a mock adapter for local demonstration; production MCP forwarding should implement the `ToolAdapter` protocol.
- Trace data is redacted by policy and stores summaries, but the SQLite trace DB should still be treated as sensitive operational data.
- Replay metrics measure configured policy behavior; they are not a substitute for a human security review of new tools or policies.

## Docs

- [Architecture](docs/architecture.md)
- [API Contract](docs/api-contract.md)
- [Threat Model](docs/threat-model.md)
- [Evaluation](docs/evaluation.md)
- [Interview Guide](docs/interview-guide.md)
- [Resume Bullets](docs/resume-bullets.md)
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
