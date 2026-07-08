# AgentGuard Demo Artifacts Snapshot

This snapshot captures stable excerpts from:

```powershell
.\.venv\Scripts\python scripts\demo_e2e.py
```

The raw demo output is written under `runs/demo/`, which is intentionally ignored by git. Re-run the command to regenerate the local artifacts.

## Scan Snapshot

Source artifact: `runs/demo/scan.md`

- Servers: 3
- Tools: 3
- Risk tags: `network_exfiltration`, `schema_ambiguity`, `secret_env_exposure`, `tool_description_injection`

Risk distribution:

- `network_exfiltration`: 1
- `schema_ambiguity`: 6
- `secret_env_exposure`: 1
- `tool_description_injection`: 1

## Gateway Snapshot

Source artifacts: `runs/demo/allowed-call.json`, `runs/demo/denied-call.json`

Allowed call:

- server: `safe-filesystem`
- tool: `read_file`
- argument summary: `{"path": "README.md"}`
- decision: `allow`
- adapter: `mcp`

Denied call:

- server: `safe-filesystem`
- tool: `read_file`
- argument summary: `{"path": "../.env"}`
- HTTP error code: `policy_denied`
- risk tags: `broad_filesystem_scope`, `sensitive_file_access`

## Trace Snapshot

Source artifact: `runs/demo/trace.json`

Trace event sequence:

```text
policy_decision -> tool_call -> tool_result -> policy_decision
```

The first three events represent the approved MCP call. The final `policy_decision` is the denied path traversal attempt, which does not produce a `tool_call` or `tool_result`.

## Evaluation Snapshot

Source artifacts: `runs/demo/evaluation.md`, `runs/demo/evaluation.json`

- Total cases: 85
- RiskRecall: 100.00%
- FalsePositiveRate: 0.00%
- PolicyViolationBlockRate: 100.00%
- TraceCoverage: 100.00%
- Failed cases: none

Category pass rates:

- `broad_filesystem_scope`: 10/10 passed
- `cross_tool_exfiltration`: 5/5 passed
- `dangerous_shell`: 10/10 passed
- `network_exfiltration`: 10/10 passed
- `normal`: 20/20 passed
- `sensitive_file_access`: 10/10 passed
- `tool_poisoning`: 20/20 passed

## Interpretation Boundary

This is a reproducible local demo snapshot, not a hosted benchmark. The metrics prove the current checked-in policy behavior on the checked-in fixture cases; they do not prove coverage for arbitrary third-party MCP servers or enterprise traffic.
