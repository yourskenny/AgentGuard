# AgentGuard Threat Model

## Assets

- Local files and repository content.
- Environment variables and credentials.
- Agent instructions, user requests, and tool-call arguments.
- Tool results and trace records.
- External systems reachable by MCP tools.

## Trust Boundaries

1. User request to Agent runtime.
2. Agent runtime to AgentGuard gateway.
3. AgentGuard gateway to MCP server or tool backend.
4. AgentGuard trace storage to reports.
5. Local policy file to runtime enforcement.

## In-Scope Threats

### Tool Description Injection

An MCP tool description may contain hidden instructions that influence the model, such as asking it to ignore user intent, read secrets, or call another tool.

Mitigation: scan tool descriptions and schema descriptions for injection phrases and produce evidence-backed risks.

### Sensitive File Access

An agent may try to read `.env`, SSH keys, cookies, tokens, or files outside the approved workspace.

Mitigation: enforce allowed roots, deny patterns, path normalization, and default redaction.

### Dangerous Shell Execution

A shell-like tool may receive destructive commands or remote script execution.

Mitigation: deny known destructive patterns and treat arbitrary command fields as high-risk.

### Network Exfiltration

An agent may read local content and send it to an external URL.

Mitigation: classify POST/upload/webhook-like tools as confirm by default and tag cross-tool exfiltration risk in traces.

### Secret Environment Exposure

An MCP server config may expose sensitive env keys to a server with unclear provenance.

Mitigation: flag sensitive env keys during scan and recommend least-privilege policy.

### Over-Broad Schema

A schema with arbitrary `path`, `command`, `url`, or untyped object fields gives the model too much agency.

Mitigation: tag schema ambiguity and require runtime policy checks for sensitive parameter names.

## Out of Scope for M0

- Kernel-level sandboxing.
- Complete OAuth authorization flows.
- Malware analysis of binaries.
- Formal proof of policy correctness.
- Multi-tenant access control.

## Security Invariants

- Denied calls never reach the backend adapter.
- Trace records store summaries and redacted arguments by default.
- Every risk decision includes category, severity, evidence, and recommendation.
- Runtime policy must be enforced in the gateway, not only in CLI scan output.

