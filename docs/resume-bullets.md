# AgentGuard Resume Bullets

## Reader And Action

Reader: a candidate selecting truthful resume bullets for AgentGuard.

Post-read action: choose one version of the bullets and paste them into a resume or project description without overstating the implemented scope.

## Evidence Boundary

Use these bullets only for the current repository state:

- Implemented: MCP config scanning, tool metadata risk detection, policy decisions, FastAPI gateway, mock tool adapter, SQLite trace recording, replay evaluation, JSON/Markdown/SARIF reports, and sample reports.
- Implemented metrics: 85 replay cases, 7 categories, RiskRecall, FalsePositiveRate, PolicyViolationBlockRate, TraceCoverage, RedactionCoverage, latency overhead, and category pass rates.
- Not implemented yet: production MCP forwarding, distributed policy service, OS sandboxing, real enterprise deployment, hosted dashboard, or LLM-judge evaluation.

## Conservative Version

- Built AgentGuard from scratch as a local-first MCP tool security gateway, covering config scanning, tool metadata analysis, runtime policy decisions, trace recording, replay evaluation, and report generation.
- Implemented policy checks for path traversal, sensitive file access, dangerous shell commands, network egress, internal network targets, cross-tool exfiltration, and recursive secret redaction.
- Added a FastAPI runtime gateway with authorization and tool-call endpoints, structured error responses, mock adapter execution, and ordered trace events for policy decisions, tool calls, tool results, and adapter errors.
- Created an 85-case replay evaluation set across 7 safety categories and generated Markdown, JSON, and SARIF reports with total metrics, category pass rates, risk distribution, and failed-case details.

## Agent Infrastructure Version

- Designed an agent control-plane prototype for MCP tool trust, separating static tool-risk analysis, runtime policy enforcement, redacted trace capture, and replay-based safety evaluation.
- Built a rule-based policy engine that returns auditable allow/deny/confirm/redact decisions with risk tags, evidence records, redacted arguments, and regression coverage for high-risk tool-call patterns.
- Introduced a `ToolAdapter` boundary so gateway policy and trace behavior can be tested independently from real MCP execution, while preserving a clear extension point for future adapters.
- Established an evaluation harness for Agent safety regressions, including metadata poisoning cases, runtime policy cases, category-level metrics, failure examples, and machine-readable SARIF output.

## Avoid These Claims For Now

- Do not claim production deployment or real enterprise traffic.
- Do not claim real MCP forwarding until a non-mock adapter is implemented.
- Do not claim OS-level sandboxing or endpoint protection.
- Do not claim LLM-judge evaluation or semantic tool-selection scoring.
- Do not claim the system prevents all prompt injection; the implemented scope is policy enforcement and measurable regression coverage for defined tool risks.

