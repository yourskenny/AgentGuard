# AgentGuard Interview Guide

## Reader And Action

Reader: a candidate preparing to explain AgentGuard in an interview.

Post-read action: explain the project in 30 seconds, 2 minutes, or 5 minutes, then answer common follow-up questions about architecture, policy, trace, evaluation, and product boundaries.

## One-Sentence Positioning

AgentGuard is a lightweight security gateway and replay evaluation system for MCP-enabled agents: it checks tool metadata before trust, enforces policy before runtime tool execution, records redacted traces, and proves behavior with replayable safety cases.

## 30-Second Version

AgentGuard solves a concrete Agent infrastructure problem: once an agent can call MCP tools, tool descriptions, schemas, filesystem access, shell commands, and network egress all become part of the attack surface.

I built a local-first gateway that scans MCP configs, detects risky tool metadata, blocks or escalates risky runtime calls, records redacted traces, and replays a regression set to measure policy behavior. The current version has a Python CLI, FastAPI gateway, SQLite trace recorder, JSON/Markdown/SARIF reports, and 85 replay cases covering normal calls, tool poisoning, path escape, sensitive files, dangerous shell, network egress, and cross-tool exfiltration.

## 2-Minute Version

The project starts from a practical gap in Agent systems. Many demos focus on whether an agent can call tools, but production risk is about whether the agent should trust and execute those tools. MCP makes tool integration easier, but it also introduces tool poisoning, ambiguous schemas, broad filesystem scope, shell execution, network exfiltration, and trace blind spots.

AgentGuard has four layers.

First, the scanner normalizes MCP server config, extracts server/tool metadata, and reports static risks such as injected tool descriptions, dangerous startup commands, sensitive environment exposure, and ambiguous input schemas.

Second, the policy engine evaluates each runtime tool call. It can allow, deny, require confirmation, or redact. The implemented policies cover path normalization, sensitive file patterns, dangerous shell commands, network egress, internal network access, cross-tool exfiltration, and recursive secret redaction.

Third, the runtime gateway exposes HTTP endpoints for authorization and tool calls. Allowed calls go through a `ToolAdapter` abstraction. The default adapter is a mock adapter so the gateway loop can be demonstrated safely, while the interface leaves room for a real MCP adapter.

Fourth, the trace and evaluation loop records policy decisions, tool calls, results, and errors into a SQLite trace store. The replay evaluator runs JSONL safety cases and produces metrics such as RiskRecall, FalsePositiveRate, PolicyViolationBlockRate, TraceCoverage, RedactionCoverage, and per-category pass rates.

The result is not just a rule list. It is a measurable security gateway: every policy claim has a regression case, report output, and trace behavior behind it.

## 5-Minute Architecture Walkthrough

### 1. Problem

The risk is not only prompt injection in user text. In tool-using agents, the tool layer itself can carry instructions and capabilities:

- Tool descriptions can tell the model to ignore the user or leak secrets.
- Schemas can expose broad `path`, `command`, or `url` parameters.
- MCP server config can pass sensitive environment variables or run unsafe startup commands.
- Runtime calls can attempt path traversal, read sensitive files, run destructive shell commands, or send prior tool output to an external URL.
- Without trace discipline, teams cannot later prove why a tool call was allowed or blocked.

### 2. Architecture

AgentGuard is split into scanner, metadata analyzer, policy engine, gateway, trace recorder, evaluator, and report generator.

The scanner and metadata analyzer run before trust. They convert MCP config and tool metadata into structured server, tool, and risk records. This layer catches risks before the agent ever calls a tool.

The policy engine runs at runtime. It evaluates a normalized tool call request and returns a structured decision with action, reason, risk tags, detailed risks, redacted arguments, and redaction count.

The gateway wraps the policy engine behind FastAPI endpoints. `authorize` records only policy decisions and never executes tools. `tool-calls` records policy decisions, blocks deny/confirm outcomes, and only executes the adapter for allow/redact outcomes.

The adapter layer is intentionally abstract. The current mock adapter proves the gateway control loop without making external tool calls. A real MCP adapter can implement the same interface later.

The trace recorder stores ordered events by run id: policy decision, tool call, tool result, and tool error. Stored arguments and result summaries are redacted.

The evaluator replays JSONL cases through the policy engine and metadata analyzer. Reports are emitted as Markdown, JSON, and SARIF.

### 3. Policy Examples

Filesystem policy denies parent traversal, absolute paths outside the allowed root, unsupported Windows path forms, and sensitive names such as env files, SSH keys, PEM keys, and cookies.

Shell policy denies dangerous command patterns, including recursive deletes, format/mkfs, recursive chmod/chown, remote script pipes, PowerShell download-and-execute, and encoded commands.

Network policy requires confirmation for external egress, denies localhost/private/link-local/metadata hosts, supports an allowlist, and flags cross-tool exfiltration when prior tool output is sent externally.

Redaction recursively replaces sensitive keys such as token, secret, password, and api_key in arguments and tool result summaries.

### 4. Trace And Evaluation

Trace is the audit layer. For an allowed tool call, the expected event order is policy decision, tool call, and tool result. For a blocked request, there is a policy decision but no tool result. For adapter failures, there is a tool error event.

Evaluation is the proof layer. The regression set currently has 85 cases across seven categories. The report shows total metrics, per-category pass rates, risk distribution, failed cases, and case-level expected versus actual decisions.

### 5. Why This Matters

For Agent engineering, this is infrastructure around the agent, not another agent demo. It makes tool trust, runtime enforcement, traceability, and regression evaluation explicit and testable.

## Common Follow-Up Questions

### How is this different from a business Agent?

A business Agent solves a domain workflow, such as support, sales, analytics, or coding. AgentGuard is control-plane infrastructure for those agents. It does not decide business actions; it decides whether a tool should be trusted, called, blocked, escalated, traced, and evaluated.

### How is this different from LangSmith or Langfuse?

LangSmith and Langfuse are mainly observability, tracing, evaluation, and debugging platforms for LLM applications. AgentGuard overlaps on trace and evaluation, but its core focus is MCP tool security enforcement: scanning tool metadata, making pre-execution policy decisions, redacting sensitive fields, and blocking risky calls before execution.

### How is this different from MCP server built-in safety?

MCP server safety is local to one server implementation. AgentGuard sits outside individual servers and applies a consistent gateway policy across configs, metadata, runtime calls, traces, and replay cases. That matters when an agent uses multiple third-party or internal MCP servers with different quality levels.

### Why not just rely on prompt rules?

Prompt rules are advisory. AgentGuard turns safety expectations into code-level policy decisions and regression tests. A dangerous shell command or path escape should be blocked by the gateway even if the model was persuaded to call it.

### What is the most important engineering tradeoff?

The project keeps the first adapter as a mock adapter. That avoids pretending to safely execute arbitrary MCP tools before the policy, trace, and evaluation loop is proven. The tradeoff is that real MCP forwarding is a later adapter implementation, but the interface is already isolated.

### What are the current limitations?

It is not a full sandbox, endpoint security tool, or distributed policy service. It does not replace human review of new tools. The current runtime adapter is mock-only. The evaluator measures configured policy behavior rather than using an LLM judge.

### What evidence proves it works?

The strongest evidence is the regression loop: tests cover scanner, metadata analysis, policy decisions, gateway behavior, trace redaction, evaluator metrics, reporting, and sample reports. The replay dataset covers 85 cases and produces category-level metrics and failure examples.

