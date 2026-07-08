# AgentGuard Demo Recording Script

## Reader And Action

Reader: a project owner recording a 2-3 minute AgentGuard demo.

Post-read action: record a concise demo that shows the implemented loop without claiming production readiness.

## Setup

Use a clean terminal at the repository root.

```powershell
.\.venv\Scripts\python -m pip install -e .[dev]
```

Optional pre-check:

```powershell
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python -m ruff check .
```

## Recording Flow

### 0:00-0:20 Opening

Say:

AgentGuard is a local-first security gateway and replay evaluator for MCP-enabled agents. The goal is to make tool trust explicit: scan tools before trust, enforce policy before execution, record redacted traces, and replay safety cases.

### 0:20-0:45 Show Project Evidence

Run:

```powershell
.\.venv\Scripts\python scripts\demo_e2e.py
```

Point out:

- the scan step finds 3 MCP servers and risk tags;
- the gateway allows one safe MCP read through the real stdio adapter;
- the gateway denies one path traversal request before adapter execution;
- trace events are written;
- eval runs 85 cases with RiskRecall and FalsePositiveRate shown.

### 0:45-1:25 Explain The Architecture

Say:

The system has four parts. Scanner and metadata analysis run before trust. Policy runs before each tool call. The gateway only invokes the adapter after allow or redact decisions. Trace and replay evaluation provide evidence after the run.

The important boundary is that deny and confirm decisions never execute the adapter.

### 1:25-1:55 Show Generated Artifacts

Mention:

The demo writes scan, allowed-call, denied-call, trace, and evaluation artifacts under `runs/demo/`. These are ignored by git because they are local run outputs.

Open or mention:

```powershell
Get-ChildItem runs\demo
```

### 1:55-2:20 State The Safety Boundary

Say:

This is not an OS sandbox or production policy service. The MCP adapter is a stdio spike. The implemented evidence is the gateway behavior, redacted trace, replay dataset, reports, and CI. Production-like MCP forwarding still needs lifecycle hardening.

### 2:20-2:40 Close With Next Step

Say:

The next slice is hardening the MCP adapter: session pooling, process cleanup, health checks, timeout handling, and result-size limits while preserving the existing ToolAdapter boundary.

## Do Not Say

- Do not say AgentGuard is deployed in production.
- Do not say it prevents all prompt injection.
- Do not say it is an OS sandbox.
- Do not say the MCP adapter is production-ready.
- Do not say it has enterprise traffic or a hosted dashboard.

