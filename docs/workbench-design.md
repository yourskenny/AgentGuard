# AgentGuard Demo Workbench Design

## Reader And Action

Reader: a developer or demo owner who wants to build the first AgentGuard workbench without turning it into a production control plane too early.

Post-read action: implement the static interactive workbench first, while preserving the seams needed to upgrade it into a live gateway console later.

## Decision

Build the first workbench as a static interactive demo, then evolve it into a live gateway console.

The first version should explain AgentGuard clearly:

- what the architecture is;
- how an MCP configuration becomes risk evidence;
- how a tool call moves through policy, gateway, adapter, trace, and evaluation;
- why the current security decisions are explainable and measurable.

It should not execute arbitrary user-supplied tools, manage long-lived MCP processes from the browser, or imply production isolation. Those belong to the later live console.

## Why Static First

The project already has a reliable local demo path, sample scan output, a gateway allow/deny trace, and replay evaluation metrics. A static interactive workbench can turn those artifacts into a clean product narrative with low operational risk.

A live console is useful, but it introduces process management, browser-to-gateway connectivity, failure recovery, CORS, and user-controlled tool input. Those are real product concerns. Starting with a static workbench lets the project prove the story before adding that surface area.

## Workbench V1 Scope

The workbench is a local frontend surface backed by checked-in sample data.

It should contain five views.

### 1. Overview

Purpose: give the viewer the one-screen mental model.

Content:

- AgentGuard as a tool security gateway, trace black box, and replay evaluator.
- Current status: local-first MVP, not a production sandbox.
- One primary demo path: scan, gateway decision, trace, evaluation.

### 2. Architecture Map

Purpose: show the system chain.

Flow:

```text
MCP config -> Scanner -> Metadata Analyzer -> Policy Engine -> Gateway -> Adapter -> Trace Recorder -> Evaluator -> Reports
```

The map should make these boundaries obvious:

- Scanner and metadata analysis are static.
- Policy engine is the runtime decision point.
- Gateway is the HTTP boundary.
- Adapter is the only execution boundary.
- Trace and evaluation are evidence surfaces.

### 3. Risk Network

Purpose: show how servers, tools, and risk tags connect.

The first dataset can use the current demo shape:

- safe filesystem server with a read tool;
- poisoned tool example with description and network risks;
- shell example with schema ambiguity;
- risk tags including network exfiltration, schema ambiguity, secret environment exposure, and tool description injection.

The UI should treat this as graph-like data, even if the first implementation renders it as cards or rows. That keeps the path open for later network visualization.

### 4. Call Flow Simulator

Purpose: show how the gateway handles an allowed call and a denied call.

The first version uses fixed scenarios:

- allowed read of a repository file through the MCP adapter;
- denied parent traversal attempt against a sensitive path.

For each scenario, show:

- request summary;
- policy action;
- risk evidence;
- whether adapter execution happened;
- resulting trace events.

The important concept is not free-form execution. The important concept is explaining why one call is allowed and the other stops before the adapter.

### 5. Evaluation Dashboard

Purpose: show measurable policy behavior.

Display:

- total replay cases;
- risk recall;
- false positive rate;
- policy violation block rate;
- trace coverage;
- category pass rates.

The dashboard should present the metrics as evidence from replay evaluation, not as a security guarantee for all possible tools.

## Data Model

Design the frontend around a stable data boundary, even if V1 data is static.

Core data groups:

- `architecture`: nodes, edges, component descriptions, and design notes;
- `servers`: MCP servers, commands, tools, environment key summaries, and server-level risks;
- `toolRisks`: tool capabilities, risk tags, evidence, recommendations, and scores;
- `callScenarios`: request summary, policy decision, adapter result or error, and trace event sequence;
- `evaluation`: metrics, category metrics, risk distribution, and failed cases.

In V1, these can be loaded from local JSON fixtures generated from the existing demo artifacts.

In the live console, the same groups should be populated from gateway and report APIs instead of bundled fixtures.

## B To C Upgrade Path

The B-to-C path should be explicit from day one.

### Phase B1: Static Interactive Workbench

Use bundled sample data. No backend dependency is required after install.

Capabilities:

- navigate views;
- inspect sample servers and risks;
- switch between allowed and denied call scenarios;
- inspect trace event order;
- inspect evaluation metrics.

### Phase B2: Refreshable Demo Data

Keep the UI static, but add a command that regenerates the workbench data from the local demo artifacts.

Capabilities:

- run the existing demo command;
- transform scan, trace, gateway, and evaluation outputs into workbench fixture data;
- keep the browser app independent from live process control.

### Phase C1: Read-Only Live Gateway Mode

Add optional live connectivity to a running local gateway.

Capabilities:

- show gateway health;
- fetch traces by run id;
- display recent policy decisions;
- display adapter health if exposed.

Constraints:

- no arbitrary tool execution from the browser yet;
- no browser-managed MCP process lifecycle;
- clear offline and error states.

### Phase C2: Controlled Live Execution

Allow the workbench to submit pre-defined safe scenarios to the local gateway.

Capabilities:

- execute curated allow/deny scenarios;
- show live policy decision and trace updates;
- compare live output to expected baseline.

Constraints:

- no free-form command, path, URL, or shell input;
- no raw secret display;
- scenario definitions must be reviewed fixtures.

### Phase C3: Operator Console

Only after C1 and C2 are stable, expand toward a real control plane.

Potential capabilities:

- configured MCP server status;
- session lifecycle visibility;
- run history;
- richer trace search;
- policy tuning workflow;
- exportable audit reports.

This phase should be treated as product work, not demo work.

## Component Boundaries

Keep the workbench implementation split into clear ownership areas.

- App shell: navigation, layout, responsive structure.
- Data adapter: loads static data in V1 and can later load live API data.
- Architecture view: renders system nodes and chain explanations.
- Risk view: renders server, tool, and risk relationships.
- Call flow view: renders scenario comparison and trace sequence.
- Evaluation view: renders metrics and category breakdowns.
- Copy and explanation content: kept near the data model, not scattered through one large component.

The key design constraint is that V1 must not bake sample data directly into view components. Views should receive normalized workbench data. That makes the later live mode a data-source change instead of a rewrite.

## Error And Empty States

Even the static workbench should model future live states.

Required states:

- no data loaded;
- malformed fixture data;
- live gateway unavailable;
- live gateway reachable but adapter unhealthy;
- evaluation report missing;
- trace run not found.

V1 can render these states from toggles or sample variants. C can bind them to real API failures.

## Testing And Verification

V1 verification should prove three things:

- the frontend builds and loads locally;
- each view renders the expected sample data;
- the user can complete the demo narrative without relying on hidden terminal output.

Recommended checks:

- unit or smoke tests for data normalization;
- a browser smoke test for the primary views;
- a local run command documented in README;
- no claims that exceed the static demo boundary.

C-phase verification will add API contract tests against the gateway and live failure-mode tests.

## Non-Goals For V1

The first workbench will not:

- execute arbitrary tools from browser input;
- manage production MCP server lifecycles;
- replace CLI or API tests;
- provide authentication or multi-user access;
- store traces in a hosted database;
- claim to be a production security operations platform.

## Acceptance For V1

The first implementation is complete when:

- the workbench can be launched locally with one documented command;
- the five primary views exist;
- sample data covers architecture, risk network, allow/deny scenarios, trace sequence, and evaluation metrics;
- README links the workbench;
- tests or smoke checks verify the workbench loads;
- the UI language preserves the local-first MVP boundary;
- the B-to-C upgrade path remains visible in this document.
