# AgentGuard API Contract

## Scope

The HTTP API is a local runtime gateway for agent tool calls. Callers are same-machine agent runtimes, integration tests, or local developer tooling. The first version uses path versioning under `/v1`.

Authentication is disabled for local MVP usage. Before remote exposure, the gateway must require an API key or mTLS and reject non-loopback traffic by default.

## Error Shape

All non-2xx responses use one error envelope:

```json
{
  "error": {
    "code": "policy_denied",
    "message": "Tool call was blocked by policy",
    "details": {
      "decision": "deny",
      "risk_tags": ["sensitive_file_access"]
    },
    "requestId": "req_..."
  }
}
```

`code` is stable and machine-readable. `message` is human-readable. `details` may vary by endpoint. `requestId` is always present.

## Endpoints

### `GET /healthz`

Checks whether the gateway is alive.

Response `200`:

```json
{
  "status": "ok",
  "service": "agentguard"
}
```

### `POST /v1/tool-calls:authorize`

Runs policy checks without executing the tool.

Request:

```json
{
  "runId": "run_123",
  "stepId": "step_001",
  "serverName": "filesystem",
  "toolName": "read_file",
  "arguments": { "path": "./workspace/notes.md" },
  "userRequest": "Summarize notes"
}
```

Response `200`:

```json
{
  "requestId": "req_123",
  "action": "allow",
  "reason": "No blocking policy matched",
  "riskTags": [],
  "risks": [],
  "redactedArguments": { "path": "./workspace/notes.md" }
}
```

### `POST /v1/tool-calls`

Authorizes and executes a tool call through the configured adapter.

Request shape is the same as `/v1/tool-calls:authorize`.

Response `200`:

```json
{
  "requestId": "req_123",
  "decision": {
    "action": "allow",
    "riskTags": []
  },
  "result": {
    "content": "adapter result"
  }
}
```

Response `403` for deny:

```json
{
  "error": {
    "code": "policy_denied",
    "message": "Tool call was blocked by policy",
    "details": {
      "decision": "deny",
      "riskTags": ["sensitive_file_access"]
    },
    "requestId": "req_123"
  }
}
```

Response `409` for confirm:

```json
{
  "error": {
    "code": "human_confirmation_required",
    "message": "Tool call requires confirmation before execution",
    "details": {
      "decision": "confirm",
      "riskTags": ["network_exfiltration"]
    },
    "requestId": "req_123"
  }
}
```

### `POST /v1/traces`

Stores a trace event emitted by an agent runtime.

Request:

```json
{
  "runId": "run_123",
  "stepId": "step_002",
  "eventType": "planner_decision",
  "payload": {
    "summary": "Need to read project README"
  }
}
```

Response `201`:

```json
{
  "stored": true
}
```

### `GET /v1/runs/{run_id}/trace`

Reads the trace for one run.

Response `200`:

```json
{
  "runId": "run_123",
  "events": []
}
```

## Pagination

List-style endpoints are not part of M0. When added, they must use cursor pagination with `limit` capped at 200 and an opaque `nextCursor`.

## Idempotency

`POST /v1/tool-calls:authorize` is idempotent for the same request payload. `POST /v1/tool-calls` may execute side effects, so clients should send `Idempotency-Key` before this endpoint is used with real tools.

## Versioning

The first public contract is `/v1`. Additive fields are allowed. Breaking changes require `/v2` or a documented compatibility window.

