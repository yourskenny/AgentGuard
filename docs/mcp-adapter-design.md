# MCP Adapter Design

## Reader And Action

Reader: a developer implementing the next AgentGuard adapter slice.

Post-read action: implement a real MCP adapter behind the existing gateway without changing policy, trace, or evaluation contracts.

## Problem

The current gateway proves the security loop with `MockToolAdapter`. The next slice needs a real adapter that can take a policy-approved `ToolCallRequest`, route it to the correct MCP server/tool, normalize the MCP result, and map adapter failures into `ToolAdapterError`.

The adapter must not weaken the existing gateway invariant: policy runs before tool execution, deny/confirm never reaches the adapter, trace records the policy decision first, and stored arguments/results are redacted.

## Callers And Constraints

Callers:

- `agentguard.gateway.create_app(..., tool_adapter=...)`
- gateway tests using fake adapters
- future CLI/proxy setup that wires a real MCP adapter from scanned config

Key operations:

- resolve `serverName` and `toolName`;
- start or reuse an MCP client session;
- call the tool with already-redacted arguments;
- normalize MCP content into a JSON-serializable dict;
- map MCP transport/call/result errors into stable `ToolAdapterError` codes;
- close sessions on shutdown when the concrete adapter owns resources.

Hidden internals:

- MCP transport differences;
- process/session lifecycle;
- tool list caching;
- raw MCP SDK result shapes;
- timeout and retry details.

Exposed surface:

- the existing `ToolAdapter.execute(request: ToolCallRequest) -> dict[str, Any]` port;
- optional concrete adapter construction config;
- optional lifecycle method on the concrete adapter, not required by the gateway port.

## Design 1: Minimal Execute Port

Interface:

```python
class ToolAdapter(Protocol):
    def execute(self, request: ToolCallRequest) -> dict[str, Any]:
        ...
```

Concrete usage:

```python
adapter = MCPToolAdapter.from_config("examples/mcp.sample.json")
app = create_app(policy_path="examples/agentguard.yml", tool_adapter=adapter)
```

This keeps the gateway almost unchanged. The adapter internally resolves the server, opens or reuses the MCP session, calls the tool, and returns normalized JSON.

Complexity kept internal:

- server registry;
- MCP process startup;
- session pooling;
- raw result normalization;
- error mapping.

Trade-off:

The interface is very easy for the gateway to use, but it gives tests and future callers fewer hooks for listing tools, refreshing sessions, or preflighting server availability.

## Design 2: Explicit Session Manager

Interface:

```python
class MCPSessionManager(Protocol):
    def connect(self, server_name: str) -> None:
        ...

    def list_tools(self, server_name: str) -> list[ToolRecord]:
        ...

    def call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        ...

    def close(self, server_name: str | None = None) -> None:
        ...
```

Gateway usage:

```python
manager.connect(request.server_name)
result = manager.call_tool(
    request.server_name,
    request.tool_name,
    decision.redacted_arguments,
)
```

Complexity exposed:

- explicit connection lifecycle;
- tool listing;
- server-level close semantics.

Trade-off:

This is flexible and useful for admin tools, but it leaks MCP lifecycle into the gateway. It also makes it easier for future callers to bypass the single policy-approved execution path.

## Design 3: Ports-And-Adapters Runtime

Interface:

```python
class ToolRuntime(Protocol):
    def prepare(self, servers: list[MCPServerRecord]) -> None:
        ...

    def invoke(self, request: ToolCallRequest, context: ToolRuntimeContext) -> ToolRuntimeResult:
        ...

    def shutdown(self) -> None:
        ...
```

Gateway usage:

```python
runtime = MCPRuntime(...)
result = runtime.invoke(
    adapter_request,
    ToolRuntimeContext(request_id=decision.request_id, timeout_ms=30_000),
)
```

Complexity kept internal:

- runtime preparation;
- transport selection;
- timeouts;
- normalized success/error envelopes.

Trade-off:

This shape is powerful for a future multi-runtime system, but it is too broad for the current gateway. It creates a second abstraction alongside `ToolAdapter` before there is evidence that AgentGuard needs multiple runtimes.

## Comparison

Design 1 is the deepest interface for the current codebase: one gateway-facing method hides most of the MCP complexity and preserves the existing policy and trace contracts. It is hard to misuse because callers cannot manually connect, list, or call outside the approved gateway flow.

Design 2 is better for operational tooling, but worse for the security boundary. It exposes lifecycle methods that the gateway does not need, and future code could accidentally call a tool without going through the current decision path.

Design 3 is attractive if AgentGuard becomes a general tool runtime. Today it is too abstract. The extra context/result types would mostly mirror data already present in `ToolCallRequest`, `PolicyDecision`, and trace events.

## Recommendation

Use a hybrid led by Design 1: keep `ToolAdapter.execute()` as the only gateway dependency, and implement `MCPToolAdapter` with internal registry, session pool, result normalization, and error mapping. Allow the concrete adapter to expose `close()` for process cleanup, but do not require the gateway port to know MCP lifecycle details yet.

Recommended sketch:

```python
@dataclass(frozen=True)
class MCPAdapterConfig:
    servers: dict[str, MCPServerRecord]
    startup_timeout_s: float = 10.0
    call_timeout_s: float = 30.0


class MCPToolAdapter:
    def __init__(self, config: MCPAdapterConfig) -> None:
        ...

    @classmethod
    def from_config(cls, config_path: str | Path) -> MCPToolAdapter:
        ...

    def execute(self, request: ToolCallRequest) -> dict[str, Any]:
        ...

    def close(self) -> None:
        ...
```

Stable error codes:

- `mcp_server_not_found`
- `mcp_tool_not_found`
- `mcp_connection_failed`
- `mcp_call_timeout`
- `mcp_call_failed`
- `mcp_invalid_result`

Returned result shape:

```json
{
  "adapter": "mcp",
  "serverName": "filesystem",
  "toolName": "read_file",
  "content": [],
  "structuredContent": {},
  "isError": false
}
```

## Acceptance Criteria For The Next Slice

- `MockToolAdapter` behavior remains unchanged.
- Gateway tests still prove deny/confirm never call the adapter.
- `MCPToolAdapter` can be constructed from an MCP config file.
- Missing server/tool maps to stable `ToolAdapterError` codes.
- A safe local MCP server can be called through `/v1/tool-calls`.
- Adapter errors are recorded as `tool_error` trace events.
- Original secret values do not appear in adapter result traces.

## Spike Status

The first real adapter spike is implemented:

- `MCPToolAdapter` loads raw MCP config with launch env values kept out of scan results.
- Approved gateway calls can reach a local stdio MCP server through MCP Python SDK v1.x.
- `agentguard proxy --mcp-config <path>` wires the real adapter into the FastAPI gateway.
- `examples/safe_mcp_server/server.py` provides a safe local fixture for read-only demo calls.
- `tests/test_mcp_adapter.py` verifies missing server handling and a gateway call through the safe MCP server.

The current spike starts a stdio session per call. A later hardening slice should add pooled sessions, startup health checks, stricter result-size limits, and cross-platform process cleanup.
