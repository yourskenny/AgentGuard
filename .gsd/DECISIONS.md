# Decisions

- 2026-07-08: AgentGuard M0 uses a Python CLI plus local FastAPI gateway, path-versioned `/v1` API, Pydantic data contracts, YAML policy, SQLite traces, and Markdown/JSON/SARIF reports.
- 2026-07-08: The real MCP integration should keep the gateway-facing `ToolAdapter.execute(ToolCallRequest) -> dict[str, Any]` port stable. A concrete `MCPToolAdapter` may own server registry, MCP sessions, result normalization, and error mapping internally, with an optional `close()` lifecycle method that is not required by the gateway port.
