from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol

from agentguard.models import ToolCallRequest
from agentguard.scanner import load_config_file


class ToolAdapter(Protocol):
    def execute(self, request: ToolCallRequest) -> dict[str, Any]:
        """Execute a policy-approved tool request."""


class ToolAdapterError(RuntimeError):
    def __init__(self, message: str, code: str = "adapter_execution_failed"):
        super().__init__(message)
        self.message = message
        self.code = code


class MockToolAdapter:
    def execute(self, request: ToolCallRequest) -> dict[str, Any]:
        return {
            "adapter": "mock",
            "serverName": request.server_name,
            "toolName": request.tool_name,
            "arguments": request.arguments,
            "content": f"mock adapter executed {request.tool_name}",
        }


@dataclass(frozen=True)
class MCPServerLaunchConfig:
    name: str
    command: str
    args: tuple[str, ...] = ()
    env: dict[str, str] | None = None


@dataclass(frozen=True)
class MCPAdapterConfig:
    servers: dict[str, MCPServerLaunchConfig]
    cwd: Path | None = None
    startup_timeout_s: float = 10.0
    call_timeout_s: float = 30.0
    max_result_bytes: int = 1_000_000


class MCPToolAdapter:
    def __init__(self, config: MCPAdapterConfig) -> None:
        self.config = config
        self._closed = False

    @classmethod
    def from_config(
        cls,
        config_path: str | Path,
        *,
        cwd: str | Path | None = None,
        startup_timeout_s: float = 10.0,
        call_timeout_s: float = 30.0,
        max_result_bytes: int = 1_000_000,
    ) -> MCPToolAdapter:
        raw = load_config_file(config_path)
        servers = {
            name: _launch_config_from_raw(name, value)
            for name, value in _server_items(raw)
        }
        return cls(
            MCPAdapterConfig(
                servers=servers,
                cwd=Path(cwd) if cwd is not None else Path.cwd(),
                startup_timeout_s=startup_timeout_s,
                call_timeout_s=call_timeout_s,
                max_result_bytes=max_result_bytes,
            )
        )

    def execute(self, request: ToolCallRequest) -> dict[str, Any]:
        if self._closed:
            raise ToolAdapterError(
                "MCP adapter has been closed.",
                code="mcp_adapter_closed",
            )
        server_name = request.server_name
        if not server_name:
            raise ToolAdapterError(
                "MCP tool calls require serverName.",
                code="mcp_server_required",
            )
        server = self.config.servers.get(server_name)
        if server is None:
            raise ToolAdapterError(
                f"MCP server {server_name!r} was not found.",
                code="mcp_server_not_found",
            )
        return asyncio.run(self._execute_async(server, request))

    def health_check(self) -> dict[str, Any]:
        return asyncio.run(self._health_check_async())

    async def _health_check_async(self) -> dict[str, Any]:
        servers: list[dict[str, Any]] = []
        for server in self.config.servers.values():
            try:
                tool_names = await self._list_tools_async(server)
                servers.append(
                    {
                        "name": server.name,
                        "ok": True,
                        "tools": tool_names,
                    }
                )
            except ToolAdapterError as exc:
                servers.append(
                    {
                        "name": server.name,
                        "ok": False,
                        "error": {"code": exc.code, "message": exc.message},
                    }
                )
        return {"adapter": "mcp", "closed": self._closed, "servers": servers}

    async def _execute_async(
        self,
        server: MCPServerLaunchConfig,
        request: ToolCallRequest,
    ) -> dict[str, Any]:
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError as exc:
            raise ToolAdapterError(
                "Install the 'agentguard[mcp]' extra to use MCPToolAdapter.",
                code="mcp_dependency_missing",
            ) from exc

        params = StdioServerParameters(
            command=server.command,
            args=list(server.args),
            env=server.env,
            cwd=self.config.cwd,
        )
        stage = "startup"
        try:
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await asyncio.wait_for(
                        session.initialize(),
                        timeout=self.config.startup_timeout_s,
                    )
                    stage = "call"
                    result = await session.call_tool(
                        request.tool_name,
                        request.arguments,
                        read_timeout_seconds=timedelta(seconds=self.config.call_timeout_s),
                    )
        except Exception as exc:
            if _contains_timeout_error(exc):
                code = "mcp_startup_timeout" if stage == "startup" else "mcp_call_timeout"
                message = (
                    f"MCP server {server.name!r} startup timed out."
                    if stage == "startup"
                    else f"MCP tool call {request.tool_name!r} timed out."
                )
                raise ToolAdapterError(message, code=code) from exc
            raise ToolAdapterError(
                f"MCP tool call {request.tool_name!r} failed: {exc}",
                code="mcp_call_failed",
            ) from exc

        return _normalize_mcp_result(
            request,
            result,
            max_result_bytes=self.config.max_result_bytes,
        )

    async def _list_tools_async(self, server: MCPServerLaunchConfig) -> list[str]:
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError as exc:
            raise ToolAdapterError(
                "Install the 'agentguard[mcp]' extra to use MCPToolAdapter.",
                code="mcp_dependency_missing",
            ) from exc

        params = StdioServerParameters(
            command=server.command,
            args=list(server.args),
            env=server.env,
            cwd=self.config.cwd,
        )
        try:
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await asyncio.wait_for(
                        session.initialize(),
                        timeout=self.config.startup_timeout_s,
                    )
                    result = await asyncio.wait_for(
                        session.list_tools(),
                        timeout=self.config.call_timeout_s,
                    )
        except Exception as exc:
            if _contains_timeout_error(exc):
                raise ToolAdapterError(
                    f"MCP server {server.name!r} health check timed out.",
                    code="mcp_startup_timeout",
                ) from exc
            raise ToolAdapterError(
                f"MCP server {server.name!r} health check failed: {exc}",
                code="mcp_health_check_failed",
            ) from exc

        return _extract_tool_names(result)

    def close(self) -> None:
        self._closed = True


def _normalize_mcp_result(
    request: ToolCallRequest,
    result: Any,
    *,
    max_result_bytes: int = 1_000_000,
) -> dict[str, Any]:
    if hasattr(result, "model_dump"):
        raw = result.model_dump(mode="json", by_alias=True)
    elif isinstance(result, dict):
        raw = result
    else:
        raise ToolAdapterError(
            f"Unsupported MCP result type: {type(result).__name__}",
            code="mcp_invalid_result",
        )
    normalized = {
        "adapter": "mcp",
        "serverName": request.server_name,
        "toolName": request.tool_name,
        "content": raw.get("content", []),
        "structuredContent": raw.get("structuredContent") or raw.get("structured_content") or {},
        "isError": bool(raw.get("isError") or raw.get("is_error", False)),
    }
    size = len(json.dumps(normalized, ensure_ascii=False, default=str).encode("utf-8"))
    if size > max_result_bytes:
        raise ToolAdapterError(
            f"MCP result exceeded max result size of {max_result_bytes} bytes.",
            code="mcp_result_too_large",
        )
    return normalized


def _contains_timeout_error(exc: BaseException) -> bool:
    if isinstance(exc, TimeoutError):
        return True
    if isinstance(exc, BaseExceptionGroup):
        return any(_contains_timeout_error(child) for child in exc.exceptions)
    return False


def _extract_tool_names(result: Any) -> list[str]:
    if hasattr(result, "model_dump"):
        raw = result.model_dump(mode="json", by_alias=True)
    elif isinstance(result, dict):
        raw = result
    else:
        raise ToolAdapterError(
            f"Unsupported MCP tools result type: {type(result).__name__}",
            code="mcp_invalid_result",
        )

    tools = raw.get("tools", [])
    if not isinstance(tools, list):
        raise ToolAdapterError(
            "MCP list_tools result field 'tools' must be a list.",
            code="mcp_invalid_result",
        )

    names: list[str] = []
    for tool in tools:
        if isinstance(tool, dict) and isinstance(tool.get("name"), str):
            names.append(tool["name"])
    return names


def _server_items(raw: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    if isinstance(raw.get("mcpServers"), dict):
        return [
            (str(name), _validate_raw_server(name, value))
            for name, value in raw["mcpServers"].items()
        ]
    if isinstance(raw.get("servers"), dict):
        return [
            (str(name), _validate_raw_server(name, value))
            for name, value in raw["servers"].items()
        ]
    if isinstance(raw.get("servers"), list):
        items: list[tuple[str, dict[str, Any]]] = []
        for index, value in enumerate(raw["servers"]):
            if not isinstance(value, dict):
                raise ValueError(f"servers[{index}] must be an object.")
            name = str(value.get("name") or f"server_{index + 1}")
            items.append((name, value))
        return items
    raise ValueError("Unsupported MCP config: expected 'mcpServers' or 'servers'.")


def _validate_raw_server(name: Any, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Server {name!r} must be an object.")
    return value


def _launch_config_from_raw(name: str, raw: dict[str, Any]) -> MCPServerLaunchConfig:
    command = raw.get("command") or raw.get("cmd")
    if not isinstance(command, str) or not command.strip():
        raise ValueError(f"Server {name!r} field 'command' must be a non-empty string.")

    args = raw.get("args", [])
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        raise ValueError(f"Server {name!r} field 'args' must be a list of strings.")

    env = raw.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(key, str) for key in env):
        raise ValueError(f"Server {name!r} field 'env' must be an object with string keys.")

    return MCPServerLaunchConfig(
        name=name,
        command=command.strip(),
        args=tuple(args),
        env=_resolve_env(env),
    )


_ENV_PLACEHOLDER = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


def _resolve_env(raw_env: dict[str, Any]) -> dict[str, str] | None:
    resolved: dict[str, str] = {}
    for key, value in raw_env.items():
        text = str(value)
        match = _ENV_PLACEHOLDER.match(text)
        resolved[key] = os.environ.get(match.group(1), "") if match else text
    return resolved or None
