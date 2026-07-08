from __future__ import annotations

import asyncio
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


class MCPToolAdapter:
    def __init__(self, config: MCPAdapterConfig) -> None:
        self.config = config

    @classmethod
    def from_config(
        cls,
        config_path: str | Path,
        *,
        cwd: str | Path | None = None,
        startup_timeout_s: float = 10.0,
        call_timeout_s: float = 30.0,
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
            )
        )

    def execute(self, request: ToolCallRequest) -> dict[str, Any]:
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
        try:
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await asyncio.wait_for(
                        session.initialize(),
                        timeout=self.config.startup_timeout_s,
                    )
                    result = await session.call_tool(
                        request.tool_name,
                        request.arguments,
                        read_timeout_seconds=timedelta(seconds=self.config.call_timeout_s),
                    )
        except TimeoutError as exc:
            raise ToolAdapterError(
                f"MCP tool call {request.tool_name!r} timed out.",
                code="mcp_call_timeout",
            ) from exc
        except Exception as exc:
            raise ToolAdapterError(
                f"MCP tool call {request.tool_name!r} failed: {exc}",
                code="mcp_call_failed",
            ) from exc

        return _normalize_mcp_result(request, result)

    def close(self) -> None:
        """Reserved for future pooled MCP sessions."""


def _normalize_mcp_result(request: ToolCallRequest, result: Any) -> dict[str, Any]:
    if hasattr(result, "model_dump"):
        raw = result.model_dump(mode="json", by_alias=True)
    elif isinstance(result, dict):
        raw = result
    else:
        raise ToolAdapterError(
            f"Unsupported MCP result type: {type(result).__name__}",
            code="mcp_invalid_result",
        )
    return {
        "adapter": "mcp",
        "serverName": request.server_name,
        "toolName": request.tool_name,
        "content": raw.get("content", []),
        "structuredContent": raw.get("structuredContent") or raw.get("structured_content") or {},
        "isError": bool(raw.get("isError") or raw.get("is_error", False)),
    }


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
