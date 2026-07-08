from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from agentguard.metadata import analyze_server, collect_risks
from agentguard.models import MCPServerRecord, ScanResult, ToolRecord


def load_config_file(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    text = config_path.read_text(encoding="utf-8")
    if config_path.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("MCP config must be a JSON/YAML object.")
    return data


def _server_items(raw: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    if isinstance(raw.get("mcpServers"), dict):
        return [(str(name), value or {}) for name, value in raw["mcpServers"].items()]
    if isinstance(raw.get("servers"), dict):
        return [(str(name), value or {}) for name, value in raw["servers"].items()]
    if isinstance(raw.get("servers"), list):
        items = []
        for index, value in enumerate(raw["servers"]):
            if not isinstance(value, dict):
                continue
            name = value.get("name") or f"server_{index + 1}"
            items.append((str(name), value))
        return items
    raise ValueError("Unsupported MCP config: expected 'mcpServers' or 'servers'.")


def _tool_records(server_name: str, raw_tools: Any) -> list[ToolRecord]:
    if not isinstance(raw_tools, list):
        return []

    tools: list[ToolRecord] = []
    for index, raw_tool in enumerate(raw_tools):
        if not isinstance(raw_tool, dict):
            continue
        tool_name = str(raw_tool.get("name") or raw_tool.get("toolName") or f"tool_{index + 1}")
        description = str(raw_tool.get("description") or "")
        input_schema = raw_tool.get("inputSchema") or raw_tool.get("input_schema") or {}
        if not isinstance(input_schema, dict):
            input_schema = {}
        tools.append(
            ToolRecord(
                server_name=server_name,
                tool_name=tool_name,
                description=description,
                input_schema=input_schema,
            )
        )
    return tools


def normalize_server(name: str, raw: dict[str, Any], source: str) -> MCPServerRecord:
    command = str(raw.get("command") or raw.get("cmd") or "")
    args = raw.get("args") or []
    if isinstance(args, str):
        args = [args]
    env = raw.get("env") or {}
    env_keys = list(env.keys()) if isinstance(env, dict) else []
    tools = _tool_records(name, raw.get("tools") or raw.get("toolDefinitions"))

    return MCPServerRecord(
        name=name,
        command=command,
        args=[str(arg) for arg in args],
        env_keys=[str(key) for key in env_keys],
        source=str(raw.get("source") or source),
        tools=tools,
    )


def scan_mcp_config(path: str | Path) -> ScanResult:
    config_path = Path(path)
    raw = load_config_file(config_path)
    servers = [
        analyze_server(normalize_server(name, server_raw, str(config_path)))
        for name, server_raw in _server_items(raw)
    ]
    return ScanResult(config_path=str(config_path), servers=servers, risks=collect_risks(servers))


def inspect_server(path: str | Path, server_name: str) -> MCPServerRecord:
    result = scan_mcp_config(path)
    for server in result.servers:
        if server.name == server_name:
            return server
    available = ", ".join(server.name for server in result.servers) or "<none>"
    raise KeyError(f"Server {server_name!r} not found. Available servers: {available}")
