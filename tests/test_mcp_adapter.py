import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentguard.adapters import (
    MCPAdapterConfig,
    MCPServerLaunchConfig,
    MCPToolAdapter,
    ToolAdapterError,
    _normalize_mcp_result,
)
from agentguard.gateway import create_app
from agentguard.models import ToolCallRequest


def _mcp_config(server_path: Path) -> dict:
    return {
        "mcpServers": {
            "safe-filesystem": {
                "command": sys.executable,
                "args": [str(server_path)],
                "env": {},
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a file inside the configured workspace.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
                            "required": ["path"],
                        },
                    }
                ],
            }
        }
    }


def test_mcp_adapter_requires_server_name(tmp_path):
    adapter = MCPToolAdapter.from_config(_write_config(tmp_path))

    with pytest.raises(ToolAdapterError) as exc_info:
        adapter.execute(ToolCallRequest(tool_name="read_file", arguments={"path": "README.md"}))

    assert exc_info.value.code == "mcp_server_required"


def test_mcp_adapter_reports_missing_server(tmp_path):
    adapter = MCPToolAdapter.from_config(_write_config(tmp_path))

    with pytest.raises(ToolAdapterError) as exc_info:
        adapter.execute(
            ToolCallRequest(
                server_name="missing",
                tool_name="read_file",
                arguments={"path": "README.md"},
            )
        )

    assert exc_info.value.code == "mcp_server_not_found"


def test_mcp_adapter_close_prevents_execution(tmp_path):
    adapter = MCPToolAdapter.from_config(_write_config(tmp_path))
    adapter.close()

    with pytest.raises(ToolAdapterError) as exc_info:
        adapter.execute(
            ToolCallRequest(
                server_name="safe-filesystem",
                tool_name="read_file",
                arguments={"path": "README.md"},
            )
        )

    assert exc_info.value.code == "mcp_adapter_closed"


def test_mcp_adapter_health_check_initializes_safe_server(tmp_path):
    adapter = MCPToolAdapter.from_config(_write_config(tmp_path))

    health = adapter.health_check()

    assert health["adapter"] == "mcp"
    assert health["servers"][0]["name"] == "safe-filesystem"
    assert health["servers"][0]["ok"] is True
    assert "read_file" in health["servers"][0]["tools"]


def test_mcp_adapter_startup_timeout_has_stable_error_code():
    adapter = MCPToolAdapter(
        MCPAdapterConfig(
            servers={
                "sleepy": MCPServerLaunchConfig(
                    name="sleepy",
                    command=sys.executable,
                    args=("-c", "import time; time.sleep(5)"),
                )
            },
            startup_timeout_s=0.1,
            call_timeout_s=0.1,
        )
    )

    with pytest.raises(ToolAdapterError) as exc_info:
        adapter.execute(
            ToolCallRequest(
                server_name="sleepy",
                tool_name="read_file",
                arguments={"path": "README.md"},
            )
        )

    assert exc_info.value.code == "mcp_startup_timeout"


def test_mcp_result_size_limit_has_stable_error_code():
    request = ToolCallRequest(
        server_name="safe-filesystem",
        tool_name="read_file",
        arguments={"path": "README.md"},
    )

    with pytest.raises(ToolAdapterError) as exc_info:
        _normalize_mcp_result(
            request,
            {"content": [{"type": "text", "text": "x" * 200}], "isError": False},
            max_result_bytes=100,
        )

    assert exc_info.value.code == "mcp_result_too_large"


def test_gateway_shutdown_closes_adapter(tmp_path):
    class ClosableAdapter:
        def __init__(self):
            self.closed = False

        def execute(self, request):
            return {"ok": True}

        def close(self):
            self.closed = True

    adapter = ClosableAdapter()
    app = create_app(trace_db=tmp_path / "trace.sqlite3", tool_adapter=adapter)

    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200

    assert adapter.closed is True


def test_gateway_can_call_safe_stdio_mcp_server(tmp_path):
    config_path = _write_config(tmp_path)
    adapter = MCPToolAdapter.from_config(config_path)
    client = TestClient(create_app(trace_db=tmp_path / "trace.sqlite3", tool_adapter=adapter))

    response = client.post(
        "/v1/tool-calls",
        json={
            "runId": "mcp-adapter-run",
            "stepId": "step-1",
            "serverName": "safe-filesystem",
            "toolName": "read_file",
            "arguments": {"path": "README.md"},
        },
    )
    payload = response.json()
    rendered = json.dumps(payload)
    trace = client.get("/v1/runs/mcp-adapter-run/trace").json()

    assert response.status_code == 200
    assert payload["decision"]["action"] == "allow"
    assert payload["result"]["adapter"] == "mcp"
    assert payload["result"]["serverName"] == "safe-filesystem"
    assert payload["result"]["toolName"] == "read_file"
    assert "AgentGuard" in rendered
    assert [event["eventType"] for event in trace["steps"]] == [
        "policy_decision",
        "tool_call",
        "tool_result",
    ]


def _write_config(tmp_path: Path) -> Path:
    server_path = Path("examples/safe_mcp_server/server.py").resolve()
    config_path = tmp_path / "mcp.json"
    config_path.write_text(json.dumps(_mcp_config(server_path)), encoding="utf-8")
    return config_path
