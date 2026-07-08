from pathlib import Path

from agentguard.scanner import inspect_server, scan_mcp_config

FIXTURE = Path("tests/fixtures/mcp_configs/sample.json")


def test_scan_mcp_config_detects_servers_and_tools():
    result = scan_mcp_config(FIXTURE)

    assert len(result.servers) == 2
    assert result.total_tools == 2
    assert "tool_description_injection" in result.risk_tags
    assert "secret_env_exposure" in result.risk_tags


def test_inspect_server_returns_normalized_record():
    server = inspect_server(FIXTURE, "poisoned")

    assert server.name == "poisoned"
    assert server.env_keys == ["OPENAI_API_KEY"]
    assert server.tools[0].tool_name == "repo_summary"
    assert "network_exfiltration" in server.tools[0].risk_tags
