from pathlib import Path

import pytest

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


@pytest.mark.parametrize(
    ("fixture", "expected_name"),
    [
        ("sample.json", "safe-filesystem"),
        ("servers_dict.json", "dict-filesystem"),
        ("servers_array.json", "array-filesystem"),
        ("mcp_servers.yaml", "yaml-filesystem"),
    ],
)
def test_scan_mcp_config_supports_common_config_shapes(fixture, expected_name):
    result = scan_mcp_config(Path("tests/fixtures/mcp_configs") / fixture)

    assert result.servers[0].name == expected_name
    assert result.servers[0].command == "python"
    assert result.servers[0].tools[0].tool_name == "read_file"


@pytest.mark.parametrize(
    ("fixture", "field_name"),
    [
        ("invalid_missing_command.json", "command"),
        ("invalid_args.json", "args"),
        ("invalid_env.json", "env"),
    ],
)
def test_scan_mcp_config_rejects_invalid_server_fields(fixture, field_name):
    with pytest.raises(ValueError, match=field_name):
        scan_mcp_config(Path("tests/fixtures/mcp_configs") / fixture)


@pytest.mark.parametrize(
    ("server_name", "category"),
    [
        ("secret-token", "secret_env_exposure"),
        ("secret-private-key", "secret_env_exposure"),
        ("dangerous-remote-script", "dangerous_shell"),
        ("dangerous-delete", "dangerous_shell"),
        ("unpinned-npx", "untrusted_source"),
        ("unpinned-uvx", "untrusted_source"),
        ("broad-root", "broad_filesystem_scope"),
        ("broad-parent", "broad_filesystem_scope"),
    ],
)
def test_scan_mcp_config_detects_server_level_risks(server_name, category):
    server = inspect_server(Path("tests/fixtures/mcp_configs/server_risks.json"), server_name)
    categories = {risk.category for risk in server.risks}

    assert category in categories
    risk = next(risk for risk in server.risks if risk.category == category)
    assert risk.evidence
    assert risk.recommendation
