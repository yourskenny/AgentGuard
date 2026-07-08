from pathlib import Path

from typer.testing import CliRunner

from agentguard.cli import app

runner = CliRunner()


def test_cli_help_runs():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "AgentGuard MCP tool security gateway" in result.output


def test_cli_scan_json_runs():
    result = runner.invoke(
        app,
        [
            "scan",
            "--config",
            str(Path("tests/fixtures/mcp_configs/sample.json")),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert "tool_description_injection" in result.output
