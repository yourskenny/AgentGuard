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


def test_cli_scan_invalid_config_reports_user_error():
    result = runner.invoke(
        app,
        [
            "scan",
            "--config",
            str(Path("tests/fixtures/mcp_configs/invalid_args.json")),
            "--format",
            "json",
        ],
    )

    assert result.exit_code != 0
    assert "args" in result.output
    assert "Traceback" not in result.output


def test_cli_scan_writes_output_file(tmp_path):
    output = tmp_path / "scan-report.md"

    result = runner.invoke(
        app,
        [
            "scan",
            "--config",
            str(Path("tests/fixtures/mcp_configs/server_risks.json")),
            "--format",
            "markdown",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert "AgentGuard Scan Report" in output.read_text(encoding="utf-8")
    assert result.output == ""
