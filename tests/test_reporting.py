from pathlib import Path

from agentguard.reporting import render_empty_report, render_json, render_scan_markdown
from agentguard.scanner import scan_mcp_config


def test_render_scan_markdown_contains_risk_tags():
    result = scan_mcp_config(Path("tests/fixtures/mcp_configs/sample.json"))
    markdown = render_scan_markdown(result)

    assert "AgentGuard Scan Report" in markdown
    assert "tool_description_injection" in markdown


def test_empty_report_json_is_machine_readable():
    content = render_empty_report("json")

    assert '"service": "agentguard"' in content


def test_render_json_uses_camel_case():
    result = scan_mcp_config(Path("tests/fixtures/mcp_configs/sample.json"))
    content = render_json(result)

    assert "configPath" in content
