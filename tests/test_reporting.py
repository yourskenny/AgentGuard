import json
from pathlib import Path

from agentguard.reporting import (
    render_empty_report,
    render_json,
    render_sarif,
    render_scan_markdown,
)
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


def test_render_scan_markdown_contains_risk_distribution():
    result = scan_mcp_config(Path("tests/fixtures/mcp_configs/server_risks.json"))
    markdown = render_scan_markdown(result)

    assert "## Risk Distribution" in markdown
    assert "- `broad_filesystem_scope`: 2" in markdown
    assert "- `dangerous_shell`: 2" in markdown
    assert "- `secret_env_exposure`: 2" in markdown
    assert "- `untrusted_source`: 2" in markdown


def test_render_scan_json_preserves_structured_risks():
    result = scan_mcp_config(Path("tests/fixtures/mcp_configs/server_risks.json"))
    payload = json.loads(render_json(result))

    assert payload["servers"][0]["risks"][0]["category"] == "secret_env_exposure"
    assert payload["risks"][0]["evidence"]


def test_render_scan_sarif_contains_rules_and_results():
    result = scan_mcp_config(Path("tests/fixtures/mcp_configs/server_risks.json"))
    payload = json.loads(render_sarif(result))
    run = payload["runs"][0]

    assert payload["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "AgentGuard"
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} >= {
        "broad_filesystem_scope",
        "dangerous_shell",
        "secret_env_exposure",
        "untrusted_source",
    }
    assert len(run["results"]) == 8
