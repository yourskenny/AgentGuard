import json
from pathlib import Path

from agentguard.config import default_config
from agentguard.evaluator import evaluate_cases
from agentguard.models import Decision, EvaluationCase, ToolCallRequest
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


def test_render_evaluation_json_contains_metrics_categories_and_failure_details():
    result = evaluate_cases(
        [
            EvaluationCase(
                case_id="json-failure-001",
                category="normal",
                request=ToolCallRequest(
                    tool_name="write_file",
                    arguments={"path": "README.md", "content": "x"},
                ),
                expected_decision=Decision.ALLOW,
            )
        ],
        config=default_config(),
        base_dir=Path.cwd(),
    )

    payload = json.loads(render_json(result))

    assert payload["metrics"]["totalCases"] == 1
    assert payload["categoryMetrics"][0]["category"] == "normal"
    assert payload["categoryMetrics"][0]["passRate"] == 0.0
    assert payload["cases"][0]["passed"] is False
    assert payload["cases"][0]["expectedDecision"] == "allow"
    assert payload["cases"][0]["actualDecision"] == "confirm"


def test_render_evaluation_markdown_contains_risk_distribution_and_failed_cases():
    result = evaluate_cases(
        [
            EvaluationCase(
                case_id="markdown-failure-001",
                category="normal",
                request=ToolCallRequest(
                    tool_name="write_file",
                    arguments={"path": "README.md", "content": "x"},
                ),
                expected_decision=Decision.ALLOW,
            ),
            EvaluationCase(
                case_id="markdown-risk-001",
                category="dangerous_shell",
                request=ToolCallRequest(
                    tool_name="run_command", arguments={"command": "rm -rf /tmp/x"}
                ),
                expected_decision=Decision.DENY,
                expected_risk_tags=["dangerous_shell"],
            ),
        ],
        config=default_config(),
        base_dir=Path.cwd(),
    )

    from agentguard.reporting import render_evaluation_markdown

    markdown = render_evaluation_markdown(result)

    assert "## Risk Distribution" in markdown
    assert "- `dangerous_shell`: 1" in markdown
    assert "## Failed Cases" in markdown
    assert "FAIL `markdown-failure-001` expected=allow actual=confirm" in markdown


def test_sample_eval_reports_exist_and_show_failure_examples():
    markdown = Path("docs/report-samples/evaluation-sample.md").read_text(encoding="utf-8")
    json_payload = json.loads(
        Path("docs/report-samples/evaluation-sample.json").read_text(encoding="utf-8")
    )
    sarif_payload = json.loads(
        Path("docs/report-samples/evaluation-sample.sarif.json").read_text(encoding="utf-8")
    )
    sarif_run = sarif_payload["runs"][0]

    assert "## Risk Distribution" in markdown
    assert "FAIL `sample-fail-001` expected=allow actual=confirm" in markdown
    assert json_payload["categoryMetrics"]
    assert any(case["passed"] is False for case in json_payload["cases"])
    assert sarif_run["tool"]["driver"]["rules"]
    assert sarif_run["results"]
