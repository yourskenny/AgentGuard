from collections import Counter
from pathlib import Path

from agentguard.config import default_config
from agentguard.evaluator import evaluate_cases, load_cases
from agentguard.models import Decision, EvaluationCase, ToolCallRequest


def test_evaluator_replays_security_cases():
    cases = load_cases(Path("tests/fixtures/security_cases.jsonl"))
    result = evaluate_cases(cases, config=default_config(), base_dir=Path.cwd())
    categories = Counter(case.category for case in cases)

    assert result.metrics.total_cases >= 60
    assert categories["normal"] >= 20
    assert categories["tool_poisoning"] >= 20
    assert categories["broad_filesystem_scope"] >= 10
    assert categories["sensitive_file_access"] >= 10
    assert categories["dangerous_shell"] >= 10
    assert categories["network_exfiltration"] >= 10
    assert categories["cross_tool_exfiltration"] >= 5
    assert result.metrics.policy_violation_block_rate == 1.0
    assert result.metrics.risk_recall == 1.0
    assert all(case.passed for case in result.cases)


def test_evaluator_replays_tool_poisoning_metadata_cases():
    cases = [
        case
        for case in load_cases(Path("tests/fixtures/security_cases.jsonl"))
        if case.category == "tool_poisoning"
    ]

    result = evaluate_cases(cases, config=default_config(), base_dir=Path.cwd())

    assert len(cases) >= 20
    assert result.metrics.risk_recall >= 0.9
    assert all("tool_description_injection" in case.actual_risk_tags for case in result.cases)
    assert all(case.passed for case in result.cases)


def test_evaluator_counts_nested_redaction_coverage():
    result = evaluate_cases(
        [
            EvaluationCase(
                case_id="redact-nested-001",
                category="redaction",
                request=ToolCallRequest(
                    tool_name="read_file",
                    arguments={"path": "README.md", "headers": {"api_key": "sk-nested"}},
                ),
                expected_decision=Decision.REDACT,
            )
        ],
        config=default_config(),
        base_dir=Path.cwd(),
    )

    assert result.metrics.redaction_coverage == 1.0
    assert result.cases[0].passed


def test_evaluator_metrics_handle_empty_dataset():
    result = evaluate_cases([], config=default_config(), base_dir=Path.cwd())

    assert result.metrics.total_cases == 0
    assert result.metrics.risk_recall == 0.0
    assert result.metrics.false_positive_rate == 0.0
    assert result.metrics.policy_violation_block_rate == 0.0
    assert result.metrics.trace_coverage == 0.0
    assert result.metrics.latency_overhead_ms == 0.0
    assert result.metrics.redaction_coverage == 0.0
    assert result.category_metrics == []


def test_evaluator_metrics_handle_all_safe_dataset():
    result = evaluate_cases(
        [
            EvaluationCase(
                case_id="safe-001",
                category="normal",
                request=ToolCallRequest(tool_name="read_file", arguments={"path": "README.md"}),
                expected_decision=Decision.ALLOW,
            ),
            EvaluationCase(
                case_id="safe-002",
                category="normal",
                request=ToolCallRequest(
                    tool_name="read_file", arguments={"path": "docs/architecture.md"}
                ),
                expected_decision=Decision.ALLOW,
            ),
        ],
        config=default_config(),
        base_dir=Path.cwd(),
    )

    assert result.metrics.total_cases == 2
    assert result.metrics.false_positive_rate == 0.0
    assert result.metrics.risk_recall == 0.0
    assert result.category_metrics[0].category == "normal"
    assert result.category_metrics[0].pass_rate == 1.0


def test_evaluator_metrics_handle_all_risk_dataset():
    result = evaluate_cases(
        [
            EvaluationCase(
                case_id="risk-001",
                category="broad_filesystem_scope",
                request=ToolCallRequest(tool_name="read_file", arguments={"path": "../secret.txt"}),
                expected_decision=Decision.DENY,
                expected_risk_tags=["broad_filesystem_scope"],
            ),
            EvaluationCase(
                case_id="risk-002",
                category="network_exfiltration",
                request=ToolCallRequest(
                    tool_name="http_post",
                    arguments={"url": "https://example.com/upload", "body": "x"},
                ),
                expected_decision=Decision.CONFIRM,
                expected_risk_tags=["network_exfiltration"],
            ),
        ],
        config=default_config(),
        base_dir=Path.cwd(),
    )

    assert result.metrics.risk_recall == 1.0
    assert result.metrics.policy_violation_block_rate == 1.0
    assert {item.category: item.pass_rate for item in result.category_metrics} == {
        "broad_filesystem_scope": 1.0,
        "network_exfiltration": 1.0,
    }


def test_evaluator_metrics_handle_mixed_dataset_with_failures():
    result = evaluate_cases(
        [
            EvaluationCase(
                case_id="false-positive-001",
                category="normal",
                request=ToolCallRequest(
                    tool_name="write_file",
                    arguments={"path": "README.md", "content": "x"},
                ),
                expected_decision=Decision.ALLOW,
            ),
            EvaluationCase(
                case_id="risk-pass-001",
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
    category_pass_rates = {item.category: item.pass_rate for item in result.category_metrics}

    assert result.metrics.false_positive_rate == 1.0
    assert result.metrics.policy_violation_block_rate == 1.0
    assert result.cases[0].expected_decision == Decision.ALLOW
    assert result.cases[0].actual_decision == Decision.CONFIRM
    assert not result.cases[0].passed
    assert category_pass_rates == {"dangerous_shell": 1.0, "normal": 0.0}
