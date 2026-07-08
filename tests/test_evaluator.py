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
