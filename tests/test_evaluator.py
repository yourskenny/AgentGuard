from pathlib import Path

from agentguard.config import default_config
from agentguard.evaluator import evaluate_cases, load_cases
from agentguard.models import Decision, EvaluationCase, ToolCallRequest


def test_evaluator_replays_security_cases():
    cases = load_cases(Path("tests/fixtures/security_cases.jsonl"))
    result = evaluate_cases(cases, config=default_config(), base_dir=Path.cwd())

    assert result.metrics.total_cases == 5
    assert result.metrics.policy_violation_block_rate == 1.0
    assert result.metrics.risk_recall == 1.0
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
