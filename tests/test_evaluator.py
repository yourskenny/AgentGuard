from pathlib import Path

from agentguard.config import default_config
from agentguard.evaluator import evaluate_cases, load_cases


def test_evaluator_replays_security_cases():
    cases = load_cases(Path("tests/fixtures/security_cases.jsonl"))
    result = evaluate_cases(cases, config=default_config(), base_dir=Path.cwd())

    assert result.metrics.total_cases == 5
    assert result.metrics.policy_violation_block_rate == 1.0
    assert result.metrics.risk_recall == 1.0
    assert all(case.passed for case in result.cases)
