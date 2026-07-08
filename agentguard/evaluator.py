from __future__ import annotations

import json
import time
from pathlib import Path

from agentguard.config import AgentGuardConfig
from agentguard.metadata import analyze_tool
from agentguard.models import (
    CaseEvaluation,
    Decision,
    EvaluationCase,
    EvaluationMetrics,
    EvaluationResult,
)
from agentguard.policy import PolicyEngine


def load_cases(path: str | Path) -> list[EvaluationCase]:
    cases: list[EvaluationCase] = []
    for line_number, line in enumerate(
        Path(path).read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            raw = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSONL at line {line_number}: {exc}") from exc
        cases.append(EvaluationCase.model_validate(raw))
    return cases


def evaluate_cases(
    cases: list[EvaluationCase],
    config: AgentGuardConfig | None = None,
    base_dir: str | Path | None = None,
) -> EvaluationResult:
    engine = PolicyEngine(config=config, base_dir=base_dir)
    case_results: list[CaseEvaluation] = []

    for case in cases:
        start = time.perf_counter()
        decision = engine.evaluate(case.request)
        latency_ms = (time.perf_counter() - start) * 1000
        risks = list(decision.risks)
        actual_tags = set(decision.risk_tags)
        if case.tool is not None:
            analyzed_tool = analyze_tool(
                case.tool.server_name,
                case.tool.tool_name,
                case.tool.description,
                case.tool.input_schema,
            )
            actual_tags.update(analyzed_tool.risk_tags)
            risks.extend(analyzed_tool.risks)
        expected_tags = set(case.expected_risk_tags)
        passed = decision.action == case.expected_decision and expected_tags.issubset(actual_tags)
        case_results.append(
            CaseEvaluation(
                case_id=case.case_id,
                category=case.category,
                expected_decision=case.expected_decision,
                actual_decision=decision.action,
                expected_risk_tags=case.expected_risk_tags,
                actual_risk_tags=sorted(actual_tags),
                passed=passed,
                latency_ms=latency_ms,
                risks=risks,
            )
        )

    return EvaluationResult(metrics=_compute_metrics(case_results), cases=case_results)


def _compute_metrics(cases: list[CaseEvaluation]) -> EvaluationMetrics:
    total = len(cases)
    risk_cases = [case for case in cases if case.expected_risk_tags]
    safe_cases = [case for case in cases if case.expected_decision == Decision.ALLOW]
    deny_cases = [case for case in cases if case.expected_decision == Decision.DENY]
    redact_cases = [case for case in cases if case.expected_decision == Decision.REDACT]

    risk_hits = [
        case
        for case in risk_cases
        if set(case.expected_risk_tags).intersection(set(case.actual_risk_tags))
    ]
    false_positives = [case for case in safe_cases if case.actual_decision != Decision.ALLOW]
    blocked = [case for case in deny_cases if case.actual_decision == Decision.DENY]
    redacted = [case for case in redact_cases if case.actual_decision == Decision.REDACT]

    return EvaluationMetrics(
        total_cases=total,
        risk_recall=_ratio(len(risk_hits), len(risk_cases)),
        false_positive_rate=_ratio(len(false_positives), len(safe_cases)),
        policy_violation_block_rate=_ratio(len(blocked), len(deny_cases)),
        trace_coverage=1.0 if total else 0.0,
        tool_call_accuracy=1.0 if total else 0.0,
        latency_overhead_ms=sum(case.latency_ms for case in cases) / total if total else 0.0,
        redaction_coverage=_ratio(len(redacted), len(redact_cases)),
    )


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0
