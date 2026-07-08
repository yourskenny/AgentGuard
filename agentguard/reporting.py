from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from agentguard.models import EvaluationResult, ScanResult


def render_json(payload: Any) -> str:
    if hasattr(payload, "model_dump"):
        data = payload.model_dump(mode="json", by_alias=True)
    else:
        data = payload
    return json.dumps(data, indent=2, ensure_ascii=False)


def render_scan_markdown(result: ScanResult) -> str:
    lines = [
        "# AgentGuard Scan Report",
        "",
        f"- Config: `{result.config_path}`",
        f"- Servers: {len(result.servers)}",
        f"- Tools: {result.total_tools}",
        f"- Risk tags: {', '.join(result.risk_tags) if result.risk_tags else 'none'}",
        "",
        "## Risk Distribution",
        "",
        *_risk_distribution_lines(result),
        "",
        "## Servers",
        "",
    ]
    for server in result.servers:
        lines.append(f"### {server.name}")
        lines.append("")
        lines.append(f"- Command: `{server.command}`")
        lines.append(f"- Args: `{server.args}`")
        lines.append(f"- Env keys: `{', '.join(server.env_keys) if server.env_keys else 'none'}`")
        if server.risks:
            lines.append("- Server risks:")
            for item in server.risks:
                lines.append(f"  - `{item.category}` ({item.severity}): {item.evidence}")
        if server.tools:
            lines.append("- Tools:")
            for tool in server.tools:
                tags = ", ".join(tool.risk_tags) if tool.risk_tags else "none"
                lines.append(f"  - `{tool.tool_name}` score={tool.risk_score:.2f} tags={tags}")
        lines.append("")
    return "\n".join(lines)


def _risk_distribution_lines(result: ScanResult) -> list[str]:
    counts = Counter(risk.category for risk in result.risks)
    if not counts:
        return ["- none"]
    return [f"- `{category}`: {count}" for category, count in sorted(counts.items())]


def render_evaluation_markdown(result: EvaluationResult) -> str:
    metrics = result.metrics
    lines = [
        "# AgentGuard Evaluation Report",
        "",
        "## Metrics",
        "",
        f"- Total cases: {metrics.total_cases}",
        f"- RiskRecall: {metrics.risk_recall:.2%}",
        f"- FalsePositiveRate: {metrics.false_positive_rate:.2%}",
        f"- PolicyViolationBlockRate: {metrics.policy_violation_block_rate:.2%}",
        f"- TraceCoverage: {metrics.trace_coverage:.2%}",
        f"- LatencyOverhead: {metrics.latency_overhead_ms:.2f} ms",
        "",
        "## Category Metrics",
        "",
    ]
    if result.category_metrics:
        for item in result.category_metrics:
            lines.append(
                f"- `{item.category}`: {item.passed_cases}/{item.total_cases} "
                f"passed ({item.pass_rate:.2%})"
            )
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Cases",
            "",
        ]
    )
    for case in result.cases:
        status = "PASS" if case.passed else "FAIL"
        lines.append(
            f"- {status} `{case.case_id}` expected={case.expected_decision} "
            f"actual={case.actual_decision} tags={case.actual_risk_tags}"
        )
    return "\n".join(lines)


def render_sarif(result: ScanResult | EvaluationResult) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    risks = []
    if isinstance(result, ScanResult):
        risks = result.risks
    else:
        for case in result.cases:
            risks.extend(case.risks)

    for item in risks:
        rules[item.category] = {
            "id": item.category,
            "name": item.category,
            "shortDescription": {"text": item.recommendation},
        }
        results.append(
            {
                "ruleId": item.category,
                "level": _sarif_level(item.severity),
                "message": {"text": item.evidence},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "agentguard"},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
        )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentGuard",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_empty_report(format_name: str) -> str:
    payload = {"service": "agentguard", "status": "empty", "runs": []}
    if format_name == "markdown":
        return "# AgentGuard Report\n\nNo run data was provided.\n"
    if format_name == "sarif":
        return render_sarif(ScanResult(config_path="", servers=[], risks=[]))
    return render_json(payload)


def write_text(output: str | Path | None, content: str) -> None:
    if output is None:
        print(content)
        return
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
