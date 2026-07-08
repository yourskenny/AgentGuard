from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def to_camel(value: str) -> str:
    parts = value.split("_")
    return parts[0] + "".join(part.capitalize() for part in parts[1:])


class CamelModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        use_enum_values=True,
    )


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    CONFIRM = "confirm"
    REDACT = "redact"
    SANDBOX = "sandbox"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FinalStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    NEEDS_REVIEW = "needs_review"


class RiskRecord(CamelModel):
    risk_id: str = Field(default_factory=lambda: f"risk_{uuid.uuid4().hex[:12]}")
    severity: Severity
    category: str
    evidence: str
    recommendation: str


class ToolRecord(CamelModel):
    server_name: str
    tool_name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    capabilities: list[str] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_tags: list[str] = Field(default_factory=list)
    risks: list[RiskRecord] = Field(default_factory=list)


class MCPServerRecord(CamelModel):
    name: str
    command: str
    args: list[str] = Field(default_factory=list)
    env_keys: list[str] = Field(default_factory=list)
    source: str | None = None
    tools: list[ToolRecord] = Field(default_factory=list)
    risks: list[RiskRecord] = Field(default_factory=list)


class ToolCallRequest(CamelModel):
    run_id: str | None = None
    step_id: str | None = None
    server_name: str | None = None
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    user_request: str | None = None


class ToolCallRecord(CamelModel):
    run_id: str
    step_id: str
    tool_name: str
    arguments_summary: dict[str, Any] = Field(default_factory=dict)
    decision: Decision
    risk_tags: list[str] = Field(default_factory=list)
    latency_ms: int | None = None


class PolicyDecision(CamelModel):
    request_id: str = Field(default_factory=lambda: f"req_{uuid.uuid4().hex[:12]}")
    action: Decision
    reason: str
    risk_tags: list[str] = Field(default_factory=list)
    risks: list[RiskRecord] = Field(default_factory=list)
    redacted_arguments: dict[str, Any] = Field(default_factory=dict)
    redaction_count: int = 0


class TraceEvent(CamelModel):
    run_id: str
    step_id: str | None = None
    parent_step_id: str | None = None
    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    latency_ms: int | None = None
    token_usage: dict[str, int] | None = None
    cost_estimate: float | None = None


class AgentTrace(CamelModel):
    run_id: str
    user_request: str = ""
    model: str | None = None
    steps: list[TraceEvent] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    risks: list[RiskRecord] = Field(default_factory=list)
    final_status: FinalStatus = FinalStatus.SUCCESS


class ScanResult(CamelModel):
    config_path: str
    servers: list[MCPServerRecord] = Field(default_factory=list)
    risks: list[RiskRecord] = Field(default_factory=list)

    @property
    def total_tools(self) -> int:
        return sum(len(server.tools) for server in self.servers)

    @property
    def risk_tags(self) -> list[str]:
        tags: set[str] = set()
        for risk in self.risks:
            tags.add(risk.category)
        for server in self.servers:
            for risk in server.risks:
                tags.add(risk.category)
            for tool in server.tools:
                tags.update(tool.risk_tags)
        return sorted(tags)


class EvaluationCase(CamelModel):
    case_id: str
    category: str
    request: ToolCallRequest
    tool: ToolRecord | None = None
    expected_decision: Decision
    expected_risk_tags: list[str] = Field(default_factory=list)


class CaseEvaluation(CamelModel):
    case_id: str
    category: str
    expected_decision: Decision
    actual_decision: Decision
    expected_risk_tags: list[str] = Field(default_factory=list)
    actual_risk_tags: list[str] = Field(default_factory=list)
    passed: bool
    latency_ms: float
    risks: list[RiskRecord] = Field(default_factory=list)


class EvaluationMetrics(CamelModel):
    total_cases: int = 0
    risk_recall: float = 0.0
    false_positive_rate: float = 0.0
    policy_violation_block_rate: float = 0.0
    trace_coverage: float = 0.0
    tool_call_accuracy: float = 0.0
    latency_overhead_ms: float = 0.0
    redaction_coverage: float = 0.0


class CategoryMetric(CamelModel):
    category: str
    total_cases: int = 0
    passed_cases: int = 0
    failed_cases: int = 0
    pass_rate: float = 0.0


class EvaluationResult(CamelModel):
    metrics: EvaluationMetrics
    category_metrics: list[CategoryMetric] = Field(default_factory=list)
    cases: list[CaseEvaluation] = Field(default_factory=list)


class ErrorEnvelope(CamelModel):
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    request_id: str
