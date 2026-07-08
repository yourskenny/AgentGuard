from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from agentguard.config import load_policy
from agentguard.models import PolicyDecision, ToolCallRequest, TraceEvent
from agentguard.policy import PolicyEngine
from agentguard.trace import TraceRecorder


def create_app(
    policy_path: str | Path | None = None,
    trace_db: str | Path = "runs/agentguard.sqlite3",
) -> FastAPI:
    config = load_policy(policy_path)
    engine = PolicyEngine(config=config)
    recorder = TraceRecorder(trace_db)
    app = FastAPI(title="AgentGuard Gateway", version="0.1.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "agentguard"}

    @app.post("/v1/tool-calls:authorize", response_model=PolicyDecision)
    def authorize(request: ToolCallRequest) -> PolicyDecision:
        decision = engine.evaluate(request)
        if request.run_id:
            recorder.record_event(
                TraceEvent(
                    run_id=request.run_id,
                    step_id=request.step_id,
                    event_type="policy_decision",
                    payload=decision.model_dump(mode="json", by_alias=True),
                )
            )
        return decision

    @app.post("/v1/tool-calls", response_model=None)
    def call_tool(request: ToolCallRequest) -> dict[str, Any] | JSONResponse:
        decision = engine.evaluate(request)
        if request.run_id:
            recorder.record_event(
                TraceEvent(
                    run_id=request.run_id,
                    step_id=request.step_id,
                    event_type="policy_decision",
                    payload=decision.model_dump(mode="json", by_alias=True),
                )
            )

        if decision.action == "deny":
            return _error_response(
                403, "policy_denied", "Tool call was blocked by policy", decision
            )
        if decision.action == "confirm":
            return _error_response(
                409,
                "human_confirmation_required",
                "Tool call requires confirmation before execution",
                decision,
            )

        result = {
            "content": "adapter execution is not configured in the M0 skeleton",
            "echo": decision.redacted_arguments,
        }
        result, result_redaction_count = engine.redact_tool_result(result)
        if request.run_id:
            recorder.record_event(
                TraceEvent(
                    run_id=request.run_id,
                    step_id=request.step_id,
                    event_type="tool_result",
                    payload={
                        "toolName": request.tool_name,
                        "resultSummary": result,
                        "redactionCount": result_redaction_count,
                    },
                )
            )
        return {
            "requestId": decision.request_id,
            "decision": decision.model_dump(mode="json", by_alias=True),
            "result": result,
        }

    @app.post("/v1/traces", status_code=201)
    def write_trace(event: TraceEvent) -> dict[str, bool]:
        recorder.record_event(event)
        return {"stored": True}

    @app.get("/v1/runs/{run_id}/trace")
    def read_trace(run_id: str) -> dict[str, Any]:
        trace = recorder.load_trace(run_id)
        return trace.model_dump(mode="json", by_alias=True)

    return app


def _error_response(
    status_code: int,
    code: str,
    message: str,
    decision: PolicyDecision,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "details": {
                    "decision": decision.action,
                    "riskTags": decision.risk_tags,
                },
                "requestId": decision.request_id,
            }
        },
    )
