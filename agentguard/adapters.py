from __future__ import annotations

from typing import Any, Protocol

from agentguard.models import ToolCallRequest


class ToolAdapter(Protocol):
    def execute(self, request: ToolCallRequest) -> dict[str, Any]:
        """Execute a policy-approved tool request."""


class ToolAdapterError(RuntimeError):
    def __init__(self, message: str, code: str = "adapter_execution_failed"):
        super().__init__(message)
        self.message = message
        self.code = code


class MockToolAdapter:
    def execute(self, request: ToolCallRequest) -> dict[str, Any]:
        return {
            "adapter": "mock",
            "serverName": request.server_name,
            "toolName": request.tool_name,
            "arguments": request.arguments,
            "content": f"mock adapter executed {request.tool_name}",
        }
