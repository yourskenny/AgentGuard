from __future__ import annotations

import fnmatch
import re
import time
from pathlib import Path
from typing import Any

from agentguard.config import AgentGuardConfig, default_config
from agentguard.metadata import DANGEROUS_COMMAND_PATTERNS, risk
from agentguard.models import Decision, PolicyDecision, RiskRecord, Severity, ToolCallRequest

SENSITIVE_FILE_NAMES = {".env", "id_rsa", "id_ed25519", "cookies.sqlite"}
NETWORK_TOOLS = {"http_post", "post_url", "webhook", "upload", "send_request"}
WRITE_TOOLS = {"write_file", "delete_file", "remove_file", "replace_file"}


class PolicyEngine:
    def __init__(self, config: AgentGuardConfig | None = None, base_dir: str | Path | None = None):
        self.config = config or default_config()
        self.base_dir = Path(base_dir or Path.cwd()).resolve()

    def evaluate(self, request: ToolCallRequest) -> PolicyDecision:
        start = time.perf_counter()
        risks: list[RiskRecord] = []
        action = self._configured_action(request.tool_name)
        redacted_arguments = self._redact_arguments(request.arguments)

        risks.extend(self._filesystem_risks(request))
        risks.extend(self._shell_risks(request))
        risks.extend(self._network_risks(request))

        risk_tags = sorted({item.category for item in risks})
        if any(item.severity in {Severity.HIGH, Severity.CRITICAL} for item in risks):
            action = Decision.DENY
        elif any(item.category == "network_exfiltration" for item in risks):
            action = Decision.CONFIRM
        elif action == Decision.ALLOW and redacted_arguments != request.arguments:
            action = Decision.REDACT

        elapsed_ms = (time.perf_counter() - start) * 1000
        reason = self._reason(action, risk_tags, elapsed_ms)
        return PolicyDecision(
            action=action,
            reason=reason,
            risk_tags=risk_tags,
            risks=risks,
            redacted_arguments=redacted_arguments,
        )

    def _configured_action(self, tool_name: str) -> Decision:
        tool_policy = self.config.tools.get(tool_name)
        if tool_policy is not None:
            return tool_policy.action
        if tool_name in WRITE_TOOLS:
            return Decision.CONFIRM
        if tool_name in NETWORK_TOOLS:
            return Decision.CONFIRM
        return self.config.default_action

    def _filesystem_risks(self, request: ToolCallRequest) -> list[RiskRecord]:
        risks: list[RiskRecord] = []
        for key, value in request.arguments.items():
            if "path" not in key.lower() and key.lower() not in {"file", "filename"}:
                continue
            if not isinstance(value, str):
                continue
            path = Path(value)
            if self._is_denied_file(path):
                risks.append(
                    risk(
                        "sensitive_file_access",
                        Severity.HIGH,
                        f"Argument {key!r} points to denied file pattern: {value}",
                        "Block sensitive file access or require explicit one-time approval.",
                    )
                )
            if not self._is_inside_allowed_root(path):
                risks.append(
                    risk(
                        "broad_filesystem_scope",
                        Severity.HIGH,
                        f"Argument {key!r} resolves outside allowed roots: {value}",
                        "Restrict file access to configured workspace roots.",
                    )
                )
        return risks

    def _shell_risks(self, request: ToolCallRequest) -> list[RiskRecord]:
        risks: list[RiskRecord] = []
        if request.tool_name not in {"shell", "run_command", "exec", "execute"}:
            command = request.arguments.get("command") or request.arguments.get("cmd")
            if command is None:
                return risks
        else:
            command = request.arguments.get("command") or request.arguments.get("cmd") or ""

        if not isinstance(command, str):
            return risks
        for pattern in DANGEROUS_COMMAND_PATTERNS:
            match = pattern.search(command)
            if match:
                risks.append(
                    risk(
                        "dangerous_shell",
                        Severity.HIGH,
                        f"Command matched dangerous pattern: {match.group(0)!r}",
                        "Deny destructive commands and remote script execution.",
                    )
                )
                break
        return risks

    def _network_risks(self, request: ToolCallRequest) -> list[RiskRecord]:
        text = f"{request.tool_name} {request.arguments}".lower()
        if request.tool_name not in NETWORK_TOOLS and not re.search(r"https?://", text):
            return []
        return [
            risk(
                "network_exfiltration",
                Severity.MEDIUM,
                "Tool call includes network egress or URL-like arguments.",
                "Require confirmation or use an allowlist for outbound domains.",
            )
        ]

    def _redact_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if not self.config.redaction.enabled:
            return dict(arguments)
        redacted: dict[str, Any] = {}
        patterns = [pattern.lower() for pattern in self.config.redaction.patterns]
        for key, value in arguments.items():
            if any(pattern in key.lower() for pattern in patterns):
                redacted[key] = "***REDACTED***"
            else:
                redacted[key] = value
        return redacted

    def _is_denied_file(self, path: Path) -> bool:
        normalized = path.name
        if normalized in SENSITIVE_FILE_NAMES:
            return True
        return any(
            fnmatch.fnmatch(normalized, pattern) for pattern in self.config.filesystem.deny_patterns
        )

    def _is_inside_allowed_root(self, path: Path) -> bool:
        try:
            resolved = (
                (self.base_dir / path).resolve() if not path.is_absolute() else path.resolve()
            )
        except OSError:
            return False
        for root in self.config.filesystem.allowed_roots:
            root_path = Path(root)
            resolved_root = (
                (self.base_dir / root_path).resolve()
                if not root_path.is_absolute()
                else root_path.resolve()
            )
            if resolved == resolved_root or resolved.is_relative_to(resolved_root):
                return True
        return False

    @staticmethod
    def _reason(action: Decision, risk_tags: list[str], elapsed_ms: float) -> str:
        if risk_tags:
            joined_tags = ", ".join(risk_tags)
            return f"{action.value} after {elapsed_ms:.2f}ms because risks matched: {joined_tags}"
        return f"{action.value} after {elapsed_ms:.2f}ms; no blocking policy matched"
