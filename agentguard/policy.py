from __future__ import annotations

import fnmatch
import os
import re
import time
from collections.abc import Iterable
from pathlib import Path, PureWindowsPath
from typing import Any

from agentguard.config import AgentGuardConfig, default_config
from agentguard.metadata import DANGEROUS_COMMAND_PATTERNS, risk
from agentguard.models import Decision, PolicyDecision, RiskRecord, Severity, ToolCallRequest

SENSITIVE_FILE_NAMES = {".env", "id_rsa", "id_ed25519", "cookies", "cookies.sqlite"}
PATH_ARGUMENT_NAMES = {"file", "file_path", "filepath", "filename"}
NETWORK_TOOLS = {"http_post", "post_url", "webhook", "upload", "send_request"}
SHELL_TOOLS = {"shell", "run_command", "exec", "execute", "bash", "powershell", "pwsh", "cmd"}
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
        if tool_name in SHELL_TOOLS:
            return Decision.DENY
        if tool_name in WRITE_TOOLS:
            return Decision.CONFIRM
        if tool_name in NETWORK_TOOLS:
            return Decision.CONFIRM
        return self.config.default_action

    def _filesystem_risks(self, request: ToolCallRequest) -> list[RiskRecord]:
        risks: list[RiskRecord] = []
        for key, value in self._iter_path_arguments(request.arguments):
            if self._is_denied_file(value):
                risks.append(
                    risk(
                        "sensitive_file_access",
                        Severity.HIGH,
                        f"Argument {key!r} points to denied file pattern: {value}",
                        "Block sensitive file access or require explicit one-time approval.",
                    )
                )
            if not self._is_inside_allowed_root(value):
                risks.append(
                    risk(
                        "broad_filesystem_scope",
                        Severity.HIGH,
                        f"Argument {key!r} resolves outside allowed roots after normalization: "
                        f"{value}",
                        "Restrict file access to configured workspace roots and treat parent "
                        "traversal or symlink-resolved escapes as denied.",
                    )
                )
        return risks

    def _shell_risks(self, request: ToolCallRequest) -> list[RiskRecord]:
        risks: list[RiskRecord] = []
        if request.tool_name not in SHELL_TOOLS:
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

    def _iter_path_arguments(
        self, value: dict[str, Any] | list[Any], prefix: str = ""
    ) -> Iterable[tuple[str, str]]:
        if isinstance(value, dict):
            for raw_key, child in value.items():
                key = str(raw_key)
                argument_name = f"{prefix}.{key}" if prefix else key
                if isinstance(child, str) and self._is_path_argument_key(key):
                    yield argument_name, child
                elif isinstance(child, dict | list):
                    yield from self._iter_path_arguments(child, argument_name)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                argument_name = f"{prefix}[{index}]"
                if isinstance(child, dict | list):
                    yield from self._iter_path_arguments(child, argument_name)

    @staticmethod
    def _is_path_argument_key(key: str) -> bool:
        normalized = key.lower()
        return (
            "path" in normalized
            or normalized in PATH_ARGUMENT_NAMES
            or normalized.endswith("_file")
            or normalized.endswith("-file")
        )

    def _is_denied_file(self, path_value: str) -> bool:
        parts = [
            part.lower()
            for part in re.split(r"[\\/]+", path_value)
            if part and part not in {".", ".."}
        ]
        patterns = [pattern.lower() for pattern in self.config.filesystem.deny_patterns]
        if any(part in SENSITIVE_FILE_NAMES for part in parts):
            return True
        return any(fnmatch.fnmatch(part, pattern) for part in parts for pattern in patterns)

    def _is_inside_allowed_root(self, path_value: str) -> bool:
        if self._is_unsupported_windows_path(path_value):
            return False
        path_text = self._normalize_path_text(path_value)
        try:
            path = Path(path_text)
            resolved = (
                (self.base_dir / path).resolve(strict=False)
                if not path.is_absolute()
                else path.resolve(strict=False)
            )
        except OSError:
            return False
        for root in self.config.filesystem.allowed_roots:
            root_path = Path(self._normalize_path_text(root))
            resolved_root = (
                (self.base_dir / root_path).resolve(strict=False)
                if not root_path.is_absolute()
                else root_path.resolve(strict=False)
            )
            if resolved == resolved_root or resolved.is_relative_to(resolved_root):
                return True
        return False

    @staticmethod
    def _normalize_path_text(path_value: str) -> str:
        if os.name == "nt":
            return path_value
        return path_value.replace("\\", "/")

    @staticmethod
    def _is_unsupported_windows_path(path_value: str) -> bool:
        windows_path = PureWindowsPath(path_value)
        if not windows_path.drive:
            return False
        return os.name != "nt" or not Path(path_value).is_absolute()

    @staticmethod
    def _reason(action: Decision, risk_tags: list[str], elapsed_ms: float) -> str:
        if risk_tags:
            joined_tags = ", ".join(risk_tags)
            return f"{action.value} after {elapsed_ms:.2f}ms because risks matched: {joined_tags}"
        return f"{action.value} after {elapsed_ms:.2f}ms; no blocking policy matched"
