from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from agentguard.models import Decision


class FilesystemPolicy(BaseModel):
    allowed_roots: list[str] = Field(default_factory=lambda: ["."])
    deny_patterns: list[str] = Field(
        default_factory=lambda: [
            ".env",
            ".env.*",
            "id_rsa",
            "id_ed25519",
            "*.pem",
            "cookies*",
            "cookies.sqlite",
        ]
    )


class ToolPolicy(BaseModel):
    action: Decision = Decision.CONFIRM
    require_path_check: bool = False


class RedactionPolicy(BaseModel):
    enabled: bool = True
    patterns: list[str] = Field(default_factory=lambda: ["api_key", "token", "password", "secret"])


class AgentGuardConfig(BaseModel):
    default_action: Decision = Decision.CONFIRM
    filesystem: FilesystemPolicy = Field(default_factory=FilesystemPolicy)
    tools: dict[str, ToolPolicy] = Field(default_factory=dict)
    redaction: RedactionPolicy = Field(default_factory=RedactionPolicy)


def default_config() -> AgentGuardConfig:
    return AgentGuardConfig(
        tools={
            "shell": ToolPolicy(action=Decision.DENY),
            "run_command": ToolPolicy(action=Decision.DENY),
            "read_file": ToolPolicy(action=Decision.ALLOW, require_path_check=True),
            "write_file": ToolPolicy(action=Decision.CONFIRM, require_path_check=True),
            "http_post": ToolPolicy(action=Decision.CONFIRM),
        }
    )


def load_policy(path: str | Path | None) -> AgentGuardConfig:
    if path is None:
        return default_config()

    policy_path = Path(path)
    raw = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    return AgentGuardConfig.model_validate(raw)
