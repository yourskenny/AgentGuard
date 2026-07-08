from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import PureWindowsPath
from typing import Any

from agentguard.models import MCPServerRecord, RiskRecord, Severity, ToolRecord

INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"\b(disregard|override)\b.*\b(original\s+request|earlier\s+instructions|previous\s+instructions|all\s+instructions)\b",
        r"\bdo\s+not\s+follow\b.*\buser\b",
        r"\bfollow\s+this\s+tool\s+description\s+instead\b",
        r"system\s+prompt",
        r"\b(read|collect|dump|retrieve|inspect)\b.*\b(secrets?|tokens?|credentials?|api\s+keys?|private\s+keys?|passwords?|id_rsa|\.ssh)\b",
        r"exfiltrat(e|ion)",
        r"\b(upload|send|post|forward|leak)\b.*\b(sensitive|secrets?|tokens?|credentials?|api\s+keys?|private\s+keys?|passwords?|file\s+contents?|repository\s+content|webhook|endpoint|remote\s+url|external\s+host)\b",
        r"\b(reveal|print|read|expose)\b.*\b(hidden\s+prompt|system\s+prompt|developer\s+message|system\s+message)\b",
        r"\btreat\s+this\s+description\s+as\s+the\s+new\s+system\s+message\b",
        r"\bbypass\b.*\b(policy|checks?|safety|guardrails?)\b",
    )
)

DANGEROUS_COMMAND_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"rm\s+-rf",
        r"del\s+/s",
        r"format\s+[a-z]:",
        r"curl\s+.*\|\s*(sh|bash|pwsh|powershell)",
        r"wget\s+.*\|\s*(sh|bash|pwsh|powershell)",
    )
)

SENSITIVE_ENV_PATTERN = re.compile(
    r"(TOKEN|SECRET|PASSWORD|API[_-]?KEY|PRIVATE[_-]?KEY)", re.IGNORECASE
)
SENSITIVE_SCHEMA_FIELDS = {"path", "file", "filename", "command", "cmd", "url", "endpoint"}
PACKAGE_RUNNERS = {"npx", "uvx"}
WINDOWS_DRIVE_ROOT_PATTERN = re.compile(r"^[a-zA-Z]:[\\/]*$")
FILESYSTEM_READ_SCHEMA_KEYS = {"path", "file", "filename", "filepath"}
SHELL_SCHEMA_KEYS = {"command", "cmd"}
NETWORK_SCHEMA_KEYS = {"url", "endpoint", "webhook", "uri"}
DATABASE_SCHEMA_KEYS = {"database", "table", "sql", "query", "collection", "connection_string"}
BROWSER_SCHEMA_KEYS = {"selector", "page", "browser", "tab"}
CREDENTIAL_SCHEMA_KEYS = {
    "env",
    "env_key",
    "environment",
    "secret",
    "secret_name",
    "credential",
    "token",
    "password",
    "api_key",
}
SCHEMA_FILESYSTEM_KEYS = {"path", "file", "filename", "filepath"}
SCHEMA_NETWORK_EGRESS_KEYS = {"url", "endpoint", "webhook", "uri"}


def risk(
    category: str,
    severity: Severity,
    evidence: str,
    recommendation: str,
) -> RiskRecord:
    return RiskRecord(
        severity=severity,
        category=category,
        evidence=evidence,
        recommendation=recommendation,
    )


def flatten_schema_keys(schema: dict[str, Any]) -> set[str]:
    keys: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                keys.add(str(key).lower())
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(schema)
    return keys


def iter_schema_objects(schema: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    def visit(value: Any, path: str) -> Iterable[tuple[str, dict[str, Any]]]:
        if not isinstance(value, dict):
            return

        if (
            value.get("type") == "object"
            or "properties" in value
            or "additionalProperties" in value
        ):
            yield path, value

        properties = value.get("properties")
        if isinstance(properties, dict):
            for property_name, child in properties.items():
                yield from visit(child, f"{path}.{property_name}")

        items = value.get("items")
        if isinstance(items, dict):
            yield from visit(items, f"{path}[]")

        additional_properties = value.get("additionalProperties")
        if isinstance(additional_properties, dict):
            yield from visit(additional_properties, f"{path}.*")

    yield from visit(schema, "$")


def _schema_key_evidence(schema_keys: set[str], candidates: set[str]) -> str:
    return ", ".join(sorted(schema_keys & candidates))


def _has_untyped_object(node: dict[str, Any]) -> bool:
    return (
        node.get("type") == "object"
        and not isinstance(node.get("properties"), dict)
        and "additionalProperties" not in node
    )


def _has_broad_additional_properties(node: dict[str, Any]) -> bool:
    additional_properties = node.get("additionalProperties")
    if additional_properties is True:
        return True
    if not isinstance(additional_properties, dict):
        return False
    if not additional_properties:
        return True
    return (
        additional_properties.get("type") == "object"
        and "properties" not in additional_properties
        and additional_properties.get("additionalProperties") is not False
    )


def _has_missing_required(node: dict[str, Any]) -> bool:
    properties = node.get("properties")
    if not isinstance(properties, dict) or not properties:
        return False
    required = node.get("required")
    return not isinstance(required, list) or not required


def infer_capabilities(tool_name: str, description: str, schema: dict[str, Any]) -> list[str]:
    text = f"{tool_name} {description}".lower()
    schema_keys = flatten_schema_keys(schema)
    capabilities: set[str] = set()

    if (
        any(token in text for token in ("read_file", "read file", "filesystem", "path"))
        or schema_keys & FILESYSTEM_READ_SCHEMA_KEYS
    ):
        capabilities.add("filesystem_read")
    if any(
        token in text
        for token in ("write_file", "write file", "write", "delete", "remove", "overwrite")
    ):
        capabilities.add("filesystem_write")
    if (
        any(token in text for token in ("shell", "command", "exec"))
        or schema_keys & SHELL_SCHEMA_KEYS
    ):
        capabilities.add("shell_execution")
    if (
        any(token in text for token in ("http", "url", "post", "webhook", "upload"))
        or schema_keys & NETWORK_SCHEMA_KEYS
    ):
        capabilities.add("network_egress")
    if (
        any(token in text for token in ("database", "sql", "query", "table", "collection"))
        or schema_keys & DATABASE_SCHEMA_KEYS
    ):
        capabilities.add("database_access")
    if (
        any(token in text for token in ("browser", "click", "navigate", "page", "screenshot"))
        or schema_keys & BROWSER_SCHEMA_KEYS
    ):
        capabilities.add("browser_automation")
    if (
        any(
            token in text
            for token in (
                "environment variable",
                "credential",
                "secret",
                "token",
                "api key",
                "password",
            )
        )
        or schema_keys & CREDENTIAL_SCHEMA_KEYS
    ):
        capabilities.add("credential_access")

    return sorted(capabilities)


def analyze_tool(
    server_name: str,
    tool_name: str,
    description: str = "",
    input_schema: dict[str, Any] | None = None,
) -> ToolRecord:
    schema = input_schema or {}
    risks: list[RiskRecord] = []
    tags: set[str] = set()
    score = 0.0

    for pattern in INJECTION_PATTERNS:
        match = pattern.search(description)
        if match:
            tags.add("tool_description_injection")
            score += 0.35
            risks.append(
                risk(
                    "tool_description_injection",
                    Severity.HIGH,
                    f"Tool description matched injection pattern: {match.group(0)!r}",
                    "Review the tool description and remove instructions that target the model.",
                )
            )
            break

    schema_keys = flatten_schema_keys(schema)

    def add_schema_ambiguity(
        severity: Severity,
        evidence: str,
        recommendation: str,
        score_delta: float,
    ) -> None:
        nonlocal score
        tags.add("schema_ambiguity")
        score += score_delta
        risks.append(
            risk(
                "schema_ambiguity",
                severity,
                evidence,
                recommendation,
            )
        )

    command_keys = _schema_key_evidence(schema_keys, SHELL_SCHEMA_KEYS)
    if command_keys:
        add_schema_ambiguity(
            Severity.HIGH,
            f"Input schema exposes command-like parameter(s): {command_keys}.",
            "Constrain command parameters or route them through a deny-by-default policy.",
            0.25,
        )

    filesystem_keys = _schema_key_evidence(schema_keys, SCHEMA_FILESYSTEM_KEYS)
    if filesystem_keys:
        add_schema_ambiguity(
            Severity.HIGH,
            f"Input schema exposes filesystem path parameter(s): {filesystem_keys}.",
            "Validate paths against allowed roots before filesystem access.",
            0.2,
        )

    network_keys = _schema_key_evidence(schema_keys, SCHEMA_NETWORK_EGRESS_KEYS)
    if network_keys:
        add_schema_ambiguity(
            Severity.MEDIUM,
            f"Input schema exposes network destination parameter(s): {network_keys}.",
            "Require confirmation or an allowlist before network egress.",
            0.2,
        )

        tags.add("network_exfiltration")
        score += 0.1
        risks.append(
            risk(
                "network_exfiltration",
                Severity.MEDIUM,
                f"Input schema exposes URL-like parameter(s): {network_keys}.",
                "Require confirmation or an allowlist before network egress.",
            )
        )

    for object_path, object_schema in iter_schema_objects(schema):
        if _has_untyped_object(object_schema):
            add_schema_ambiguity(
                Severity.MEDIUM,
                f"Input schema has an unconstrained object at {object_path}.",
                "Define explicit object properties or set additionalProperties to false.",
                0.15,
            )
        if _has_broad_additional_properties(object_schema):
            add_schema_ambiguity(
                Severity.MEDIUM,
                f"Input schema allows broad additionalProperties at {object_path}.",
                "Constrain additionalProperties with a narrow schema or disable it.",
                0.15,
            )
        if _has_missing_required(object_schema):
            add_schema_ambiguity(
                Severity.MEDIUM,
                f"Input schema object at {object_path} has properties but no required fields.",
                "Declare required fields for security-relevant tool parameters.",
                0.1,
            )

    if "filesystem_write" in infer_capabilities(tool_name, description, schema):
        tags.add("destructive_write")
        score += 0.15
        risks.append(
            risk(
                "destructive_write",
                Severity.MEDIUM,
                "Tool appears able to write, delete, or overwrite files.",
                "Require confirmation and path checks for filesystem writes.",
            )
        )

    return ToolRecord(
        server_name=server_name,
        tool_name=tool_name,
        description=description,
        input_schema=schema,
        capabilities=infer_capabilities(tool_name, description, schema),
        risk_score=min(score, 1.0),
        risk_tags=sorted(tags),
        risks=risks,
    )


def analyze_server(server: MCPServerRecord) -> MCPServerRecord:
    risks = list(server.risks)
    command_line = " ".join([server.command, *server.args]).strip()
    tags_seen: set[str] = set()

    for pattern in DANGEROUS_COMMAND_PATTERNS:
        match = pattern.search(command_line)
        if match and "dangerous_shell" not in tags_seen:
            tags_seen.add("dangerous_shell")
            risks.append(
                risk(
                    "dangerous_shell",
                    Severity.HIGH,
                    f"Server startup command matched dangerous shell pattern: {match.group(0)!r}",
                    "Avoid shell pipelines or destructive commands in MCP server launch config.",
                )
            )

    sensitive_envs = [key for key in server.env_keys if SENSITIVE_ENV_PATTERN.search(key)]
    if sensitive_envs:
        risks.append(
            risk(
                "secret_env_exposure",
                Severity.MEDIUM,
                f"Server receives sensitive environment keys: {', '.join(sorted(sensitive_envs))}",
                "Pass least-privilege scoped credentials and redact env values from logs.",
            )
        )

    unpinned_package = _unpinned_package_source(server.command, server.args)
    if unpinned_package:
        risks.append(
            risk(
                "untrusted_source",
                Severity.MEDIUM,
                f"Server starts package runner without a pinned version: {unpinned_package}",
                "Pin MCP server package versions before allowing them in trusted agent workflows.",
            )
        )

    broad_arg = _broad_filesystem_arg(server.args)
    if broad_arg:
        risks.append(
            risk(
                "broad_filesystem_scope",
                Severity.HIGH,
                f"Server launch arguments expose a broad filesystem scope: {broad_arg}",
                "Restrict server roots to a project workspace instead of home, "
                "parent, or drive roots.",
            )
        )

    analyzed_tools = [
        analyze_tool(server.name, tool.tool_name, tool.description, tool.input_schema)
        for tool in server.tools
    ]
    return server.model_copy(update={"tools": analyzed_tools, "risks": risks})


def _command_name(command: str) -> str:
    name = PureWindowsPath(command).name.lower()
    for suffix in (".cmd", ".exe", ".ps1"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _first_package_arg(args: list[str]) -> str | None:
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in {"--package", "-p"}:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


def _is_npm_package_pinned(package: str) -> bool:
    if package.startswith("@"):
        return package.count("@") >= 2
    return "@" in package


def _is_python_package_pinned(package: str) -> bool:
    return any(operator in package for operator in ("==", ">=", "<=", "~=", "==="))


def _unpinned_package_source(command: str, args: list[str]) -> str | None:
    runner = _command_name(command)
    if runner not in PACKAGE_RUNNERS:
        return None

    package = _first_package_arg(args)
    if not package:
        return runner
    if runner == "npx" and not _is_npm_package_pinned(package):
        return f"{runner} {package}"
    if runner == "uvx" and not _is_python_package_pinned(package):
        return f"{runner} {package}"
    return None


def _broad_filesystem_arg(args: list[str]) -> str | None:
    for arg in args:
        normalized = arg.strip()
        lowered = normalized.lower()
        if normalized in {"/", "\\", "..", "../", "..\\"}:
            return normalized
        if lowered in {"~", "~/", "~\\", "$home", "%userprofile%"}:
            return normalized
        if normalized.startswith("../") or normalized.startswith("..\\"):
            return normalized
        if normalized.startswith("~/") or normalized.startswith("~\\"):
            return normalized
        if WINDOWS_DRIVE_ROOT_PATTERN.fullmatch(normalized):
            return normalized
    return None


def collect_risks(servers: Iterable[MCPServerRecord]) -> list[RiskRecord]:
    risks: list[RiskRecord] = []
    for server in servers:
        risks.extend(server.risks)
        for tool in server.tools:
            risks.extend(tool.risks)
    return risks
