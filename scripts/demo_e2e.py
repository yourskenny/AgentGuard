from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from agentguard.adapters import MCPToolAdapter
from agentguard.config import load_policy
from agentguard.evaluator import evaluate_cases, load_cases
from agentguard.gateway import create_app
from agentguard.reporting import render_evaluation_markdown, render_json, render_scan_markdown
from agentguard.scanner import scan_mcp_config

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "examples" / "mcp.sample.json"
POLICY_PATH = ROOT / "examples" / "agentguard.yml"
CASES_PATH = ROOT / "tests" / "fixtures" / "security_cases.jsonl"
SAFE_SERVER_PATH = ROOT / "examples" / "safe_mcp_server" / "server.py"
OUT_DIR = ROOT / "runs" / "demo"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    _clean_outputs()

    print("AgentGuard end-to-end demo")
    print(f"workspace: {ROOT}")

    scan_result = scan_mcp_config(CONFIG_PATH)
    _write_text("scan.md", render_scan_markdown(scan_result))
    _write_text("scan.json", render_json(scan_result))
    print(
        "scan:",
        f"{len(scan_result.servers)} servers,",
        f"{scan_result.total_tools} tools,",
        f"risk tags={', '.join(scan_result.risk_tags)}",
    )

    runtime_config = _write_runtime_mcp_config()
    adapter = MCPToolAdapter.from_config(runtime_config, cwd=ROOT)
    client = TestClient(
        create_app(
            policy_path=POLICY_PATH,
            trace_db=OUT_DIR / "trace.sqlite3",
            tool_adapter=adapter,
        )
    )

    allowed = client.post(
        "/v1/tool-calls",
        json={
            "runId": "demo-run",
            "stepId": "allow-read",
            "serverName": "safe-filesystem",
            "toolName": "read_file",
            "arguments": {"path": "README.md"},
        },
    )
    _assert_status(allowed.status_code, 200, "allowed MCP read")
    allowed_payload = allowed.json()
    _write_json("allowed-call.json", allowed_payload)
    _assert_contains(allowed_payload, "AgentGuard", "allowed MCP result")
    print(
        "gateway allow:",
        allowed_payload["decision"]["action"],
        allowed_payload["result"]["adapter"],
    )

    denied = client.post(
        "/v1/tool-calls",
        json={
            "runId": "demo-run",
            "stepId": "deny-path",
            "serverName": "safe-filesystem",
            "toolName": "read_file",
            "arguments": {"path": "../.env"},
        },
    )
    _assert_status(denied.status_code, 403, "denied path traversal")
    denied_payload = denied.json()
    _write_json("denied-call.json", denied_payload)
    print("gateway deny:", denied_payload["error"]["code"])

    trace = client.get("/v1/runs/demo-run/trace")
    _assert_status(trace.status_code, 200, "trace read")
    trace_payload = trace.json()
    _write_json("trace.json", trace_payload)
    print("trace events:", ", ".join(event["eventType"] for event in trace_payload["steps"]))

    evaluation = evaluate_cases(
        load_cases(CASES_PATH),
        config=load_policy(POLICY_PATH),
        base_dir=ROOT,
    )
    _write_text("evaluation.md", render_evaluation_markdown(evaluation))
    _write_text("evaluation.json", render_json(evaluation))
    print(
        "eval:",
        f"{evaluation.metrics.total_cases} cases,",
        f"RiskRecall={evaluation.metrics.risk_recall:.2%},",
        f"FalsePositiveRate={evaluation.metrics.false_positive_rate:.2%}",
    )

    print(f"outputs: {OUT_DIR}")
    return 0


def _write_runtime_mcp_config() -> Path:
    config = {
        "mcpServers": {
            "safe-filesystem": {
                "command": sys.executable,
                "args": [str(SAFE_SERVER_PATH)],
                "env": {},
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a file inside the configured workspace.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
                            "required": ["path"],
                        },
                    }
                ],
            }
        }
    }
    path = OUT_DIR / "mcp.runtime.json"
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path


def _clean_outputs() -> None:
    for name in (
        "allowed-call.json",
        "denied-call.json",
        "evaluation.json",
        "evaluation.md",
        "mcp.runtime.json",
        "scan.json",
        "scan.md",
        "trace.json",
        "trace.sqlite3",
    ):
        path = OUT_DIR / name
        if path.exists():
            path.unlink()


def _write_json(name: str, payload: Any) -> None:
    _write_text(name, json.dumps(payload, indent=2))


def _write_text(name: str, content: str) -> None:
    (OUT_DIR / name).write_text(content, encoding="utf-8")


def _assert_status(actual: int, expected: int, label: str) -> None:
    if actual != expected:
        raise RuntimeError(f"{label} returned {actual}, expected {expected}")


def _assert_contains(payload: Any, expected: str, label: str) -> None:
    rendered = json.dumps(payload)
    if expected not in rendered:
        raise RuntimeError(f"{label} did not contain {expected!r}")


if __name__ == "__main__":
    raise SystemExit(main())
