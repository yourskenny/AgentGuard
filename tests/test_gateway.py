import json

from fastapi.testclient import TestClient

from agentguard.gateway import create_app


def test_authorize_trace_redacts_nested_secret(tmp_path):
    app = create_app(trace_db=tmp_path / "trace.sqlite3")
    client = TestClient(app)

    response = client.post(
        "/v1/tool-calls:authorize",
        json={
            "runId": "redact-trace-run",
            "toolName": "read_file",
            "arguments": {
                "path": "README.md",
                "headers": {"api_key": "sk-trace-secret"},
            },
        },
    )

    assert response.status_code == 200
    trace_response = client.get("/v1/runs/redact-trace-run/trace")
    trace_payload = trace_response.json()
    rendered = json.dumps(trace_payload)

    assert "sk-trace-secret" not in rendered
    assert "***REDACTED***" in rendered
