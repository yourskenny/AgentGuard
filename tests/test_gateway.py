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


def test_healthz_returns_service_status(tmp_path):
    client = TestClient(create_app(trace_db=tmp_path / "trace.sqlite3"))

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "agentguard"}


def test_authorize_records_only_policy_decision_trace(tmp_path):
    client = TestClient(create_app(trace_db=tmp_path / "trace.sqlite3"))

    response = client.post(
        "/v1/tool-calls:authorize",
        json={
            "runId": "authorize-only-run",
            "stepId": "step-1",
            "toolName": "read_file",
            "arguments": {"path": "README.md"},
        },
    )
    trace = client.get("/v1/runs/authorize-only-run/trace").json()
    event_types = [event["eventType"] for event in trace["steps"]]

    assert response.status_code == 200
    assert response.json()["action"] == "allow"
    assert event_types == ["policy_decision"]


def test_call_tool_returns_403_error_body_for_denied_request(tmp_path):
    client = TestClient(create_app(trace_db=tmp_path / "trace.sqlite3"))

    response = client.post(
        "/v1/tool-calls",
        json={"toolName": "read_file", "arguments": {"path": "../secret.txt"}},
    )
    payload = response.json()

    assert response.status_code == 403
    assert payload["error"]["code"] == "policy_denied"
    assert payload["error"]["requestId"]
    assert payload["error"]["details"]["decision"] == "deny"
    assert "broad_filesystem_scope" in payload["error"]["details"]["riskTags"]


def test_call_tool_returns_409_error_body_for_confirm_request(tmp_path):
    client = TestClient(create_app(trace_db=tmp_path / "trace.sqlite3"))

    response = client.post(
        "/v1/tool-calls",
        json={"toolName": "write_file", "arguments": {"path": "README.md", "content": "x"}},
    )
    payload = response.json()

    assert response.status_code == 409
    assert payload["error"]["code"] == "human_confirmation_required"
    assert payload["error"]["requestId"]
    assert payload["error"]["details"]["decision"] == "confirm"


def test_call_tool_records_policy_and_result_trace_for_allowed_request(tmp_path):
    client = TestClient(create_app(trace_db=tmp_path / "trace.sqlite3"))

    response = client.post(
        "/v1/tool-calls",
        json={
            "runId": "allowed-call-run",
            "stepId": "step-1",
            "toolName": "read_file",
            "arguments": {"path": "README.md"},
        },
    )
    trace = client.get("/v1/runs/allowed-call-run/trace").json()
    event_types = [event["eventType"] for event in trace["steps"]]

    assert response.status_code == 200
    assert response.json()["decision"]["action"] == "allow"
    assert event_types == ["policy_decision", "tool_result"]


def test_trace_write_and_read_roundtrip(tmp_path):
    client = TestClient(create_app(trace_db=tmp_path / "trace.sqlite3"))

    write_response = client.post(
        "/v1/traces",
        json={
            "runId": "manual-trace-run",
            "stepId": "manual-step",
            "eventType": "policy_decision",
            "payload": {"ok": True},
        },
    )
    trace_response = client.get("/v1/runs/manual-trace-run/trace")

    assert write_response.status_code == 201
    assert write_response.json() == {"stored": True}
    assert trace_response.status_code == 200
    assert trace_response.json()["steps"][0]["payload"] == {"ok": True}
