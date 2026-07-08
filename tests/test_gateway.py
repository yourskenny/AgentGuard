import json

from fastapi.testclient import TestClient

from agentguard.adapters import ToolAdapterError
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


def test_call_tool_records_policy_call_and_result_trace_for_allowed_request(tmp_path):
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
    tool_call_payload = trace["steps"][1]["payload"]

    assert response.status_code == 200
    assert response.json()["decision"]["action"] == "allow"
    assert event_types == ["policy_decision", "tool_call", "tool_result"]
    assert tool_call_payload["toolName"] == "read_file"
    assert tool_call_payload["argumentsSummary"] == {"path": "README.md"}


def test_call_tool_trace_redacts_arguments_and_result_summary(tmp_path):
    client = TestClient(create_app(trace_db=tmp_path / "trace.sqlite3"))

    response = client.post(
        "/v1/tool-calls",
        json={
            "runId": "redacted-call-run",
            "stepId": "step-1",
            "toolName": "read_file",
            "arguments": {
                "path": "README.md",
                "headers": {"api_key": "sk-call-secret"},
            },
        },
    )
    trace = client.get("/v1/runs/redacted-call-run/trace").json()
    rendered = json.dumps(trace)
    tool_call_payload = trace["steps"][1]["payload"]
    result_payload = trace["steps"][2]["payload"]

    assert response.status_code == 200
    assert response.json()["decision"]["action"] == "redact"
    assert "sk-call-secret" not in rendered
    assert tool_call_payload["argumentsSummary"]["headers"]["api_key"] == "***REDACTED***"
    assert result_payload["resultSummary"]["arguments"]["headers"]["api_key"] == "***REDACTED***"


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


def test_denied_tool_call_does_not_execute_adapter(tmp_path):
    class CountingAdapter:
        def __init__(self):
            self.calls = 0

        def execute(self, request):
            self.calls += 1
            return {"ok": True}

    adapter = CountingAdapter()
    client = TestClient(create_app(trace_db=tmp_path / "trace.sqlite3", tool_adapter=adapter))

    response = client.post(
        "/v1/tool-calls",
        json={"toolName": "read_file", "arguments": {"path": "../secret.txt"}},
    )

    assert response.status_code == 403
    assert adapter.calls == 0


def test_allowed_tool_call_returns_mock_adapter_result(tmp_path):
    client = TestClient(create_app(trace_db=tmp_path / "trace.sqlite3"))

    response = client.post(
        "/v1/tool-calls",
        json={
            "serverName": "filesystem",
            "toolName": "read_file",
            "arguments": {"path": "README.md"},
        },
    )
    payload = response.json()

    assert response.status_code == 200
    assert payload["result"] == {
        "adapter": "mock",
        "serverName": "filesystem",
        "toolName": "read_file",
        "arguments": {"path": "README.md"},
        "content": "mock adapter executed read_file",
    }


def test_adapter_error_is_recorded_as_trace_error_event(tmp_path):
    class FailingAdapter:
        def execute(self, request):
            raise ToolAdapterError("adapter exploded", code="adapter_failed")

    client = TestClient(
        create_app(trace_db=tmp_path / "trace.sqlite3", tool_adapter=FailingAdapter())
    )

    response = client.post(
        "/v1/tool-calls",
        json={
            "runId": "adapter-error-run",
            "stepId": "step-1",
            "toolName": "read_file",
            "arguments": {"path": "README.md"},
        },
    )
    trace = client.get("/v1/runs/adapter-error-run/trace").json()
    event_types = [event["eventType"] for event in trace["steps"]]
    error_payload = trace["steps"][2]["payload"]

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "adapter_failed"
    assert event_types == ["policy_decision", "tool_call", "tool_error"]
    assert error_payload["toolName"] == "read_file"
    assert error_payload["error"]["code"] == "adapter_failed"
    assert error_payload["error"]["message"] == "adapter exploded"
