import pytest

from agentguard.metadata import infer_capabilities


@pytest.mark.parametrize(
    ("tool_name", "description", "schema", "expected"),
    [
        ("read_file", "Read a local file.", {}, "filesystem_read"),
        (
            "open_document",
            "Open a workspace path.",
            {"type": "object", "properties": {"path": {"type": "string"}}},
            "filesystem_read",
        ),
        ("write_file", "Write file contents.", {}, "filesystem_write"),
        ("delete_path", "Delete a file or directory.", {}, "filesystem_write"),
        (
            "run_command",
            "Run a shell command.",
            {"type": "object", "properties": {"command": {"type": "string"}}},
            "shell_execution",
        ),
        ("exec_shell", "Execute shell process.", {}, "shell_execution"),
        ("http_post", "POST data to an external URL.", {}, "network_egress"),
        (
            "send_webhook",
            "Send a webhook.",
            {"type": "object", "properties": {"url": {"type": "string"}}},
            "network_egress",
        ),
        ("query_database", "Run a SQL query.", {}, "database_access"),
        (
            "fetch_table",
            "Read records from a database table.",
            {"type": "object", "properties": {"table": {"type": "string"}}},
            "database_access",
        ),
        ("browser_click", "Click an element in the browser.", {}, "browser_automation"),
        (
            "navigate_browser",
            "Navigate a web page.",
            {"type": "object", "properties": {"selector": {"type": "string"}}},
            "browser_automation",
        ),
        ("get_env", "Read an environment variable.", {}, "credential_access"),
        (
            "read_secret",
            "Read a credential by name.",
            {"type": "object", "properties": {"secret_name": {"type": "string"}}},
            "credential_access",
        ),
    ],
)
def test_infer_capabilities_classifies_tool_ability(tool_name, description, schema, expected):
    assert expected in infer_capabilities(tool_name, description, schema)


def test_infer_capabilities_allows_multiple_capabilities():
    capabilities = infer_capabilities(
        "write_and_post_file",
        "Write a file and upload it to a webhook.",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "url": {"type": "string"},
            },
        },
    )

    assert capabilities == ["filesystem_read", "filesystem_write", "network_egress"]
