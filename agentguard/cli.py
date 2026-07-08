from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from agentguard.config import load_policy
from agentguard.evaluator import evaluate_cases, load_cases
from agentguard.reporting import (
    render_empty_report,
    render_evaluation_markdown,
    render_json,
    render_sarif,
    render_scan_markdown,
    write_text,
)
from agentguard.scanner import inspect_server, scan_mcp_config

app = typer.Typer(no_args_is_help=True, help="AgentGuard MCP tool security gateway.")


@app.command()
def scan(
    config: Annotated[Path, typer.Option("--config", "-c", exists=True, help="MCP config file.")],
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output path.")] = None,
    format_name: Annotated[
        str, typer.Option("--format", "-f", help="markdown, json, or sarif.")
    ] = "markdown",
) -> None:
    """Scan an MCP config and report server/tool risks."""
    try:
        result = scan_mcp_config(config)
    except ValueError as exc:
        _exit_with_error(str(exc))
    content = _render_scan(result, format_name)
    write_text(output, content)


@app.command()
def inspect(
    server: Annotated[str, typer.Option("--server", "-s", help="Server name to inspect.")],
    config: Annotated[Path, typer.Option("--config", "-c", exists=True, help="MCP config file.")],
) -> None:
    """Show normalized metadata and risk records for one server."""
    try:
        record = inspect_server(config, server)
    except (KeyError, ValueError) as exc:
        _exit_with_error(str(exc))
    typer.echo(render_json(record))


@app.command()
def proxy(
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", exists=True, help="AgentGuard policy YAML."),
    ] = None,
    listen: Annotated[str, typer.Option("--listen", help="Host:port to bind.")] = "127.0.0.1:8787",
    trace_db: Annotated[
        Path,
        typer.Option("--trace-db", help="SQLite trace DB."),
    ] = Path("runs/agentguard.sqlite3"),
) -> None:
    """Start the local runtime gateway."""
    import uvicorn

    from agentguard.gateway import create_app

    host, port = _parse_listen(listen)
    uvicorn.run(create_app(policy_path=policy, trace_db=trace_db), host=host, port=port)


@app.command("eval")
def eval_command(
    cases: Annotated[Path, typer.Option("--cases", exists=True, help="JSONL security cases.")],
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", exists=True, help="AgentGuard policy YAML."),
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output path.")] = None,
    format_name: Annotated[
        str, typer.Option("--format", "-f", help="markdown, json, or sarif.")
    ] = "markdown",
) -> None:
    """Replay safety cases through the policy engine."""
    try:
        config = load_policy(policy)
        result = evaluate_cases(load_cases(cases), config=config, base_dir=Path.cwd())
    except ValueError as exc:
        _exit_with_error(str(exc))
    content = _render_eval(result, format_name)
    write_text(output, content)


@app.command()
def report(
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output path.")] = None,
    format_name: Annotated[
        str, typer.Option("--format", "-f", help="markdown, json, or sarif.")
    ] = "json",
) -> None:
    """Generate an empty report shell for automation wiring."""
    write_text(output, render_empty_report(format_name))


def _render_scan(result, format_name: str) -> str:
    if format_name == "markdown":
        return render_scan_markdown(result)
    if format_name == "json":
        return render_json(result)
    if format_name == "sarif":
        return render_sarif(result)
    raise typer.BadParameter("format must be one of: markdown, json, sarif")


def _render_eval(result, format_name: str) -> str:
    if format_name == "markdown":
        return render_evaluation_markdown(result)
    if format_name == "json":
        return render_json(result)
    if format_name == "sarif":
        return render_sarif(result)
    raise typer.BadParameter("format must be one of: markdown, json, sarif")


def _parse_listen(value: str) -> tuple[str, int]:
    if ":" not in value:
        raise typer.BadParameter("listen must be HOST:PORT")
    host, port_text = value.rsplit(":", 1)
    return host, int(port_text)


def _exit_with_error(message: str) -> None:
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(1)
