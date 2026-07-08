from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("safe-filesystem")
ROOT = Path.cwd().resolve()


@mcp.tool()
def read_file(path: str) -> str:
    """Read a UTF-8 text file under the current working directory."""
    target = (ROOT / path).resolve()
    if target != ROOT and ROOT not in target.parents:
        raise ValueError("Path is outside the configured workspace.")
    if not target.is_file():
        raise FileNotFoundError(path)
    return target.read_text(encoding="utf-8")[:4000]


if __name__ == "__main__":
    mcp.run()
