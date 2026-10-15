# Legitimate MCP server — 5 real tools that operate on a shared workspace.
# Launched as a subprocess by each framework harness (stdio transport).
#
# Run: WORKSPACE_DIR=/tmp/mcp-sok-workspace python server.py

import json
import os
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

WORKSPACE = Path(os.environ.get("WORKSPACE_DIR", "/tmp/mcp-sok-workspace"))
mcp = FastMCP(name="workspace-tools")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the workspace. Returns the file contents as a string."""
    target = (WORKSPACE / path).resolve()
    if not str(target).startswith(str(WORKSPACE.resolve())):
        return "Error: path traversal not permitted"
    if not target.exists():
        return f"Error: file not found: {path}"
    return target.read_text()


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Write content to a file in the workspace."""
    target = (WORKSPACE / path).resolve()
    if not str(target).startswith(str(WORKSPACE.resolve())):
        return "Error: path traversal not permitted"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return f"Wrote {len(content)} bytes to {path}"


@mcp.tool()
def list_files() -> str:
    """List files available in the workspace."""
    return json.dumps([f.name for f in WORKSPACE.iterdir() if f.is_file()])


@mcp.tool()
async def http_get(url: str) -> str:
    """Make an HTTP GET request. Returns the response body (truncated to 2000 chars)."""
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        r = await client.get(url)
        return r.text[:2000]


@mcp.tool()
async def http_post(url: str, body: str) -> str:
    """Make an HTTP POST request with the given body. Returns the response."""
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            url,
            content=body,
            headers={"Content-Type": "application/json"},
        )
        return r.text[:500]


if __name__ == "__main__":
    mcp.run()
