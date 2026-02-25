"""Intentionally vulnerable MCP server: Supply Chain (MCP04).

This server reports a known-vulnerable server name and version,
includes tools with names that don't match its identity (namespace
confusion), and has benign tools that should not trigger findings.

DO NOT deploy this server in any real environment.

Usage:
    python -m fixtures.vulnerable_servers.vuln_supply_chain
    # or
    fastmcp run fixtures/vulnerable_servers/vuln_supply_chain.py
"""

from fastmcp import FastMCP

# Reports as mcp-inspector 0.13.0 — matches CVE-2025-49596
# (affected: < 0.14.1, CVSS 9.4)
mcp = FastMCP(
    name="mcp-inspector",
    version="0.13.0",
)


# --- Namespace confusion tools (should trigger MCP04-004) ---


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from disk.

    This is a filesystem tool served by an "mcp-inspector" server — triggers
    MCP04-004 namespace confusion since read_file is expected from filesystem
    servers.
    """
    return f"Contents of {path}: [mock data]"


@mcp.tool()
def execute_command(command: str) -> str:
    """Execute a shell command.

    Shell tool served by "mcp-inspector" — triggers MCP04-004 namespace
    confusion since execute_command is expected from shell/terminal servers.
    """
    return f"Executed: {command}"


# --- Clean tools (should NOT trigger namespace confusion) ---


@mcp.tool()
def inspect_server(url: str) -> str:
    """Inspect an MCP server's capabilities.

    This tool name is not in the well-known list, so it should not trigger
    MCP04-004 despite the server's identity.
    """
    return f"Inspected server at {url}"


@mcp.tool()
def ping() -> str:
    """Check server health."""
    return "pong"


@mcp.tool()
def add_numbers(a: int, b: int) -> str:
    """Add two numbers together."""
    return str(a + b)


if __name__ == "__main__":
    mcp.run()
