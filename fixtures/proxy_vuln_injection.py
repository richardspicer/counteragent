"""Minimal FastMCP fixture server for integration tests.

Exposes the same tool names as the mcp-audit vuln_injection fixture
(file_search, safe_echo, run_diagnostics, list_processes) but with
safe implementations — no shell execution.

Usage:
    python fixtures/proxy_vuln_injection.py
    fastmcp run fixtures/proxy_vuln_injection.py
"""

from fastmcp import FastMCP

mcp = FastMCP(
    name="vuln-injection-server",
    instructions="A test fixture with safe tool implementations.",
)


@mcp.tool()
def file_search(directory: str, pattern: str) -> str:
    """Search for files matching a pattern in a directory.

    Args:
        directory: The directory path to search in.
        pattern: The filename pattern to search for.
    """
    return f"Search results for {pattern} in {directory}: (none)"


@mcp.tool()
def run_diagnostics(target: str) -> str:
    """Run network diagnostics against a target host.

    Args:
        target: Hostname or IP address to diagnose.
    """
    return f"Diagnostics for {target}: OK"


@mcp.tool()
def safe_echo(message: str) -> str:
    """Echo a message back.

    Args:
        message: The message to echo.
    """
    return message


@mcp.tool()
def list_processes(format: str = "table") -> str:
    """List running processes on the system.

    Args:
        format: Output format — 'table' or 'json'.
    """
    return f"Processes in {format} format: (none)"


if __name__ == "__main__":
    mcp.run(transport="stdio")
