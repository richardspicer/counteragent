"""Intentionally vulnerable MCP server: Command Injection (MCP05).

This server has tools that pass user input directly to shell commands
without sanitization. Used for testing mcp-audit's injection scanner.

DO NOT deploy this server in any real environment.

Usage:
    python -m fixtures.vulnerable_servers.vuln_injection
    # or
    fastmcp run fixtures/vulnerable_servers/vuln_injection.py
"""

import subprocess

from fastmcp import FastMCP

mcp = FastMCP(
    name="vuln-injection-server",
    instructions="A test server with intentional command injection vulnerabilities.",
)


@mcp.tool()
def file_search(directory: str, pattern: str) -> str:
    """Search for files matching a pattern in a directory.

    Args:
        directory: The directory path to search in.
        pattern: The filename pattern to search for (e.g., '*.txt').
    """
    # VULNERABLE: directory and pattern appended to shell command unquoted,
    # allowing shell metacharacters to break out and execute arbitrary commands.
    result = subprocess.run(
        f'python -c "import sys, glob; print(glob.glob(sys.argv[1]))" {directory}/{pattern}',
        shell=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=10,
    )
    return result.stdout or result.stderr or "No results found."


@mcp.tool()
def run_diagnostics(target: str) -> str:
    """Run network diagnostics against a target host.

    Args:
        target: Hostname or IP address to diagnose.
    """
    # VULNERABLE: target appended to shell command unquoted,
    # allowing shell metacharacters to break out and execute arbitrary commands.
    result = subprocess.run(
        f"python -c \"import sys; print('Diagnosing:', sys.argv[1])\" {target}",
        shell=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=10,
    )
    return result.stdout or result.stderr


@mcp.tool()
def safe_echo(message: str) -> str:
    """Echo a message back (safe — no shell involvement).

    Args:
        message: The message to echo.
    """
    # SAFE: no shell execution, returns input unchanged
    return message


@mcp.tool()
def list_processes(format: str = "table") -> str:
    """List running processes on the system.

    Args:
        format: Output format — 'table' or 'json'.
    """
    # VULNERABLE: format param appended to shell command unquoted,
    # allowing shell metacharacters to break out and execute arbitrary commands.
    result = subprocess.run(
        f"python -c \"import sys; print('Processes in', sys.argv[1], 'format')\" {format}",
        shell=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=10,
    )
    return result.stdout or result.stderr


if __name__ == "__main__":
    mcp.run()
