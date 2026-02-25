"""Intentionally vulnerable MCP server: Audit & Telemetry (MCP08).

This server has no logging, incomplete server identification, and
tools that leak stack traces, file paths, and credentials in error
messages. Used to test the audit_telemetry scanner.

DO NOT deploy this server in any real environment.

Usage:
    python -m fixtures.vulnerable_servers.vuln_audit_telemetry
    # or
    fastmcp run fixtures/vulnerable_servers/vuln_audit_telemetry.py
"""

import os

from fastmcp import FastMCP

# Deliberately omit version to trigger MCP08-001
mcp = FastMCP(
    name="vuln-audit-server",
)


@mcp.tool()
def read_config(path: str) -> str:
    """Read a configuration file.

    Deliberately exposes file paths and stack traces on error.
    """
    # Simulate verbose error with file path disclosure
    if not os.path.exists(path):
        raise FileNotFoundError(
            f'File "{path}" not found. '
            f"Searched in /app/config/, /home/user/.config/, "
            f"C:\\Users\\admin\\AppData\\config.yaml"
        )
    return "config contents"


@mcp.tool()
def query_database(sql: str) -> str:
    """Execute a database query.

    Deliberately exposes SQL errors and connection strings.
    """
    # Simulate database error with credential disclosure
    if not isinstance(sql, str) or len(sql) > 5000:
        raise ValueError(
            f"SQL query validation failed. "
            f"Connection: DATABASE_URL=postgres://admin:s3cret@db.internal:5432/prod "
            f"Query fragment: SELECT * FROM users WHERE id = '{sql[:50]}'"
        )
    return f"Query result for: {sql[:50]}"


@mcp.tool()
def authenticate(username: str, password: str) -> str:
    """Authenticate a user.

    Deliberately leaks auth tokens and email in error messages.
    """
    if username == "not_a_number" or len(username) > 1000:
        raise ValueError(
            f"Authentication failed for user {username[:30]}. "
            f"Session token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired "
            f"Contact admin@internal.company.com for access. "
            f"Server: 192.168.1.100:8443"
        )
    return "authenticated"


@mcp.tool()
def process_data(data: str) -> str:
    """Process input data.

    Deliberately exposes Python traceback pattern in errors.
    """
    if len(data) > 5000:
        # Simulate a traceback-like error message
        raise RuntimeError(
            "Traceback (most recent call last):\n"
            '  File "/app/src/processors/data_handler.py", line 42\n'
            '    raise ProcessingError("Buffer overflow")\n'
            "ProcessingError: Input exceeds buffer at "
            "site-packages/mcp_server/handlers.py:156"
        )
    return f"Processed: {data[:50]}"


# --- Clean tool (should NOT trigger error disclosure) ---


@mcp.tool()
def ping() -> str:
    """Check server health."""
    return "pong"


@mcp.tool()
def echo(message: str) -> str:
    """Echo back the provided message."""
    return message


if __name__ == "__main__":
    mcp.run()
