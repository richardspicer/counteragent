"""Intentionally vulnerable MCP server: Insufficient Authentication (MCP07).

This server exposes sensitive tools with NO authentication or
authorization controls. Any client can connect, enumerate capabilities,
and invoke tools — including those that read files and access secrets.

Models CVE-2025-49596 pattern: no auth, open binding, no origin checks.

DO NOT deploy this server in any real environment.

Usage:
    python -m fixtures.vulnerable_servers.vuln_auth
    # or
    fastmcp run fixtures/vulnerable_servers/vuln_auth.py
"""

from fastmcp import FastMCP

mcp = FastMCP(
    name="vuln-auth-server",
    instructions="A test server with no authentication — all tools are publicly accessible.",
)


@mcp.tool()
def read_config(path: str) -> str:
    """Read a configuration file from the server.

    Args:
        path: Path to the config file to read.
    """
    # VULNERABLE: No auth check — anyone can read server files
    # Simulated response (doesn't actually read files for safety)
    return (
        f"[config contents from {path}]\n"
        "db_host=localhost\ndb_password=hunter2\napi_key=sk-fake-1234"
    )


@mcp.tool()
def list_secrets() -> str:
    """List available secrets and API keys.

    Returns a list of secret names stored on the server.
    """
    # VULNERABLE: Sensitive operation with no auth
    return (
        "Available secrets:\n"
        "  DATABASE_PASSWORD (set 2025-01-15)\n"
        "  STRIPE_API_KEY (set 2025-02-01)\n"
        "  AWS_SECRET_KEY (set 2025-01-20)\n"
        "  OPENAI_API_KEY (set 2025-02-10)"
    )


@mcp.tool()
def execute_query(sql: str) -> str:
    """Execute a SQL query against the database.

    Args:
        sql: The SQL query to execute.
    """
    # VULNERABLE: Database access with no auth or authorization
    return f"[query result for: {sql}]\nRows returned: 42"


@mcp.tool()
def server_status() -> str:
    """Check server health and uptime.

    A low-sensitivity tool that returns basic status info.
    """
    # LOW RISK: Status endpoints are commonly unauthenticated
    return "Server OK | Uptime: 47d 3h | Version: 1.2.3"


if __name__ == "__main__":
    mcp.run()
