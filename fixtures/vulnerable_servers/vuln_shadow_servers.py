"""Intentionally vulnerable MCP server: Shadow Servers (MCP09).

This server exhibits characteristics of a shadow/unmanaged deployment:
- Server name contains "test" and hex suffix (MCP09-001, MCP09-005)
- Version contains "dev" and is 0.x (MCP09-001, MCP09-005)
- No server description (MCP09-004 when 5+ tools)
- Multiple debug/test tools exposed (MCP09-003)

DO NOT deploy this server in any real environment.

Usage:
    python -m fixtures.vulnerable_servers.vuln_shadow_servers
    # or
    fastmcp run fixtures/vulnerable_servers/vuln_shadow_servers.py
"""

from fastmcp import FastMCP

# Server name triggers MCP09-001 ("test") and MCP09-005 (hex suffix).
# Version triggers MCP09-001 ("dev") and MCP09-005 (0.x-dev pattern).
# No description triggers MCP09-004 with 7 tools (>= 5 threshold).
mcp = FastMCP(
    name="debug-test-mcp-abc123def456",
    version="0.0.1-dev",
)


# --- Debug/test tools (should trigger MCP09-003) ---


@mcp.tool()
def debug_dump_state() -> str:
    """Dump internal server state for debugging."""
    return '{"state": "mock debug state"}'


@mcp.tool()
def test_echo(message: str) -> str:
    """Echo input back for testing only."""
    return message


@mcp.tool()
def inspect_context() -> str:
    """Inspect current context window - for development only."""
    return '{"context": "mock context"}'


@mcp.tool()
def mock_api_call(endpoint: str) -> str:
    """Mock external API call for testing."""
    return f'{{"endpoint": "{endpoint}", "status": "mocked"}}'


@mcp.tool()
def tmp_cleanup() -> str:
    """Temporary cleanup utility."""
    return "cleanup complete"


# --- Normal tools (should NOT trigger MCP09-003 by themselves) ---


@mcp.tool()
def get_data(query: str) -> str:
    """Get data based on query."""
    return f'{{"query": "{query}", "results": []}}'


@mcp.tool()
def process_request(data: str) -> str:
    """Process incoming request data."""
    return f'{{"processed": "{data}"}}'


if __name__ == "__main__":
    mcp.run()
