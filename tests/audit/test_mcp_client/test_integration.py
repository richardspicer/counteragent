"""Integration tests for the MCP client (connector + discovery).

Launches a real MCP fixture server and tests connection,
initialization, and capability enumeration.

These tests require the 'fixtures' extra to be installed
(fastmcp is needed for the fixture servers).
"""

import sys

import pytest

from counteragent.core.connection import MCPConnection
from counteragent.core.discovery import enumerate_server

# Path to our vulnerable fixture server
VULN_INJECTION_SERVER = "fixtures/vulnerable_servers/vuln_injection.py"

# Use the same Python interpreter running the tests (the venv's Python),
# so the fixture server can import fastmcp and other venv packages.
PYTHON = sys.executable


class TestStdioConnection:
    """Test connecting to an MCP server via stdio transport."""

    @pytest.mark.asyncio
    async def test_connect_and_initialize(self):
        """Can connect to a fixture server and complete the MCP handshake."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            assert conn.session is not None
            assert conn.init_result is not None
            assert conn.init_result.protocolVersion is not None
            assert conn.transport_type == "stdio"

    @pytest.mark.asyncio
    async def test_server_info(self):
        """Server info is populated from the handshake response."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            info = conn.init_result.serverInfo
            assert info is not None
            assert info.name == "vuln-injection-server"


class TestEnumeration:
    """Test server capability enumeration."""

    @pytest.mark.asyncio
    async def test_enumerate_tools(self):
        """Discovers all tools exposed by the fixture server."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)

            assert len(ctx.tools) == 4
            tool_names = {t["name"] for t in ctx.tools}
            assert tool_names == {"file_search", "run_diagnostics", "safe_echo", "list_processes"}

    @pytest.mark.asyncio
    async def test_tool_has_schema(self):
        """Each tool has an input schema with parameter definitions."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)

            for tool in ctx.tools:
                assert "inputSchema" in tool
                assert tool["inputSchema"] is not None

    @pytest.mark.asyncio
    async def test_scan_context_metadata(self):
        """ScanContext includes server info and transport type."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)

            assert ctx.server_info["name"] == "vuln-injection-server"
            assert ctx.transport_type == "stdio"
            assert ctx.server_info["protocolVersion"] is not None

    @pytest.mark.asyncio
    async def test_tool_descriptions(self):
        """Tools have descriptions that describe their function."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)

            file_search = next(t for t in ctx.tools if t["name"] == "file_search")
            assert (
                "pattern" in file_search["description"].lower()
                or "file" in file_search["description"].lower()
            )
