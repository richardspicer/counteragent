"""Tests for the permissions scanner (MCP02).

Tests the permissions scanner against the vulnerable fixture server
and with synthetic ScanContext objects for edge cases.
"""

import sys

import pytest

from counteragent.core.connection import MCPConnection
from counteragent.core.discovery import enumerate_server
from counteragent.core.models import ScanContext
from counteragent.scan.scanner.permissions import (
    PermissionsScanner,
    _check_param_constraints,
    _classify_tool_category,
)

VULN_PERMS_SERVER = "fixtures/vulnerable_servers/vuln_permissions.py"
PYTHON = sys.executable


class TestPermissionsScanner:
    """Test the permissions scanner against the fixture server."""

    @pytest.mark.asyncio
    async def test_finds_excessive_tools(self):
        """Scanner detects excessive tool count on the fixture."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_PERMS_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = PermissionsScanner()
            findings = await scanner.scan(ctx)

            excessive = [f for f in findings if f.rule_id == "MCP02-001"]
            assert len(excessive) == 1, "Should detect excessive tool count"
            assert "16" in excessive[0].description or "tool" in excessive[0].description

    @pytest.mark.asyncio
    async def test_finds_dangerous_capabilities(self):
        """Scanner detects dangerous tool categories."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_PERMS_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = PermissionsScanner()
            findings = await scanner.scan(ctx)

            dangerous = [f for f in findings if f.rule_id == "MCP02-002"]
            assert len(dangerous) >= 5, (
                f"Should detect multiple dangerous tools, got {len(dangerous)}: "
                f"{[f.tool_name for f in dangerous]}"
            )

    @pytest.mark.asyncio
    async def test_finds_unconstrained_params(self):
        """Scanner detects unconstrained dangerous parameters."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_PERMS_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = PermissionsScanner()
            findings = await scanner.scan(ctx)

            unconstrained = [f for f in findings if f.rule_id == "MCP02-003"]
            assert len(unconstrained) >= 3, (
                f"Should detect unconstrained params, got {len(unconstrained)}"
            )

    @pytest.mark.asyncio
    async def test_finds_high_write_ratio(self):
        """Scanner detects high write/execute ratio."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_PERMS_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = PermissionsScanner()
            findings = await scanner.scan(ctx)

            ratio = [f for f in findings if f.rule_id == "MCP02-004"]
            assert len(ratio) == 1, "Should detect high write ratio"

    @pytest.mark.asyncio
    async def test_findings_have_remediation(self):
        """Each finding includes remediation guidance."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_PERMS_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = PermissionsScanner()
            findings = await scanner.scan(ctx)

            for f in findings:
                assert f.remediation, f"Finding {f.rule_id} missing remediation"

    @pytest.mark.asyncio
    async def test_all_findings_map_to_mcp02(self):
        """All findings should map to OWASP MCP02."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_PERMS_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = PermissionsScanner()
            findings = await scanner.scan(ctx)

            for f in findings:
                assert f.owasp_id == "MCP02", f"{f.rule_id} has wrong OWASP ID"


class TestEdgeCases:
    """Test scanner behavior with synthetic contexts."""

    @pytest.mark.asyncio
    async def test_no_tools_produces_no_findings(self):
        """Empty tool list should produce no findings."""
        ctx = ScanContext(tools=[])
        scanner = PermissionsScanner()
        findings = await scanner.scan(ctx)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_few_safe_tools_no_findings(self):
        """Small number of safe tools should produce minimal findings."""
        ctx = ScanContext(
            tools=[
                {"name": "ping", "description": "Check health", "inputSchema": {}},
                {"name": "version", "description": "Get version", "inputSchema": {}},
            ]
        )
        scanner = PermissionsScanner()
        findings = await scanner.scan(ctx)

        # No excessive count, no dangerous tools, no write ratio (too few)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_threshold_boundary(self):
        """Exactly at threshold should NOT trigger excessive tools finding."""
        tools = [
            {"name": f"tool_{i}", "description": "Safe tool", "inputSchema": {}}
            for i in range(_EXCESSIVE_TOOL_THRESHOLD)
        ]
        ctx = ScanContext(tools=tools)
        scanner = PermissionsScanner()
        findings = await scanner.scan(ctx)

        excessive = [f for f in findings if f.rule_id == "MCP02-001"]
        assert len(excessive) == 0, "At-threshold should not trigger"


# Import threshold for boundary test
from counteragent.scan.scanner.permissions import _EXCESSIVE_TOOL_THRESHOLD  # noqa: E402


class TestHelpers:
    """Test helper functions."""

    def test_classify_shell_tool(self):
        """Shell execution tools are classified correctly."""
        categories = _classify_tool_category(
            {"name": "run_command", "description": "Execute a shell command"}
        )
        labels = [c["label"] for c in categories]
        assert "Shell/Command Execution" in labels

    def test_classify_file_write_tool(self):
        """File write tools are classified correctly."""
        categories = _classify_tool_category(
            {"name": "write_file", "description": "Write content to a file"}
        )
        labels = [c["label"] for c in categories]
        assert "File System Write/Delete" in labels

    def test_classify_safe_tool(self):
        """Safe tools produce no category matches."""
        categories = _classify_tool_category(
            {"name": "ping", "description": "Check if server is alive"}
        )
        assert len(categories) == 0

    def test_classify_multiple_categories(self):
        """Tools matching multiple categories return all matches."""
        categories = _classify_tool_category(
            {"name": "execute_and_save", "description": "Execute query and write file"}
        )
        assert len(categories) >= 2

    def test_unconstrained_path_param(self):
        """Path parameters without constraints are flagged."""
        tool = {
            "name": "read_file",
            "description": "Read a file",
            "inputSchema": {
                "properties": {
                    "path": {"type": "string"},
                },
            },
        }
        issues = _check_param_constraints(tool)
        assert len(issues) == 1
        assert issues[0]["label"] == "file path"

    def test_constrained_param_not_flagged(self):
        """Parameters with enum constraints are not flagged."""
        tool = {
            "name": "read_file",
            "description": "Read a file",
            "inputSchema": {
                "properties": {
                    "path": {
                        "type": "string",
                        "enum": ["/etc/config.json", "/etc/settings.json"],
                    },
                },
            },
        }
        issues = _check_param_constraints(tool)
        assert len(issues) == 0

    def test_non_string_param_not_flagged(self):
        """Non-string parameters are not checked."""
        tool = {
            "name": "set_value",
            "description": "Set a value",
            "inputSchema": {
                "properties": {
                    "command_id": {"type": "integer"},
                },
            },
        }
        issues = _check_param_constraints(tool)
        assert len(issues) == 0

    def test_url_param_flagged(self):
        """URL parameters without constraints are flagged."""
        tool = {
            "name": "fetch",
            "description": "Fetch data",
            "inputSchema": {
                "properties": {
                    "url": {"type": "string"},
                },
            },
        }
        issues = _check_param_constraints(tool)
        assert len(issues) == 1
        assert issues[0]["label"] == "URL"
