"""Tests for the shadow servers scanner (MCP09).

Tests the scanner against the vulnerable fixture server and verifies
detection of development indicators, known dev tools, debug tool
exposure, governance gaps, and ephemeral deployment markers.
"""

import sys

import pytest

from counteragent.audit.scanner.shadow_servers import (
    ShadowServersScanner,
    _has_dev_description,
    _has_dev_indicator,
    _has_ephemeral_markers,
    _is_debug_tool,
    _match_known_dev_tool,
)
from counteragent.core.connection import MCPConnection
from counteragent.core.discovery import enumerate_server
from counteragent.core.models import ScanContext, Severity

VULN_SHADOW_SERVER = "fixtures/vulnerable_servers/vuln_shadow_servers.py"
PYTHON = sys.executable


class TestShadowServersIntegration:
    """Integration tests against the fixture server."""

    @pytest.mark.asyncio
    async def test_detects_dev_indicator_in_name(self):
        """Fixture server name contains 'test' — triggers MCP09-001."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_SHADOW_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ShadowServersScanner()
            findings = await scanner.scan(ctx)

            dev_findings = [
                f
                for f in findings
                if f.rule_id == "MCP09-001" and f.metadata.get("field") == "name"
            ]
            assert len(dev_findings) >= 1, "Should detect 'test' in server name"

    @pytest.mark.asyncio
    async def test_detects_dev_indicator_in_version(self):
        """Fixture server version '0.0.1-dev' triggers MCP09-001."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_SHADOW_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ShadowServersScanner()
            findings = await scanner.scan(ctx)

            version_findings = [
                f
                for f in findings
                if f.rule_id == "MCP09-001" and f.metadata.get("field") == "version"
            ]
            assert len(version_findings) >= 1, "Should detect 'dev' in version"

    @pytest.mark.asyncio
    async def test_detects_debug_tools(self):
        """Fixture server has debug/test tools — triggers MCP09-003."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_SHADOW_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ShadowServersScanner()
            findings = await scanner.scan(ctx)

            debug_findings = [f for f in findings if f.rule_id == "MCP09-003"]
            assert len(debug_findings) >= 1, "Should detect debug/test tools"
            tool_names = {f.tool_name for f in debug_findings if f.tool_name}
            assert "debug_dump_state" in tool_names or "test_echo" in tool_names

    @pytest.mark.asyncio
    async def test_detects_multiple_debug_tools_summary(self):
        """3+ debug/test tools trigger MEDIUM summary finding."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_SHADOW_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ShadowServersScanner()
            findings = await scanner.scan(ctx)

            summary_findings = [
                f for f in findings if f.rule_id == "MCP09-003" and "Multiple" in f.title
            ]
            assert len(summary_findings) == 1
            assert summary_findings[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_detects_governance_gap(self):
        """Fixture has no description + 7 tools — triggers MCP09-004."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_SHADOW_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ShadowServersScanner()
            findings = await scanner.scan(ctx)

            gov_findings = [f for f in findings if f.rule_id == "MCP09-004"]
            assert len(gov_findings) == 1
            assert gov_findings[0].severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_detects_ephemeral_markers(self):
        """Fixture version '0.0.1-dev' triggers MCP09-005."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_SHADOW_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ShadowServersScanner()
            findings = await scanner.scan(ctx)

            eph_findings = [f for f in findings if f.rule_id == "MCP09-005"]
            assert len(eph_findings) >= 1

    @pytest.mark.asyncio
    async def test_all_findings_have_remediation(self):
        """Every finding includes remediation guidance."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_SHADOW_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ShadowServersScanner()
            findings = await scanner.scan(ctx)

            for f in findings:
                assert f.remediation, f"Finding {f.rule_id} missing remediation"


class TestDevIndicators:
    """Synthetic tests for MCP09-001: Development server indicators."""

    @pytest.mark.asyncio
    async def test_dev_in_name(self):
        """Server named 'my-dev-server' triggers MCP09-001."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "my-dev-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_findings = [f for f in findings if f.rule_id == "MCP09-001"]
        assert len(dev_findings) >= 1
        assert any(f.metadata.get("matched_pattern") == "dev" for f in dev_findings)

    @pytest.mark.asyncio
    async def test_staging_in_name(self):
        """Server named 'staging-api' triggers MCP09-001."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "staging-api", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_findings = [f for f in findings if f.rule_id == "MCP09-001"]
        assert len(dev_findings) >= 1

    @pytest.mark.asyncio
    async def test_production_name_no_finding(self):
        """Server named 'production-api' does not trigger MCP09-001."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "production-api", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_findings = [f for f in findings if f.rule_id == "MCP09-001"]
        assert len(dev_findings) == 0

    @pytest.mark.asyncio
    async def test_myapp_name_no_finding(self):
        """Server named 'MyApp' does not trigger MCP09-001."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "MyApp", "version": "2.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_findings = [f for f in findings if f.rule_id == "MCP09-001"]
        assert len(dev_findings) == 0

    @pytest.mark.asyncio
    async def test_case_insensitive_debug(self):
        """'DEBUG-Server' triggers MCP09-001 (case-insensitive)."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "DEBUG-Server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_findings = [f for f in findings if f.rule_id == "MCP09-001"]
        assert len(dev_findings) >= 1

    @pytest.mark.asyncio
    async def test_test_in_name(self):
        """Server named 'test-api' triggers MCP09-001."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "test-api", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_findings = [f for f in findings if f.rule_id == "MCP09-001"]
        assert len(dev_findings) >= 1

    @pytest.mark.asyncio
    async def test_example_in_name(self):
        """Server named 'example-server' triggers MCP09-001."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "example-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_findings = [f for f in findings if f.rule_id == "MCP09-001"]
        assert len(dev_findings) >= 1

    @pytest.mark.asyncio
    async def test_demo_in_name(self):
        """Server named 'demo-mcp' triggers MCP09-001."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "demo-mcp", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_findings = [f for f in findings if f.rule_id == "MCP09-001"]
        assert len(dev_findings) >= 1

    @pytest.mark.asyncio
    async def test_localhost_in_name(self):
        """Server named 'localhost-server' triggers MCP09-001."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "localhost-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_findings = [f for f in findings if f.rule_id == "MCP09-001"]
        assert len(dev_findings) >= 1

    @pytest.mark.asyncio
    async def test_prototype_in_name(self):
        """Server named 'prototype-v2' triggers MCP09-001."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "prototype-v2", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_findings = [f for f in findings if f.rule_id == "MCP09-001"]
        assert len(dev_findings) >= 1

    @pytest.mark.asyncio
    async def test_experimental_in_name(self):
        """Server named 'experimental-api' triggers MCP09-001."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "experimental-api", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_findings = [f for f in findings if f.rule_id == "MCP09-001"]
        assert len(dev_findings) >= 1

    @pytest.mark.asyncio
    async def test_tmp_in_name(self):
        """Server named 'tmp-service' triggers MCP09-001."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "tmp-service", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_findings = [f for f in findings if f.rule_id == "MCP09-001"]
        assert len(dev_findings) >= 1

    @pytest.mark.asyncio
    async def test_dev_in_version_only(self):
        """Dev indicator in version but not name triggers MCP09-001."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "my-api", "version": "1.0.0-dev"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_findings = [f for f in findings if f.rule_id == "MCP09-001"]
        assert len(dev_findings) >= 1
        assert any(f.metadata.get("field") == "version" for f in dev_findings)

    @pytest.mark.asyncio
    async def test_severity_is_low(self):
        """MCP09-001 findings have LOW severity."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "dev-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_findings = [f for f in findings if f.rule_id == "MCP09-001"]
        assert all(f.severity == Severity.LOW for f in dev_findings)


class TestKnownDevTools:
    """Synthetic tests for MCP09-002: Known development tool fingerprint."""

    @pytest.mark.asyncio
    async def test_mcp_inspector(self):
        """Server named 'MCP Inspector' triggers MCP09-002."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "MCP Inspector", "version": "0.13.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_tool_findings = [f for f in findings if f.rule_id == "MCP09-002"]
        assert len(dev_tool_findings) >= 1
        assert dev_tool_findings[0].severity in (Severity.MEDIUM, Severity.HIGH)

    @pytest.mark.asyncio
    async def test_mcp_server_template(self):
        """Server named 'mcp-server-template' triggers MCP09-002."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "mcp-server-template", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_tool_findings = [f for f in findings if f.rule_id == "MCP09-002"]
        assert len(dev_tool_findings) >= 1

    @pytest.mark.asyncio
    async def test_hello_world_mcp(self):
        """Server named 'hello-world-mcp' triggers MCP09-002."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "hello-world-mcp", "version": "0.1.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_tool_findings = [f for f in findings if f.rule_id == "MCP09-002"]
        assert len(dev_tool_findings) >= 1

    @pytest.mark.asyncio
    async def test_company_api_no_finding(self):
        """Server named 'my-company-api' does not trigger MCP09-002."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "my-company-api", "version": "2.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_tool_findings = [f for f in findings if f.rule_id == "MCP09-002"]
        assert len(dev_tool_findings) == 0

    @pytest.mark.asyncio
    async def test_fastmcp_dev_version(self):
        """FastMCP with dev version triggers MCP09-002."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "FastMCP Server", "version": "0.5.0-dev"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_tool_findings = [f for f in findings if f.rule_id == "MCP09-002"]
        assert len(dev_tool_findings) >= 1

    @pytest.mark.asyncio
    async def test_fastmcp_zero_x_version(self):
        """FastMCP with 0.x version triggers MCP09-002."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "FastMCP", "version": "0.9.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_tool_findings = [f for f in findings if f.rule_id == "MCP09-002"]
        assert len(dev_tool_findings) >= 1

    @pytest.mark.asyncio
    async def test_fastmcp_stable_no_finding(self):
        """FastMCP with stable version does not trigger MCP09-002."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "FastMCP", "version": "2.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_tool_findings = [f for f in findings if f.rule_id == "MCP09-002"]
        assert len(dev_tool_findings) == 0

    @pytest.mark.asyncio
    async def test_create_mcp_server(self):
        """Server named 'create-mcp-server' triggers MCP09-002."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "create-mcp-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_tool_findings = [f for f in findings if f.rule_id == "MCP09-002"]
        assert len(dev_tool_findings) >= 1

    @pytest.mark.asyncio
    async def test_quickstart_server(self):
        """Server named 'mcp-quickstart' triggers MCP09-002."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "mcp-quickstart", "version": "0.1.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_tool_findings = [f for f in findings if f.rule_id == "MCP09-002"]
        assert len(dev_tool_findings) >= 1

    @pytest.mark.asyncio
    async def test_getting_started_server(self):
        """Server with 'getting-started' triggers MCP09-002."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "mcp-getting-started", "version": "0.1.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_tool_findings = [f for f in findings if f.rule_id == "MCP09-002"]
        assert len(dev_tool_findings) >= 1

    @pytest.mark.asyncio
    async def test_empty_name_no_finding(self):
        """Empty server name does not trigger MCP09-002."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "", "version": "0.13.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        dev_tool_findings = [f for f in findings if f.rule_id == "MCP09-002"]
        assert len(dev_tool_findings) == 0


class TestDebugTools:
    """Synthetic tests for MCP09-003: Debug/test tool exposure."""

    @pytest.mark.asyncio
    async def test_debug_prefix(self):
        """Tool with debug_ prefix triggers MCP09-003."""
        ctx = ScanContext(
            tools=[{"name": "debug_dump", "description": ""}],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        debug_findings = [
            f for f in findings if f.rule_id == "MCP09-003" and f.tool_name == "debug_dump"
        ]
        assert len(debug_findings) >= 1

    @pytest.mark.asyncio
    async def test_test_prefix(self):
        """Tool with test_ prefix triggers MCP09-003."""
        ctx = ScanContext(
            tools=[{"name": "test_connection", "description": ""}],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        debug_findings = [
            f for f in findings if f.rule_id == "MCP09-003" and f.tool_name == "test_connection"
        ]
        assert len(debug_findings) >= 1

    @pytest.mark.asyncio
    async def test_dump_prefix(self):
        """Tool with dump_ prefix triggers MCP09-003."""
        ctx = ScanContext(
            tools=[{"name": "dump_state", "description": ""}],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        debug_findings = [
            f for f in findings if f.rule_id == "MCP09-003" and f.tool_name == "dump_state"
        ]
        assert len(debug_findings) >= 1

    @pytest.mark.asyncio
    async def test_mock_prefix(self):
        """Tool with mock_ prefix triggers MCP09-003."""
        ctx = ScanContext(
            tools=[{"name": "mock_api", "description": ""}],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        debug_findings = [
            f for f in findings if f.rule_id == "MCP09-003" and f.tool_name == "mock_api"
        ]
        assert len(debug_findings) >= 1

    @pytest.mark.asyncio
    async def test_tmp_prefix(self):
        """Tool with tmp_ prefix triggers MCP09-003."""
        ctx = ScanContext(
            tools=[{"name": "tmp_util", "description": ""}],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        debug_findings = [
            f for f in findings if f.rule_id == "MCP09-003" and f.tool_name == "tmp_util"
        ]
        assert len(debug_findings) >= 1

    @pytest.mark.asyncio
    async def test_healthcheck_alone_no_finding(self):
        """Single 'healthcheck' tool alone does not trigger individual finding."""
        ctx = ScanContext(
            tools=[{"name": "healthcheck", "description": "Check server health"}],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        # Should not produce individual tool finding (exact name alone)
        individual_findings = [
            f for f in findings if f.rule_id == "MCP09-003" and f.tool_name == "healthcheck"
        ]
        assert len(individual_findings) == 0

    @pytest.mark.asyncio
    async def test_three_debug_tools_summary(self):
        """3+ debug tools produce MEDIUM summary finding."""
        ctx = ScanContext(
            tools=[
                {"name": "debug_a", "description": ""},
                {"name": "test_b", "description": ""},
                {"name": "dump_c", "description": ""},
            ],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        summary = [f for f in findings if f.rule_id == "MCP09-003" and "Multiple" in f.title]
        assert len(summary) == 1
        assert summary[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_description_not_for_production(self):
        """Tool description with 'not for production' triggers MCP09-003."""
        ctx = ScanContext(
            tools=[
                {
                    "name": "admin_panel",
                    "description": "Admin panel - not for production use",
                }
            ],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        debug_findings = [
            f for f in findings if f.rule_id == "MCP09-003" and f.tool_name == "admin_panel"
        ]
        assert len(debug_findings) >= 1

    @pytest.mark.asyncio
    async def test_description_testing_only(self):
        """Tool description with 'testing only' triggers MCP09-003."""
        ctx = ScanContext(
            tools=[
                {
                    "name": "validate",
                    "description": "Validate input - for testing only",
                }
            ],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        debug_findings = [
            f for f in findings if f.rule_id == "MCP09-003" and f.tool_name == "validate"
        ]
        assert len(debug_findings) >= 1

    @pytest.mark.asyncio
    async def test_normal_tools_no_finding(self):
        """Normal tools do not trigger MCP09-003."""
        ctx = ScanContext(
            tools=[
                {"name": "get_data", "description": "Retrieve data from API"},
                {"name": "process", "description": "Process request"},
            ],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        debug_findings = [f for f in findings if f.rule_id == "MCP09-003"]
        assert len(debug_findings) == 0

    @pytest.mark.asyncio
    async def test_inspect_prefix(self):
        """Tool with inspect_ prefix triggers MCP09-003."""
        ctx = ScanContext(
            tools=[{"name": "inspect_vars", "description": ""}],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        debug_findings = [
            f for f in findings if f.rule_id == "MCP09-003" and f.tool_name == "inspect_vars"
        ]
        assert len(debug_findings) >= 1

    @pytest.mark.asyncio
    async def test_internal_prefix(self):
        """Tool with __internal_ prefix triggers MCP09-003."""
        ctx = ScanContext(
            tools=[{"name": "__internal_reset", "description": ""}],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        debug_findings = [
            f for f in findings if f.rule_id == "MCP09-003" and f.tool_name == "__internal_reset"
        ]
        assert len(debug_findings) >= 1

    @pytest.mark.asyncio
    async def test_description_internal_use(self):
        """Tool description with 'internal use' triggers MCP09-003."""
        ctx = ScanContext(
            tools=[
                {
                    "name": "reset_cache",
                    "description": "Reset cache - internal use only",
                }
            ],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        debug_findings = [
            f for f in findings if f.rule_id == "MCP09-003" and f.tool_name == "reset_cache"
        ]
        assert len(debug_findings) >= 1

    @pytest.mark.asyncio
    async def test_two_debug_tools_no_summary(self):
        """2 debug tools do not produce summary finding."""
        ctx = ScanContext(
            tools=[
                {"name": "debug_a", "description": ""},
                {"name": "test_b", "description": ""},
            ],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        summary = [f for f in findings if f.rule_id == "MCP09-003" and "Multiple" in f.title]
        assert len(summary) == 0


class TestGovernanceGap:
    """Synthetic tests for MCP09-004: Governance metadata gap."""

    @pytest.mark.asyncio
    async def test_no_description_five_tools(self):
        """No description + 5 tools triggers MCP09-004."""
        ctx = ScanContext(
            tools=[{"name": f"tool_{i}"} for i in range(5)],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        gov_findings = [f for f in findings if f.rule_id == "MCP09-004"]
        assert len(gov_findings) == 1

    @pytest.mark.asyncio
    async def test_no_description_three_tools_no_finding(self):
        """No description + 3 tools (below threshold) does not trigger."""
        ctx = ScanContext(
            tools=[{"name": f"tool_{i}"} for i in range(3)],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        gov_findings = [f for f in findings if f.rule_id == "MCP09-004"]
        assert len(gov_findings) == 0

    @pytest.mark.asyncio
    async def test_has_description_many_tools_no_finding(self):
        """Has description + 10 tools does not trigger."""
        ctx = ScanContext(
            tools=[{"name": f"tool_{i}"} for i in range(10)],
            server_info={
                "name": "my-server",
                "version": "1.0.0",
                "description": "Production API server",
            },
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        gov_findings = [f for f in findings if f.rule_id == "MCP09-004"]
        assert len(gov_findings) == 0

    @pytest.mark.asyncio
    async def test_no_server_name_no_finding(self):
        """No server name skips MCP09-004 (MCP08's territory)."""
        ctx = ScanContext(
            tools=[{"name": f"tool_{i}"} for i in range(10)],
            server_info={"name": "", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        gov_findings = [f for f in findings if f.rule_id == "MCP09-004"]
        assert len(gov_findings) == 0

    @pytest.mark.asyncio
    async def test_empty_description_triggers(self):
        """Empty string description + 5 tools triggers MCP09-004."""
        ctx = ScanContext(
            tools=[{"name": f"tool_{i}"} for i in range(5)],
            server_info={
                "name": "my-server",
                "version": "1.0.0",
                "description": "",
            },
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        gov_findings = [f for f in findings if f.rule_id == "MCP09-004"]
        assert len(gov_findings) == 1

    @pytest.mark.asyncio
    async def test_four_tools_no_finding(self):
        """No description + 4 tools (below threshold) does not trigger."""
        ctx = ScanContext(
            tools=[{"name": f"tool_{i}"} for i in range(4)],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        gov_findings = [f for f in findings if f.rule_id == "MCP09-004"]
        assert len(gov_findings) == 0


class TestEphemeralMarkers:
    """Synthetic tests for MCP09-005: Ephemeral deployment markers."""

    @pytest.mark.asyncio
    async def test_uuid_server_name(self):
        """UUID server name triggers MCP09-005."""
        ctx = ScanContext(
            tools=[],
            server_info={
                "name": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "version": "1.0.0",
            },
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        eph_findings = [f for f in findings if f.rule_id == "MCP09-005"]
        assert len(eph_findings) >= 1

    @pytest.mark.asyncio
    async def test_pure_hex_name(self):
        """Pure hex name (12+ chars) triggers MCP09-005."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "abc123def456", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        eph_findings = [f for f in findings if f.rule_id == "MCP09-005"]
        assert len(eph_findings) >= 1

    @pytest.mark.asyncio
    async def test_version_zero_zero_zero(self):
        """Version '0.0.0' triggers MCP09-005."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "my-server", "version": "0.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        eph_findings = [f for f in findings if f.rule_id == "MCP09-005"]
        assert len(eph_findings) >= 1

    @pytest.mark.asyncio
    async def test_snapshot_version(self):
        """Version '0.1.0-SNAPSHOT' triggers MCP09-005."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "my-server", "version": "0.1.0-SNAPSHOT"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        eph_findings = [f for f in findings if f.rule_id == "MCP09-005"]
        assert len(eph_findings) >= 1

    @pytest.mark.asyncio
    async def test_normal_name_no_finding(self):
        """Normal name 'my-api-server' does not trigger MCP09-005."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "my-api-server", "version": "2.1.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        eph_findings = [f for f in findings if f.rule_id == "MCP09-005"]
        assert len(eph_findings) == 0

    @pytest.mark.asyncio
    async def test_timestamp_name(self):
        """Timestamp-like name (10+ digits) triggers MCP09-005."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "1708617600000", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        eph_findings = [f for f in findings if f.rule_id == "MCP09-005"]
        assert len(eph_findings) >= 1

    @pytest.mark.asyncio
    async def test_container_prefix(self):
        """Container-prefixed name triggers MCP09-005."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "container-abc123", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        eph_findings = [f for f in findings if f.rule_id == "MCP09-005"]
        assert len(eph_findings) >= 1

    @pytest.mark.asyncio
    async def test_canary_version(self):
        """Version with 'canary' triggers MCP09-005."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "my-server", "version": "1.0.0-canary"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        eph_findings = [f for f in findings if f.rule_id == "MCP09-005"]
        assert len(eph_findings) >= 1

    @pytest.mark.asyncio
    async def test_alpha0_version(self):
        """Version with 'alpha0' triggers MCP09-005."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "my-server", "version": "2.0.0-alpha0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        eph_findings = [f for f in findings if f.rule_id == "MCP09-005"]
        assert len(eph_findings) >= 1

    @pytest.mark.asyncio
    async def test_dev_prerelease_version(self):
        """Version '0.1.0-dev' triggers MCP09-005."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "my-server", "version": "0.1.0-dev"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        eph_findings = [f for f in findings if f.rule_id == "MCP09-005"]
        assert len(eph_findings) >= 1

    @pytest.mark.asyncio
    async def test_severity_is_info(self):
        """MCP09-005 findings have INFORMATIONAL severity."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "abc123def456", "version": "1.0.0"},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        eph_findings = [f for f in findings if f.rule_id == "MCP09-005"]
        assert all(f.severity == Severity.INFO for f in eph_findings)

    @pytest.mark.asyncio
    async def test_empty_name_and_version_no_finding(self):
        """Empty name and version does not trigger MCP09-005."""
        ctx = ScanContext(
            tools=[],
            server_info={"name": "", "version": ""},
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        eph_findings = [f for f in findings if f.rule_id == "MCP09-005"]
        assert len(eph_findings) == 0

    @pytest.mark.asyncio
    async def test_continuous_hex_32_chars(self):
        """32 continuous hex chars (UUID without dashes) triggers MCP09-005."""
        ctx = ScanContext(
            tools=[],
            server_info={
                "name": "a1b2c3d4e5f67890abcdef1234567890",
                "version": "1.0.0",
            },
        )
        scanner = ShadowServersScanner()
        findings = await scanner.scan(ctx)

        eph_findings = [f for f in findings if f.rule_id == "MCP09-005"]
        assert len(eph_findings) >= 1


class TestHelpers:
    """Unit tests for helper functions."""

    def test_has_dev_indicator_dev(self):
        """'dev' matched in server name."""
        assert _has_dev_indicator("my-dev-server") == "dev"

    def test_has_dev_indicator_staging(self):
        """'staging' matched in server name."""
        assert _has_dev_indicator("staging-api") == "staging"

    def test_has_dev_indicator_none(self):
        """No match returns None."""
        assert _has_dev_indicator("production-api") is None

    def test_has_dev_indicator_case_insensitive(self):
        """Case-insensitive matching."""
        assert _has_dev_indicator("DEBUG-Server") == "debug"

    def test_has_dev_indicator_temp(self):
        """'temp' matched."""
        assert _has_dev_indicator("temp-worker") == "temp"

    def test_match_known_dev_tool_inspector(self):
        """MCP Inspector matched."""
        result = _match_known_dev_tool("MCP Inspector", "0.13.0")
        assert result is not None
        assert "inspector" in result["name_pattern"]

    def test_match_known_dev_tool_none(self):
        """Non-dev tool returns None."""
        assert _match_known_dev_tool("my-api", "1.0.0") is None

    def test_match_known_dev_tool_fastmcp_dev(self):
        """FastMCP with dev version matched."""
        result = _match_known_dev_tool("FastMCP Server", "0.5.0-dev")
        assert result is not None

    def test_match_known_dev_tool_fastmcp_stable(self):
        """FastMCP with stable version not matched."""
        assert _match_known_dev_tool("FastMCP", "2.0.0") is None

    def test_is_debug_tool_prefix(self):
        """debug_ prefix detected."""
        assert _is_debug_tool("debug_dump") is True

    def test_is_debug_tool_normal(self):
        """Normal tool not flagged."""
        assert _is_debug_tool("get_data") is False

    def test_is_debug_tool_test_prefix(self):
        """test_ prefix detected."""
        assert _is_debug_tool("test_echo") is True

    def test_has_dev_description_match(self):
        """Development phrase detected."""
        assert _has_dev_description("for development only") is not None

    def test_has_dev_description_none(self):
        """Normal description not flagged."""
        assert _has_dev_description("Process incoming requests") is None

    def test_has_dev_description_debug(self):
        """'debug purposes' detected."""
        assert _has_dev_description("Used for debug purposes") == "debug purposes"

    def test_has_ephemeral_markers_uuid(self):
        """UUID detected in name."""
        markers = _has_ephemeral_markers("a1b2c3d4-e5f6-7890-abcd-ef1234567890", "1.0.0")
        assert len(markers) >= 1
        assert any("UUID" in m for m in markers)

    def test_has_ephemeral_markers_docker_hex(self):
        """Docker hex hostname detected."""
        markers = _has_ephemeral_markers("abc123def456ab", "1.0.0")
        assert len(markers) >= 1

    def test_has_ephemeral_markers_snapshot(self):
        """SNAPSHOT version detected."""
        markers = _has_ephemeral_markers("server", "1.0.0-SNAPSHOT")
        assert len(markers) >= 1
        assert any("Snapshot" in m for m in markers)

    def test_has_ephemeral_markers_none(self):
        """Normal name and version produce no markers."""
        markers = _has_ephemeral_markers("my-api-server", "2.1.0")
        assert len(markers) == 0

    def test_has_ephemeral_markers_zero_version(self):
        """Version 0.0.0 detected as ephemeral."""
        markers = _has_ephemeral_markers("server", "0.0.0")
        assert len(markers) >= 1
