"""Tests for the audit telemetry scanner (MCP08).

Tests the scanner against the vulnerable fixture server and
verifies detection of missing identification, error disclosure,
logging capability gaps, and sensitive data exposure.
"""

import sys

import pytest

from counteragent.audit.scanner.audit_telemetry import (
    AuditTelemetryScanner,
    _build_error_triggering_args,
    _check_error_disclosure,
    _check_sensitive_data,
)
from counteragent.core.connection import MCPConnection
from counteragent.core.discovery import enumerate_server
from counteragent.core.models import ScanContext

VULN_AUDIT_SERVER = "fixtures/vulnerable_servers/vuln_audit_telemetry.py"
PYTHON = sys.executable


class TestAuditTelemetryIntegration:
    """Integration tests against the fixture server."""

    @pytest.mark.asyncio
    async def test_detects_missing_logging(self):
        """Scanner flags absence of logging capability."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_AUDIT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = AuditTelemetryScanner()
            findings = await scanner.scan(ctx)

            logging_findings = [f for f in findings if f.rule_id == "MCP08-003"]
            assert len(logging_findings) >= 1, "Should detect missing logging"

    @pytest.mark.asyncio
    async def test_detects_error_disclosure(self):
        """Scanner finds information disclosure in error responses."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_AUDIT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = AuditTelemetryScanner()
            findings = await scanner.scan(ctx)

            disclosure_findings = [f for f in findings if f.rule_id == "MCP08-002"]
            assert len(disclosure_findings) >= 1, "Should detect error information disclosure"

    @pytest.mark.asyncio
    async def test_detects_sensitive_data_in_errors(self):
        """Scanner finds credentials and tokens in error messages."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_AUDIT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = AuditTelemetryScanner()
            findings = await scanner.scan(ctx)

            sensitive_findings = [f for f in findings if f.rule_id == "MCP08-004"]
            assert len(sensitive_findings) >= 1, "Should detect sensitive data in errors"

    @pytest.mark.asyncio
    async def test_clean_tools_no_error_findings(self):
        """Clean tools (ping, echo) should not trigger error findings."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_AUDIT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = AuditTelemetryScanner()
            findings = await scanner.scan(ctx)

            error_tool_findings = [
                f
                for f in findings
                if f.tool_name in ("ping", "echo") and f.rule_id in ("MCP08-002", "MCP08-004")
            ]
            assert len(error_tool_findings) == 0, (
                f"Clean tools should not trigger error findings: {error_tool_findings}"
            )

    @pytest.mark.asyncio
    async def test_all_findings_have_remediation(self):
        """Every finding includes remediation guidance."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_AUDIT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = AuditTelemetryScanner()
            findings = await scanner.scan(ctx)

            for f in findings:
                assert f.remediation, f"Finding {f.rule_id} missing remediation"

    @pytest.mark.asyncio
    async def test_produces_multiple_finding_types(self):
        """Scanner produces findings across multiple rule IDs."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_AUDIT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = AuditTelemetryScanner()
            findings = await scanner.scan(ctx)

            rule_ids = {f.rule_id for f in findings}
            assert len(rule_ids) >= 2, f"Expected at least 2 distinct rule IDs, got: {rule_ids}"


class TestSyntheticChecks:
    """Unit tests with synthetic data."""

    @pytest.mark.asyncio
    async def test_no_tools_returns_metadata_findings_only(self):
        """Empty tool list still checks server metadata."""
        ctx = ScanContext(
            tools=[],
            server_info={},
        )
        scanner = AuditTelemetryScanner()
        findings = await scanner.scan(ctx)

        # Should still find missing name, version, protocol, logging
        rule_ids = {f.rule_id for f in findings}
        assert "MCP08-001" in rule_ids, "Should flag missing identification"

    @pytest.mark.asyncio
    async def test_complete_server_info_no_id_findings(self):
        """Complete server_info should not trigger MCP08-001 or MCP08-005."""
        ctx = ScanContext(
            tools=[],
            server_info={
                "name": "test-server",
                "version": "1.0.0",
                "protocolVersion": "2025-03-26",
                "capabilities": {"logging": {}},
            },
        )
        scanner = AuditTelemetryScanner()
        findings = await scanner.scan(ctx)

        id_findings = [f for f in findings if f.rule_id in ("MCP08-001", "MCP08-005")]
        assert len(id_findings) == 0, f"Complete server info should not trigger: {id_findings}"

    @pytest.mark.asyncio
    async def test_logging_capability_suppresses_mcp08_003(self):
        """Server with logging capability should not trigger MCP08-003."""
        ctx = ScanContext(
            tools=[],
            server_info={"capabilities": {"logging": {}}},
        )
        scanner = AuditTelemetryScanner()
        findings = await scanner.scan(ctx)

        logging_findings = [f for f in findings if f.rule_id == "MCP08-003"]
        assert len(logging_findings) == 0

    @pytest.mark.asyncio
    async def test_log_resource_suppresses_mcp08_003(self):
        """Server with audit resource should not trigger MCP08-003."""
        ctx = ScanContext(
            tools=[],
            server_info={"capabilities": {}},
            resources=[{"name": "audit_log", "description": "Server audit log"}],
        )
        scanner = AuditTelemetryScanner()
        findings = await scanner.scan(ctx)

        logging_findings = [f for f in findings if f.rule_id == "MCP08-003"]
        assert len(logging_findings) == 0


class TestHelpers:
    """Unit tests for helper functions."""

    def test_error_disclosure_traceback(self):
        """Detects Python traceback in error text."""
        text = 'Traceback (most recent call last):\n  File "app.py", line 10'
        results = _check_error_disclosure(text)
        assert len(results) >= 1
        assert any("traceback" in r["pattern"].lower() for r in results)

    def test_error_disclosure_windows_path(self):
        """Detects Windows file paths."""
        text = r"Config not found at C:\Users\admin\config.yaml"
        results = _check_error_disclosure(text)
        assert len(results) >= 1

    def test_error_disclosure_unix_path(self):
        """Detects Unix file paths."""
        text = "Error reading /home/user/app/config.py"
        results = _check_error_disclosure(text)
        assert len(results) >= 1

    def test_error_disclosure_sql(self):
        """Detects SQL query fragments."""
        text = "Error: SELECT * FROM users WHERE id = '1'"
        results = _check_error_disclosure(text)
        assert len(results) >= 1

    def test_error_disclosure_clean(self):
        """Clean error message produces no findings."""
        text = "Invalid input: please provide a valid query string"
        results = _check_error_disclosure(text)
        assert results == []

    def test_sensitive_data_bearer_token(self):
        """Detects Bearer tokens."""
        text = "Auth failed: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        results = _check_sensitive_data(text)
        assert len(results) >= 1

    def test_sensitive_data_email(self):
        """Detects email addresses."""
        text = "Contact admin@internal.company.com for help"
        results = _check_sensitive_data(text)
        assert len(results) >= 1

    def test_sensitive_data_ip(self):
        """Detects IP addresses."""
        text = "Server at 192.168.1.100 is unreachable"
        results = _check_sensitive_data(text)
        assert len(results) >= 1

    def test_sensitive_data_clean(self):
        """Clean message produces no findings."""
        text = "Operation completed successfully"
        results = _check_sensitive_data(text)
        assert results == []

    def test_build_error_args_string(self):
        """Builds long string for string params."""
        tool = {
            "name": "test",
            "inputSchema": {
                "properties": {"query": {"type": "string"}},
            },
        }
        args = _build_error_triggering_args(tool)
        assert "query" in args
        assert len(args["query"]) == 10000

    def test_build_error_args_number(self):
        """Sends string for number params (type mismatch)."""
        tool = {
            "name": "test",
            "inputSchema": {
                "properties": {"count": {"type": "integer"}},
            },
        }
        args = _build_error_triggering_args(tool)
        assert args["count"] == "not_a_number"

    def test_build_error_args_empty_schema(self):
        """Empty schema produces empty args."""
        tool = {"name": "test", "inputSchema": {}}
        args = _build_error_triggering_args(tool)
        assert args == {}
