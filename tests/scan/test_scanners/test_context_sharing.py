"""Tests for the context sharing scanner (MCP10).

Tests the scanner against the vulnerable fixture server and
verifies detection of excessive context, session data leakage,
error context leakage, resource over-exposure, and sensitive
data in resources.
"""

import sys

import pytest

from counteragent.core.connection import MCPConnection
from counteragent.core.discovery import enumerate_server
from counteragent.core.models import ScanContext, Severity
from counteragent.scan.scanner.context_sharing import (
    ContextSharingScanner,
    _build_error_args,
    _build_minimal_args,
    _check_resource_scoping,
    _compute_response_ratio,
    _find_sensitive_in_resource,
    _find_session_data,
)

VULN_CONTEXT_SERVER = "fixtures/vulnerable_servers/vuln_context.py"
PYTHON = sys.executable


class TestContextSharingIntegration:
    """Integration tests against the fixture server."""

    @pytest.mark.asyncio
    async def test_detects_excessive_context(self):
        """Scanner flags tools that return disproportionate data."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_CONTEXT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ContextSharingScanner()
            findings = await scanner.scan(ctx)

            excessive_findings = [f for f in findings if f.rule_id == "MCP10-001"]
            assert len(excessive_findings) >= 1, "Should detect excessive context in response"

    @pytest.mark.asyncio
    async def test_detects_session_data_in_response(self):
        """Scanner flags session IDs and internal state in tool responses."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_CONTEXT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ContextSharingScanner()
            findings = await scanner.scan(ctx)

            session_findings = [f for f in findings if f.rule_id == "MCP10-002"]
            assert len(session_findings) >= 1, "Should detect session data in response"

    @pytest.mark.asyncio
    async def test_detects_error_context_leakage(self):
        """Scanner flags context leaked in error responses."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_CONTEXT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ContextSharingScanner()
            findings = await scanner.scan(ctx)

            error_findings = [f for f in findings if f.rule_id == "MCP10-003"]
            assert len(error_findings) >= 1, "Should detect context leakage in errors"

    @pytest.mark.asyncio
    async def test_detects_resource_over_exposure(self):
        """Scanner flags resources with no user/session scoping."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_CONTEXT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ContextSharingScanner()
            findings = await scanner.scan(ctx)

            scoping_findings = [f for f in findings if f.rule_id == "MCP10-004"]
            assert len(scoping_findings) >= 1, "Should detect unscoped resources"

    @pytest.mark.asyncio
    async def test_detects_sensitive_data_in_resources(self):
        """Scanner flags credentials and PII in resource content."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_CONTEXT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ContextSharingScanner()
            findings = await scanner.scan(ctx)

            sensitive_findings = [f for f in findings if f.rule_id == "MCP10-005"]
            assert len(sensitive_findings) >= 1, "Should detect sensitive data in resources"

    @pytest.mark.asyncio
    async def test_sensitive_resource_findings_have_high_severity(self):
        """Credential findings in resources are escalated to HIGH severity."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_CONTEXT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ContextSharingScanner()
            findings = await scanner.scan(ctx)

            sensitive_findings = [f for f in findings if f.rule_id == "MCP10-005"]
            high_findings = [f for f in sensitive_findings if f.severity == Severity.HIGH]
            assert len(high_findings) >= 1, (
                "Credential leakage in resources should be HIGH severity"
            )

    @pytest.mark.asyncio
    async def test_clean_tools_no_findings(self):
        """Clean tools (ping, echo) should not trigger findings."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_CONTEXT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ContextSharingScanner()
            findings = await scanner.scan(ctx)

            clean_tool_findings = [f for f in findings if f.tool_name in ("ping", "echo")]
            assert len(clean_tool_findings) == 0, (
                f"Clean tools should not trigger findings: {clean_tool_findings}"
            )

    @pytest.mark.asyncio
    async def test_all_findings_have_remediation(self):
        """Every finding includes remediation guidance."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_CONTEXT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ContextSharingScanner()
            findings = await scanner.scan(ctx)

            for f in findings:
                assert f.remediation, f"Finding {f.rule_id} missing remediation"

    @pytest.mark.asyncio
    async def test_produces_multiple_finding_types(self):
        """Scanner produces findings across multiple rule IDs."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_CONTEXT_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = ContextSharingScanner()
            findings = await scanner.scan(ctx)

            rule_ids = {f.rule_id for f in findings}
            assert len(rule_ids) >= 3, f"Expected at least 3 distinct rule IDs, got: {rule_ids}"


class TestSyntheticChecks:
    """Unit tests with synthetic data."""

    @pytest.mark.asyncio
    async def test_no_tools_no_resources_returns_empty(self):
        """Empty tool and resource lists produce no findings."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={},
        )
        scanner = ContextSharingScanner()
        findings = await scanner.scan(ctx)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_unscoped_resources_detected(self):
        """Resources without scoping keywords are flagged."""
        ctx = ScanContext(
            tools=[],
            resources=[
                {
                    "uri": "config://global/settings",
                    "name": "settings",
                    "description": "App config",
                },
            ],
            server_info={},
        )
        scanner = ContextSharingScanner()
        findings = await scanner.scan(ctx)

        scoping_findings = [f for f in findings if f.rule_id == "MCP10-004"]
        assert len(scoping_findings) == 1

    @pytest.mark.asyncio
    async def test_scoped_resources_not_flagged(self):
        """Resources with user/session scoping are not flagged."""
        ctx = ScanContext(
            tools=[],
            resources=[
                {
                    "uri": "data://user/123/profile",
                    "name": "user_profile",
                    "description": "User profile data",
                },
            ],
            server_info={},
        )
        scanner = ContextSharingScanner()
        findings = await scanner.scan(ctx)

        scoping_findings = [f for f in findings if f.rule_id == "MCP10-004"]
        assert len(scoping_findings) == 0

    @pytest.mark.asyncio
    async def test_mixed_resources_partial_findings(self):
        """Only unscoped resources trigger MCP10-004."""
        ctx = ScanContext(
            tools=[],
            resources=[
                {"uri": "config://global", "name": "global_config", "description": "All settings"},
                {
                    "uri": "data://user/profile",
                    "name": "user_data",
                    "description": "Per-user data scoped to session",
                },
            ],
            server_info={},
        )
        scanner = ContextSharingScanner()
        findings = await scanner.scan(ctx)

        scoping_findings = [f for f in findings if f.rule_id == "MCP10-004"]
        assert len(scoping_findings) == 1
        assert "global_config" in scoping_findings[0].title


class TestHelpers:
    """Unit tests for helper functions."""

    def test_find_session_data_session_id(self):
        """Detects session_id in text."""
        text = "Response: session_id=abc123 data=ok"
        results = _find_session_data(text)
        assert len(results) >= 1
        assert any("Session ID" in r["pattern"] for r in results)

    def test_find_session_data_request_id(self):
        """Detects request_id in text."""
        text = "request_id=req-2024-001"
        results = _find_session_data(text)
        assert len(results) >= 1
        assert any("Request ID" in r["pattern"] for r in results)

    def test_find_session_data_trace_id(self):
        """Detects trace_id in text."""
        text = "trace_id=trace-deadbeef"
        results = _find_session_data(text)
        assert len(results) >= 1

    def test_find_session_data_clean(self):
        """Clean text produces no session data findings."""
        text = "Operation completed successfully. Result: 42"
        results = _find_session_data(text)
        assert results == []

    def test_find_sensitive_password(self):
        """Detects password in resource content."""
        text = "password=SuperSecret123"
        results = _find_sensitive_in_resource(text)
        assert len(results) >= 1
        assert any("Password" in r["pattern"] for r in results)

    def test_find_sensitive_api_key(self):
        """Detects API key pattern."""
        text = "api_key=sk-prod-a1b2c3d4e5f6g7h8i9j0"  # gitleaks:allow
        results = _find_sensitive_in_resource(text)
        assert len(results) >= 1

    def test_find_sensitive_email(self):
        """Detects email addresses."""
        text = "Contact admin@internal.corp for support"
        results = _find_sensitive_in_resource(text)
        assert len(results) >= 1
        assert any("Email" in r["pattern"] for r in results)

    def test_find_sensitive_ssn(self):
        """Detects SSN patterns."""
        text = "SSN on file: 123-45-6789"
        results = _find_sensitive_in_resource(text)
        assert len(results) >= 1
        assert any("SSN" in r["pattern"] for r in results)

    def test_find_sensitive_connection_string(self):
        """Detects database connection URIs."""
        text = "postgres://admin:pass@db:5432/prod"
        results = _find_sensitive_in_resource(text)
        assert len(results) >= 1

    def test_find_sensitive_clean(self):
        """Clean content produces no findings."""
        text = "This is a normal report with no sensitive data."
        results = _find_sensitive_in_resource(text)
        assert results == []

    def test_check_resource_scoping_unscoped(self):
        """Unscoped resource returns False."""
        resource = {
            "uri": "config://global/settings",
            "name": "settings",
            "description": "Application configuration",
        }
        assert _check_resource_scoping(resource) is False

    def test_check_resource_scoping_user_in_uri(self):
        """Resource with 'user' in URI returns True."""
        resource = {
            "uri": "data://user/123/profile",
            "name": "profile",
            "description": "Data",
        }
        assert _check_resource_scoping(resource) is True

    def test_check_resource_scoping_session_in_description(self):
        """Resource with 'session' in description returns True."""
        resource = {
            "uri": "data://cache",
            "name": "cache",
            "description": "Per-session cache data",
        }
        assert _check_resource_scoping(resource) is True

    def test_compute_response_ratio_normal(self):
        """Normal ratio for proportionate response."""
        ratio = _compute_response_ratio("test query", "result data")
        assert ratio < 5.0

    def test_compute_response_ratio_excessive(self):
        """High ratio for disproportionate response."""
        ratio = _compute_response_ratio("x", "A" * 1000)
        assert ratio > 50.0

    def test_compute_response_ratio_empty_input(self):
        """Empty input returns 0.0."""
        ratio = _compute_response_ratio("", "some response")
        assert ratio == 0.0

    def test_build_minimal_args_string(self):
        """Builds short string for string params."""
        tool = {
            "name": "test",
            "inputSchema": {"properties": {"query": {"type": "string"}}},
        }
        args = _build_minimal_args(tool)
        assert args["query"] == "test"

    def test_build_minimal_args_number(self):
        """Builds minimal number for integer params."""
        tool = {
            "name": "test",
            "inputSchema": {"properties": {"count": {"type": "integer"}}},
        }
        args = _build_minimal_args(tool)
        assert args["count"] == 1

    def test_build_minimal_args_empty_schema(self):
        """Empty schema produces empty args."""
        tool = {"name": "test", "inputSchema": {}}
        args = _build_minimal_args(tool)
        assert args == {}

    def test_build_error_args_string(self):
        """Builds empty string for string params."""
        tool = {
            "name": "test",
            "inputSchema": {"properties": {"query": {"type": "string"}}},
        }
        args = _build_error_args(tool)
        assert args["query"] == ""

    def test_build_error_args_number(self):
        """Sends string for number params (type mismatch)."""
        tool = {
            "name": "test",
            "inputSchema": {"properties": {"count": {"type": "integer"}}},
        }
        args = _build_error_args(tool)
        assert args["count"] == "not_a_number"

    def test_build_error_args_empty_schema(self):
        """Empty schema produces empty args."""
        tool = {"name": "test", "inputSchema": {}}
        args = _build_error_args(tool)
        assert args == {}
