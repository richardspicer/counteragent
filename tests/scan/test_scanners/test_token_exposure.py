"""Tests for the token exposure scanner (MCP01).

Tests the scanner against the vulnerable fixture server and
verifies detection of sensitive parameters, secret patterns in
responses, secrets in error messages, and environment variable
leakage.
"""

import sys

import pytest

from counteragent.core.connection import MCPConnection
from counteragent.core.discovery import enumerate_server
from counteragent.core.models import ScanContext, Severity
from counteragent.scan.scanner.token_exposure import (
    TokenExposureScanner,
    _find_env_var_leakage,
    _find_secret_patterns,
    _find_sensitive_params,
    _normalize_param_name,
    _redact_secret,
)

VULN_TOKEN_SERVER = "fixtures/vulnerable_servers/vuln_token_exposure.py"
PYTHON = sys.executable


class TestTokenExposureIntegration:
    """Integration tests against the fixture server."""

    @pytest.mark.asyncio
    async def test_detects_sensitive_params(self):
        """Scanner flags tools with sensitive parameter names."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_TOKEN_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = TokenExposureScanner()
            findings = await scanner.scan(ctx)

            param_findings = [f for f in findings if f.rule_id == "MCP01-001"]
            assert len(param_findings) >= 1, "Should detect sensitive parameter names"

    @pytest.mark.asyncio
    async def test_detects_secrets_in_response(self):
        """Scanner flags secret patterns in tool responses."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_TOKEN_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = TokenExposureScanner()
            findings = await scanner.scan(ctx)

            secret_findings = [f for f in findings if f.rule_id == "MCP01-002"]
            assert len(secret_findings) >= 1, "Should detect secrets in responses"

    @pytest.mark.asyncio
    async def test_detects_secrets_in_errors(self):
        """Scanner flags secrets leaked in error responses."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_TOKEN_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = TokenExposureScanner()
            findings = await scanner.scan(ctx)

            error_findings = [f for f in findings if f.rule_id == "MCP01-003"]
            assert len(error_findings) >= 1, "Should detect secrets in error responses"

    @pytest.mark.asyncio
    async def test_detects_env_var_leakage(self):
        """Scanner flags environment variable leakage."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_TOKEN_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = TokenExposureScanner()
            findings = await scanner.scan(ctx)

            env_findings = [f for f in findings if f.rule_id == "MCP01-004"]
            assert len(env_findings) >= 1, "Should detect env var leakage"

    @pytest.mark.asyncio
    async def test_secret_findings_have_high_severity(self):
        """Secret pattern findings are HIGH severity."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_TOKEN_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = TokenExposureScanner()
            findings = await scanner.scan(ctx)

            secret_findings = [f for f in findings if f.rule_id == "MCP01-002"]
            for f in secret_findings:
                assert f.severity == Severity.HIGH, (
                    f"Secret in response should be HIGH severity, got {f.severity}"
                )

    @pytest.mark.asyncio
    async def test_clean_tools_no_findings(self):
        """Clean tools (ping, add_numbers, get_time) should not trigger findings."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_TOKEN_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = TokenExposureScanner()
            findings = await scanner.scan(ctx)

            clean_tool_findings = [
                f for f in findings if f.tool_name in ("ping", "add_numbers", "get_time")
            ]
            assert len(clean_tool_findings) == 0, (
                f"Clean tools should not trigger findings: {clean_tool_findings}"
            )

    @pytest.mark.asyncio
    async def test_all_findings_have_remediation(self):
        """Every finding includes remediation guidance."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_TOKEN_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = TokenExposureScanner()
            findings = await scanner.scan(ctx)

            for f in findings:
                assert f.remediation, f"Finding {f.rule_id} missing remediation"

    @pytest.mark.asyncio
    async def test_produces_multiple_finding_types(self):
        """Scanner produces findings across multiple rule IDs."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_TOKEN_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = TokenExposureScanner()
            findings = await scanner.scan(ctx)

            rule_ids = {f.rule_id for f in findings}
            assert len(rule_ids) >= 3, f"Expected at least 3 distinct rule IDs, got: {rule_ids}"


class TestSyntheticChecks:
    """Unit tests with synthetic data."""

    @pytest.mark.asyncio
    async def test_no_tools_returns_empty(self):
        """Empty tool list produces no findings."""
        ctx = ScanContext(tools=[], resources=[], server_info={})
        scanner = TokenExposureScanner()
        findings = await scanner.scan(ctx)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_sensitive_param_detected(self):
        """Tool with 'api_key' parameter is flagged."""
        ctx = ScanContext(
            tools=[
                {
                    "name": "test_tool",
                    "inputSchema": {
                        "properties": {
                            "api_key": {"type": "string"},
                            "query": {"type": "string"},
                        }
                    },
                }
            ],
            resources=[],
            server_info={},
        )
        scanner = TokenExposureScanner()
        findings = await scanner.scan(ctx)

        param_findings = [f for f in findings if f.rule_id == "MCP01-001"]
        assert len(param_findings) == 1
        assert "api_key" in param_findings[0].evidence

    @pytest.mark.asyncio
    async def test_multiple_sensitive_params(self):
        """Tool with multiple sensitive params produces one finding listing all."""
        ctx = ScanContext(
            tools=[
                {
                    "name": "vault_tool",
                    "inputSchema": {
                        "properties": {
                            "password": {"type": "string"},
                            "token": {"type": "string"},
                            "name": {"type": "string"},
                        }
                    },
                }
            ],
            resources=[],
            server_info={},
        )
        scanner = TokenExposureScanner()
        findings = await scanner.scan(ctx)

        param_findings = [f for f in findings if f.rule_id == "MCP01-001"]
        assert len(param_findings) == 1
        assert "password" in param_findings[0].evidence
        assert "token" in param_findings[0].evidence

    @pytest.mark.asyncio
    async def test_clean_tool_no_param_findings(self):
        """Tool with non-sensitive params produces no MCP01-001 findings."""
        ctx = ScanContext(
            tools=[
                {
                    "name": "safe_tool",
                    "inputSchema": {
                        "properties": {
                            "query": {"type": "string"},
                            "limit": {"type": "integer"},
                        }
                    },
                }
            ],
            resources=[],
            server_info={},
        )
        scanner = TokenExposureScanner()
        findings = await scanner.scan(ctx)

        param_findings = [f for f in findings if f.rule_id == "MCP01-001"]
        assert len(param_findings) == 0

    @pytest.mark.asyncio
    async def test_hyphen_variant_detected(self):
        """Parameter 'api-key' (with hyphen) is detected."""
        ctx = ScanContext(
            tools=[
                {
                    "name": "test_tool",
                    "inputSchema": {
                        "properties": {
                            "api-key": {"type": "string"},
                        }
                    },
                }
            ],
            resources=[],
            server_info={},
        )
        scanner = TokenExposureScanner()
        findings = await scanner.scan(ctx)

        param_findings = [f for f in findings if f.rule_id == "MCP01-001"]
        assert len(param_findings) == 1


class TestHelpers:
    """Unit tests for helper functions."""

    def test_normalize_param_name_underscore(self):
        """Underscored name is preserved."""
        assert _normalize_param_name("api_key") == "api_key"

    def test_normalize_param_name_hyphen(self):
        """Hyphens are converted to underscores."""
        assert _normalize_param_name("api-key") == "api_key"

    def test_normalize_param_name_uppercase(self):
        """Uppercase is lowered."""
        assert _normalize_param_name("API_KEY") == "api_key"

    def test_normalize_param_name_mixed(self):
        """Mixed case with hyphens is normalized."""
        assert _normalize_param_name("Auth-Token") == "auth_token"

    def test_find_sensitive_params_match(self):
        """Detects sensitive params in schema."""
        tool = {
            "name": "test",
            "inputSchema": {
                "properties": {
                    "api_key": {"type": "string"},
                    "query": {"type": "string"},
                }
            },
        }
        result = _find_sensitive_params(tool)
        assert "api_key" in result
        assert "query" not in result

    def test_find_sensitive_params_empty_schema(self):
        """Empty schema returns empty list."""
        tool = {"name": "test", "inputSchema": {}}
        result = _find_sensitive_params(tool)
        assert result == []

    def test_find_secret_patterns_jwt(self):
        """Detects JWT pattern."""
        header = "eyJhbGciOiJIUzI1NiJ9"
        payload = "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        text = f"token: {header}.{payload}"
        results = _find_secret_patterns(text)
        assert len(results) >= 1
        assert any("JWT" in r["pattern"] for r in results)

    def test_find_secret_patterns_openai(self):
        """Detects OpenAI API key pattern."""
        prefix = "sk-"
        text = f"key: {prefix}abcdefghijklmnopqrstuvwxyz1234567890"
        results = _find_secret_patterns(text)
        assert len(results) >= 1
        assert any("OpenAI" in r["pattern"] for r in results)

    def test_find_secret_patterns_github_pat(self):
        """Detects GitHub PAT pattern."""
        prefix = "ghp_"
        text = f"token: {prefix}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        results = _find_secret_patterns(text)
        assert len(results) >= 1
        assert any("GitHub PAT" in r["pattern"] for r in results)

    def test_find_secret_patterns_aws_access_key(self):
        """Detects AWS access key pattern."""
        prefix = "AKIA"
        text = f"key: {prefix}IOSFODNN7EXAMPLE"
        results = _find_secret_patterns(text)
        assert len(results) >= 1
        assert any("AWS" in r["pattern"] for r in results)

    def test_find_secret_patterns_bearer(self):
        """Detects Bearer token pattern."""
        header = "eyJhbGciOiJIUzI1NiJ9"
        payload = "eyJzdWIiOiIxIn0xxxxxxxx"
        text = f"Authorization: Bearer {header}.{payload}"
        results = _find_secret_patterns(text)
        assert any("Bearer" in r["pattern"] or "JWT" in r["pattern"] for r in results)

    def test_find_secret_patterns_private_key(self):
        """Detects private key header."""
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ..."
        results = _find_secret_patterns(text)
        assert len(results) >= 1
        assert any("Private key" in r["pattern"] for r in results)

    def test_find_secret_patterns_clean(self):
        """Clean text produces no findings."""
        text = "Operation completed successfully. Result: 42"
        results = _find_secret_patterns(text)
        assert results == []

    def test_find_secret_patterns_generic_api_key(self):
        """Detects generic API key assignment."""
        value = "abcdefghijklmnopqrstuvwxyz1234"
        text = f"api_key={value}"
        results = _find_secret_patterns(text)
        assert len(results) >= 1

    def test_find_secret_patterns_slack(self):
        """Detects Slack bot token."""
        # Construct dynamically to avoid GitHub push protection
        slack_prefix = "xoxb"
        text = f"token: {slack_prefix}-1234567890-abcdefghijklmnop"
        results = _find_secret_patterns(text)
        assert len(results) >= 1
        assert any("Slack" in r["pattern"] for r in results)

    def test_redact_secret_short(self):
        """Short secrets get partial redaction."""
        assert _redact_secret("abc12") == "abc***"

    def test_redact_secret_long(self):
        """Long secrets show first 5 and last 3."""
        result = _redact_secret("test-abcdefghijklmnop")
        assert result.startswith("test-")
        assert result.endswith("nop")
        assert "***" in result

    def test_redact_secret_exact_boundary(self):
        """8-char secret uses short redaction."""
        assert _redact_secret("12345678") == "123***"

    def test_find_env_var_leakage_secret(self):
        """Detects secret env vars."""
        text = "DB_PASSWORD=SuperSecret123\nJWT_SECRET=mysecretkey123"
        results = _find_env_var_leakage(text)
        assert len(results) >= 2
        names = [r["name"] for r in results]
        assert "DB_PASSWORD" in names
        assert "JWT_SECRET" in names

    def test_find_env_var_leakage_non_secret(self):
        """Non-secret env vars are not flagged."""
        text = "APP_NAME=myapp\nLOG_LEVEL=debug"
        results = _find_env_var_leakage(text)
        assert len(results) == 0

    def test_find_env_var_leakage_empty(self):
        """Empty text produces no findings."""
        results = _find_env_var_leakage("")
        assert results == []

    def test_find_env_var_leakage_mixed(self):
        """Only secret-indicating env vars are flagged from mixed content."""
        text = "APP_NAME=myapp\nSECRET_KEY=abc123456\nDEBUG=true"
        results = _find_env_var_leakage(text)
        assert len(results) == 1
        assert results[0]["name"] == "SECRET_KEY"

    def test_find_env_var_leakage_deduplicates(self):
        """Duplicate env var names are not reported twice."""
        text = "DB_PASSWORD=first\nDB_PASSWORD=second"
        results = _find_env_var_leakage(text)
        assert len(results) == 1
