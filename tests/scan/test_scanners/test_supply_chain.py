"""Tests for the supply chain scanner (MCP04).

Tests the scanner against the vulnerable fixture server and verifies
detection of unidentified servers, known CVEs, outdated protocol
versions, and tool namespace confusion.
"""

import sys

import pytest

from counteragent.core.connection import MCPConnection
from counteragent.core.discovery import enumerate_server
from counteragent.core.models import ScanContext, Severity
from counteragent.scan.scanner.supply_chain import (
    SupplyChainScanner,
    _check_version_affected,
    _is_generic_name,
    _is_version_missing,
    _match_server_name,
    _match_tool_namespace,
    _parse_version,
    _severity_from_cvss,
)

VULN_SUPPLY_CHAIN_SERVER = "fixtures/vulnerable_servers/vuln_supply_chain.py"
PYTHON = sys.executable


class TestSupplyChainIntegration:
    """Integration tests against the fixture server."""

    @pytest.mark.asyncio
    async def test_detects_known_cve(self):
        """Scanner flags the fixture server as known-vulnerable (CVE-2025-49596)."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_SUPPLY_CHAIN_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = SupplyChainScanner()
            findings = await scanner.scan(ctx)

            cve_findings = [f for f in findings if f.rule_id == "MCP04-002"]
            assert len(cve_findings) >= 1, "Should detect known CVE"
            assert any("CVE-2025-49596" in f.title for f in cve_findings)

    @pytest.mark.asyncio
    async def test_cve_finding_is_critical(self):
        """CVE-2025-49596 has CVSS 9.4, so finding should be CRITICAL."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_SUPPLY_CHAIN_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = SupplyChainScanner()
            findings = await scanner.scan(ctx)

            cve_findings = [
                f for f in findings if f.rule_id == "MCP04-002" and "CVE-2025-49596" in f.title
            ]
            assert len(cve_findings) >= 1
            assert cve_findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_detects_namespace_confusion(self):
        """Scanner flags filesystem/shell tools from inspector server."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_SUPPLY_CHAIN_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = SupplyChainScanner()
            findings = await scanner.scan(ctx)

            ns_findings = [f for f in findings if f.rule_id == "MCP04-004"]
            assert len(ns_findings) >= 2, "Should flag read_file and execute_command"
            tool_names = {f.tool_name for f in ns_findings}
            assert "read_file" in tool_names
            assert "execute_command" in tool_names

    @pytest.mark.asyncio
    async def test_clean_tools_no_namespace_findings(self):
        """Clean tools (inspect_server, ping, add_numbers) don't trigger MCP04-004."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_SUPPLY_CHAIN_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = SupplyChainScanner()
            findings = await scanner.scan(ctx)

            clean_ns_findings = [
                f
                for f in findings
                if f.rule_id == "MCP04-004"
                and f.tool_name in ("inspect_server", "ping", "add_numbers")
            ]
            assert len(clean_ns_findings) == 0

    @pytest.mark.asyncio
    async def test_all_findings_have_remediation(self):
        """Every finding includes remediation guidance."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_SUPPLY_CHAIN_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = SupplyChainScanner()
            findings = await scanner.scan(ctx)

            for f in findings:
                assert f.remediation, f"Finding {f.rule_id} missing remediation"


class TestServerIdentity:
    """Synthetic tests for MCP04-001: Unidentified server."""

    @pytest.mark.asyncio
    async def test_missing_name_and_version(self):
        """Both name and version missing produces single MEDIUM finding."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "", "version": ""},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        id_findings = [f for f in findings if f.rule_id == "MCP04-001"]
        assert len(id_findings) == 1
        assert id_findings[0].severity == Severity.MEDIUM
        assert "name" in id_findings[0].evidence
        assert "version" in id_findings[0].evidence

    @pytest.mark.asyncio
    async def test_generic_name_flagged(self):
        """Generic name like 'mcp-server' triggers MCP04-001."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "mcp-server", "version": "1.0.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        id_findings = [f for f in findings if f.rule_id == "MCP04-001"]
        assert len(id_findings) == 1
        assert id_findings[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_missing_version_flagged(self):
        """Missing version with valid name triggers LOW finding."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "my-custom-server", "version": ""},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        id_findings = [f for f in findings if f.rule_id == "MCP04-001"]
        assert len(id_findings) == 1
        assert id_findings[0].severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_valid_name_and_version_no_finding(self):
        """Valid name and version produces no MCP04-001 finding."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "my-custom-server", "version": "2.1.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        id_findings = [f for f in findings if f.rule_id == "MCP04-001"]
        assert len(id_findings) == 0

    @pytest.mark.asyncio
    async def test_none_version_flagged(self):
        """None version triggers LOW finding."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "my-server-app", "version": None},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        id_findings = [f for f in findings if f.rule_id == "MCP04-001"]
        assert len(id_findings) == 1
        assert id_findings[0].severity == Severity.LOW


class TestKnownCVEs:
    """Synthetic tests for MCP04-002: Known vulnerable server version."""

    @pytest.mark.asyncio
    async def test_vulnerable_version_detected(self):
        """mcp-remote 0.1.0 is in CVE-2025-6514 range (0.0.5-0.1.15)."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "mcp-remote", "version": "0.1.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        cve_findings = [f for f in findings if f.rule_id == "MCP04-002"]
        assert len(cve_findings) == 1
        assert "CVE-2025-6514" in cve_findings[0].title
        assert cve_findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_safe_version_no_finding(self):
        """mcp-remote 0.2.0 is above CVE-2025-6514 range."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "mcp-remote", "version": "0.2.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        cve_findings = [f for f in findings if f.rule_id == "MCP04-002"]
        assert len(cve_findings) == 0

    @pytest.mark.asyncio
    async def test_all_versions_affected(self):
        """figma-developer-mcp has no version bounds -- all versions affected."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "figma-developer-mcp", "version": "99.0.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        cve_findings = [f for f in findings if f.rule_id == "MCP04-002"]
        assert len(cve_findings) == 1
        assert "CVE-2025-53967" in cve_findings[0].title

    @pytest.mark.asyncio
    async def test_unparseable_version_info_finding(self):
        """Unparseable version produces INFO finding for name match."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "mcp-remote", "version": "nightly-build-abc"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        cve_findings = [f for f in findings if f.rule_id == "MCP04-002"]
        assert len(cve_findings) == 1
        assert cve_findings[0].severity == Severity.INFO
        assert "unparseable" in cve_findings[0].evidence

    @pytest.mark.asyncio
    async def test_case_insensitive_name_match(self):
        """Name matching is case-insensitive."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "MCP-Remote", "version": "0.1.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        cve_findings = [f for f in findings if f.rule_id == "MCP04-002"]
        assert len(cve_findings) == 1

    @pytest.mark.asyncio
    async def test_partial_name_match(self):
        """Partial name match works (mcp-remote-v2 matches mcp-remote)."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "mcp-remote-v2", "version": "0.1.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        cve_findings = [f for f in findings if f.rule_id == "MCP04-002"]
        assert len(cve_findings) >= 1

    @pytest.mark.asyncio
    async def test_missing_version_with_name_match(self):
        """Name match with missing version produces INFO finding."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "mcp-inspector", "version": ""},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        cve_findings = [f for f in findings if f.rule_id == "MCP04-002"]
        assert len(cve_findings) == 1
        assert cve_findings[0].severity == Severity.INFO

    @pytest.mark.asyncio
    async def test_no_name_skips_cve_check(self):
        """Empty server name skips CVE checking entirely."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "", "version": "0.13.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        cve_findings = [f for f in findings if f.rule_id == "MCP04-002"]
        assert len(cve_findings) == 0

    @pytest.mark.asyncio
    async def test_multiple_cves_for_same_server(self):
        """Server matching multiple CVEs produces multiple findings."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={
                "name": "@anthropic/filesystem-mcp",
                "version": "1.0.0",
            },
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        cve_findings = [f for f in findings if f.rule_id == "MCP04-002"]
        assert len(cve_findings) == 2
        cve_ids = {f.metadata["cve_id"] for f in cve_findings}
        assert "CVE-2025-53110" in cve_ids
        assert "CVE-2025-53109" in cve_ids

    @pytest.mark.asyncio
    async def test_unrelated_server_no_cve(self):
        """Server name that doesn't match any CVE produces no MCP04-002 finding."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "my-custom-server", "version": "1.0.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        cve_findings = [f for f in findings if f.rule_id == "MCP04-002"]
        assert len(cve_findings) == 0


class TestProtocolVersion:
    """Synthetic tests for MCP04-003: Outdated protocol version."""

    @pytest.mark.asyncio
    async def test_outdated_protocol_flagged(self):
        """Older protocol version triggers MCP04-003."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={
                "name": "my-server",
                "version": "1.0.0",
                "protocolVersion": "2024-11-05",
            },
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        proto_findings = [f for f in findings if f.rule_id == "MCP04-003"]
        assert len(proto_findings) == 1
        assert proto_findings[0].severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_current_protocol_no_finding(self):
        """Current protocol version produces no MCP04-003 finding."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={
                "name": "my-server",
                "version": "1.0.0",
                "protocolVersion": "2025-11-25",
            },
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        proto_findings = [f for f in findings if f.rule_id == "MCP04-003"]
        assert len(proto_findings) == 0

    @pytest.mark.asyncio
    async def test_missing_protocol_no_finding(self):
        """Missing protocolVersion does not trigger MCP04-003."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        proto_findings = [f for f in findings if f.rule_id == "MCP04-003"]
        assert len(proto_findings) == 0


class TestToolNamespaces:
    """Synthetic tests for MCP04-004: Tool namespace confusion."""

    @pytest.mark.asyncio
    async def test_mismatched_tool_flagged(self):
        """Filesystem tool from a database server triggers MCP04-004."""
        ctx = ScanContext(
            tools=[{"name": "read_file", "inputSchema": {}}],
            resources=[],
            server_info={"name": "my-database-server", "version": "1.0.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        ns_findings = [f for f in findings if f.rule_id == "MCP04-004"]
        assert len(ns_findings) == 1
        assert ns_findings[0].tool_name == "read_file"
        assert ns_findings[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_matching_tool_no_finding(self):
        """Filesystem tool from a filesystem server produces no finding."""
        ctx = ScanContext(
            tools=[{"name": "read_file", "inputSchema": {}}],
            resources=[],
            server_info={"name": "my-filesystem-server", "version": "1.0.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        ns_findings = [f for f in findings if f.rule_id == "MCP04-004"]
        assert len(ns_findings) == 0

    @pytest.mark.asyncio
    async def test_unknown_tool_no_finding(self):
        """Unknown tool name produces no MCP04-004 finding."""
        ctx = ScanContext(
            tools=[{"name": "custom_analysis_tool", "inputSchema": {}}],
            resources=[],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        ns_findings = [f for f in findings if f.rule_id == "MCP04-004"]
        assert len(ns_findings) == 0

    @pytest.mark.asyncio
    async def test_missing_server_name_skips_check(self):
        """Missing server name skips namespace check entirely."""
        ctx = ScanContext(
            tools=[{"name": "read_file", "inputSchema": {}}],
            resources=[],
            server_info={"name": "", "version": "1.0.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        ns_findings = [f for f in findings if f.rule_id == "MCP04-004"]
        assert len(ns_findings) == 0

    @pytest.mark.asyncio
    async def test_multiple_mismatched_tools(self):
        """Multiple well-known tools from wrong server each get flagged."""
        ctx = ScanContext(
            tools=[
                {"name": "read_file", "inputSchema": {}},
                {"name": "execute_command", "inputSchema": {}},
                {"name": "custom_tool", "inputSchema": {}},
            ],
            resources=[],
            server_info={"name": "my-analytics-server", "version": "1.0.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        ns_findings = [f for f in findings if f.rule_id == "MCP04-004"]
        assert len(ns_findings) == 2
        tool_names = {f.tool_name for f in ns_findings}
        assert "read_file" in tool_names
        assert "execute_command" in tool_names

    @pytest.mark.asyncio
    async def test_no_tools_no_findings(self):
        """Empty tool list produces no MCP04-004 findings."""
        ctx = ScanContext(
            tools=[],
            resources=[],
            server_info={"name": "my-server", "version": "1.0.0"},
        )
        scanner = SupplyChainScanner()
        findings = await scanner.scan(ctx)

        ns_findings = [f for f in findings if f.rule_id == "MCP04-004"]
        assert len(ns_findings) == 0


class TestHelpers:
    """Unit tests for helper functions."""

    def test_is_generic_name_empty(self):
        """Empty string is generic."""
        assert _is_generic_name("") is True

    def test_is_generic_name_none(self):
        """None-like empty string is generic."""
        assert _is_generic_name("   ") is True

    def test_is_generic_name_mcp_server(self):
        """'mcp-server' is generic."""
        assert _is_generic_name("mcp-server") is True

    def test_is_generic_name_case_insensitive(self):
        """Generic name matching is case-insensitive."""
        assert _is_generic_name("MCP-SERVER") is True
        assert _is_generic_name("Unknown") is True

    def test_is_generic_name_custom(self):
        """Custom server names are not generic."""
        assert _is_generic_name("my-custom-api") is False

    def test_is_version_missing_empty(self):
        """Empty string is missing."""
        assert _is_version_missing("") is True

    def test_is_version_missing_none(self):
        """None is missing."""
        assert _is_version_missing(None) is True

    def test_is_version_missing_whitespace(self):
        """Whitespace-only is missing."""
        assert _is_version_missing("   ") is True

    def test_is_version_missing_valid(self):
        """Valid version is not missing."""
        assert _is_version_missing("1.2.3") is False

    def test_parse_version_valid(self):
        """Valid semver is parsed."""
        v = _parse_version("1.2.3")
        assert v is not None
        assert str(v) == "1.2.3"

    def test_parse_version_invalid(self):
        """Invalid version returns None."""
        assert _parse_version("not-a-version") is None

    def test_parse_version_prerelease(self):
        """Prerelease versions are parseable."""
        v = _parse_version("1.0.0rc1")
        assert v is not None

    def test_match_server_name_exact(self):
        """Exact match works."""
        assert _match_server_name("mcp-remote", "mcp-remote") is True

    def test_match_server_name_partial(self):
        """Partial match works (pattern is substring)."""
        assert _match_server_name("mcp-remote-v2", "mcp-remote") is True

    def test_match_server_name_case_insensitive(self):
        """Case-insensitive match."""
        assert _match_server_name("MCP-Remote", "mcp-remote") is True

    def test_match_server_name_no_match(self):
        """Non-matching names return False."""
        assert _match_server_name("my-server", "mcp-remote") is False

    def test_check_version_affected_in_range(self):
        """Version in affected range returns True."""
        assert _check_version_affected("0.1.0", "0.0.5", "0.1.15") is True

    def test_check_version_affected_above_range(self):
        """Version above affected range returns False."""
        assert _check_version_affected("0.2.0", "0.0.5", "0.1.15") is False

    def test_check_version_affected_below_range(self):
        """Version below affected range returns False."""
        assert _check_version_affected("0.0.1", "0.0.5", "0.1.15") is False

    def test_check_version_affected_at_min(self):
        """Version at min boundary is affected."""
        assert _check_version_affected("0.0.5", "0.0.5", "0.1.15") is True

    def test_check_version_affected_at_max(self):
        """Version at max boundary is affected."""
        assert _check_version_affected("0.1.15", "0.0.5", "0.1.15") is True

    def test_check_version_affected_no_bounds(self):
        """No bounds means all versions affected."""
        assert _check_version_affected("99.0.0", None, None) is True

    def test_check_version_affected_no_min(self):
        """No lower bound, only upper bound."""
        assert _check_version_affected("0.10.0", None, "0.14.0") is True
        assert _check_version_affected("0.15.0", None, "0.14.0") is False

    def test_check_version_affected_no_max(self):
        """No upper bound, only lower bound."""
        assert _check_version_affected("1.0.0", "0.5.0", None) is True
        assert _check_version_affected("0.1.0", "0.5.0", None) is False

    def test_check_version_affected_unparseable(self):
        """Unparseable version returns None."""
        assert _check_version_affected("nightly", "0.0.5", "0.1.15") is None

    def test_severity_from_cvss_critical(self):
        """CVSS >= 9.0 is CRITICAL."""
        assert _severity_from_cvss(9.6) == Severity.CRITICAL
        assert _severity_from_cvss(9.0) == Severity.CRITICAL

    def test_severity_from_cvss_high(self):
        """CVSS >= 7.0 and < 9.0 is HIGH."""
        assert _severity_from_cvss(8.4) == Severity.HIGH
        assert _severity_from_cvss(7.0) == Severity.HIGH

    def test_severity_from_cvss_medium(self):
        """CVSS >= 4.0 and < 7.0 is MEDIUM."""
        assert _severity_from_cvss(5.5) == Severity.MEDIUM
        assert _severity_from_cvss(4.0) == Severity.MEDIUM

    def test_severity_from_cvss_low(self):
        """CVSS < 4.0 is LOW."""
        assert _severity_from_cvss(3.9) == Severity.LOW
        assert _severity_from_cvss(0.0) == Severity.LOW

    def test_match_tool_namespace_mismatch(self):
        """Well-known tool from wrong server returns expected servers."""
        result = _match_tool_namespace("read_file", "my-database-server")
        assert result is not None
        assert "filesystem" in result

    def test_match_tool_namespace_match(self):
        """Well-known tool from matching server returns None."""
        result = _match_tool_namespace("read_file", "my-filesystem-server")
        assert result is None

    def test_match_tool_namespace_unknown_tool(self):
        """Unknown tool name returns None."""
        result = _match_tool_namespace("custom_analysis", "any-server")
        assert result is None

    def test_match_tool_namespace_case_insensitive(self):
        """Server name matching is case-insensitive."""
        result = _match_tool_namespace("read_file", "My-FileSystem-App")
        assert result is None
