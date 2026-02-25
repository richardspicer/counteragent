"""Scanner for supply chain risks and dependency awareness (MCP04).

Tests whether MCP servers can be identified, version-checked against
known vulnerabilities, and verified for expected tool provenance.
This is a static scanner — it analyzes server metadata from ScanContext
without making active tool calls.

Checks:
    MCP04-001: Unidentified server (missing/generic name or version)
    MCP04-002: Known vulnerable server version (CVE database match)
    MCP04-003: Outdated MCP protocol version
    MCP04-004: Tool namespace confusion (tool name from unexpected server)

References:
    - OWASP MCP Top 10: MCP04 — Software Supply Chain Attacks & Dependency Tampering

Planned Enhancement:
    Future ``mcp-audit update-cves`` CLI command will use the GitHub Advisory
    Database REST API (``GET https://api.github.com/advisories``) to refresh
    the local CVE database.

    GitHub Advisory Database is the preferred source over NVD because:
    - MCP CVEs are published there first (often before NVD ingests them)
    - Includes GitHub-originated advisories (GHSA) that may never get CVE IDs
    - Provides structured affected version ranges and patched versions per
      ecosystem (npm, pip)
    - REST API works without authentication for public advisories
    - No rate limit concerns at the query volume mcp-audit needs

    The update flow:
    1. Query ``GET https://api.github.com/advisories?keyword=MCP``
       (and "Model Context Protocol")
    2. Parse response for CVE ID, GHSA ID, severity, affected packages,
       patched versions
    3. Merge into local CVE dict (JSON cache file alongside the module)
    4. CLI: ``mcp-audit update-cves [--since YYYY-MM-DD]``

    This enhancement also supports the CounterAgent program's cross-tool
    advisory strategy — see ``counteragent/docs/github-advisory-integration.md``
    for the program-level design note.
"""

from __future__ import annotations

import logging
from typing import Any

from packaging.version import InvalidVersion, Version

from counteragent.scan.scanner.base import (
    BaseScanner,
    Finding,
    ScanContext,
    Severity,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Server names considered too generic to establish identity.
_GENERIC_SERVER_NAMES: set[str] = {
    "unknown",
    "server",
    "mcp-server",
    "mcp",
    "test",
    "default",
    "localhost",
    "example",
    "my-server",
    "untitled",
}

# Known MCP CVE database — static, updated manually.
# Last reviewed: 2026-02-22
# To update: search GitHub Advisory Database (keyword: MCP, Model Context Protocol),
# check NVD (nvd.nist.gov), review OWASP MCP Top 10 exploit tracker.
# Planned enhancement: `mcp-audit update-cves` CLI command (GitHub Advisory Database
# REST API integration — see counteragent/docs/github-advisory-integration.md).
_KNOWN_CVES: list[dict[str, Any]] = [
    {
        "cve_id": "CVE-2025-6514",
        "server_pattern": "mcp-remote",
        "affected_min": "0.0.5",
        "affected_max": "0.1.15",
        "fixed_version": "0.1.16",
        "cvss": 9.6,
        "description": (
            "Command injection and SSRF via crafted MCP tool responses "
            "in mcp-remote, allowing remote code execution."
        ),
        "related_owasp": ["MCP05", "MCP01"],
    },
    {
        "cve_id": "CVE-2025-49596",
        "server_pattern": "mcp-inspector",
        "affected_min": None,
        "affected_max": "0.14.0",
        "fixed_version": "0.14.1",
        "cvss": 9.4,
        "description": (
            "Authentication bypass and command injection in MCP Inspector, "
            "allowing unauthenticated remote code execution."
        ),
        "related_owasp": ["MCP07", "MCP05"],
    },
    {
        "cve_id": "CVE-2025-53967",
        "server_pattern": "figma-developer-mcp",
        "affected_min": None,
        "affected_max": None,
        "fixed_version": None,
        "cvss": 9.8,
        "description": (
            "Command injection in figma-developer-mcp via crafted Figma "
            "document content, allowing arbitrary code execution."
        ),
        "related_owasp": ["MCP05"],
    },
    {
        "cve_id": "CVE-2025-5277",
        "server_pattern": "aws-mcp-server",
        "affected_min": None,
        "affected_max": None,
        "fixed_version": None,
        "cvss": 9.4,
        "description": (
            "Command injection in aws-mcp-server through tool parameters, "
            "allowing arbitrary command execution."
        ),
        "related_owasp": ["MCP05"],
    },
    {
        "cve_id": "CVE-2025-53110",
        "server_pattern": "@anthropic/filesystem-mcp",
        "affected_min": None,
        "affected_max": None,
        "fixed_version": None,
        "cvss": 7.3,
        "description": (
            "Path traversal in @anthropic/filesystem-mcp allowing read "
            "access outside configured directories."
        ),
        "related_owasp": ["MCP02"],
    },
    {
        "cve_id": "CVE-2025-53109",
        "server_pattern": "@anthropic/filesystem-mcp",
        "affected_min": None,
        "affected_max": None,
        "fixed_version": None,
        "cvss": 8.4,
        "description": (
            "Symlink following in @anthropic/filesystem-mcp allowing "
            "command injection through crafted filenames."
        ),
        "related_owasp": ["MCP02", "MCP05"],
    },
]

# Current stable MCP protocol version.
_CURRENT_PROTOCOL_VERSION = "2025-11-25"

# Well-known tool names mapped to expected server identity patterns.
# If a tool name matches but the server identity doesn't, it may indicate
# dependency confusion or impersonation.
_WELL_KNOWN_TOOLS: dict[str, list[str]] = {
    # Filesystem tools
    "read_file": ["filesystem", "fs", "@anthropic/filesystem"],
    "write_file": ["filesystem", "fs", "@anthropic/filesystem"],
    "list_directory": ["filesystem", "fs", "@anthropic/filesystem"],
    "create_directory": ["filesystem", "fs", "@anthropic/filesystem"],
    # Shell/terminal tools
    "execute_command": ["shell", "terminal", "exec", "command"],
    "run_shell": ["shell", "terminal", "exec", "command"],
    "run_command": ["shell", "terminal", "exec", "command"],
    # Git tools
    "git_clone": ["git", "github"],
    "git_commit": ["git", "github"],
    "git_diff": ["git", "github"],
    # Database tools
    "query_database": ["database", "db", "sql", "postgres", "mysql", "sqlite"],
    "execute_sql": ["database", "db", "sql", "postgres", "mysql", "sqlite"],
    # Web/fetch tools
    "fetch_url": ["fetch", "web", "browser", "http"],
    "web_search": ["search", "web", "browser", "brave", "google"],
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _is_generic_name(name: str) -> bool:
    """Check if a server name is missing, empty, or too generic.

    Args:
        name: Server name from ``server_info["name"]``.

    Returns:
        True if the name is missing, empty, or matches a known generic name.

    Example:
        >>> _is_generic_name("mcp-server")
        True
        >>> _is_generic_name("my-custom-api")
        False
    """
    if not name or not name.strip():
        return True
    return name.strip().lower() in _GENERIC_SERVER_NAMES


def _is_version_missing(version: str | None) -> bool:
    """Check if a server version is missing or empty.

    Args:
        version: Server version from ``server_info["version"]``.

    Returns:
        True if the version is None, empty, or whitespace-only.

    Example:
        >>> _is_version_missing("")
        True
        >>> _is_version_missing("1.2.3")
        False
    """
    return not version or not str(version).strip()


def _parse_version(version_str: str) -> Version | None:
    """Safely parse a version string into a packaging.version.Version.

    Args:
        version_str: A version string like ``"1.2.3"`` or ``"0.14.0"``.

    Returns:
        A ``Version`` object, or ``None`` if the string cannot be parsed.

    Example:
        >>> _parse_version("1.2.3")
        <Version('1.2.3')>
        >>> _parse_version("not-a-version") is None
        True
    """
    try:
        return Version(version_str)
    except InvalidVersion:
        logger.warning("Could not parse version string: %r", version_str)
        return None


def _match_server_name(server_name: str, pattern: str) -> bool:
    """Check if a server name matches a CVE server name pattern.

    Matching is case-insensitive and supports partial matching — the
    pattern is checked as a substring of the server name.

    Args:
        server_name: Server name from ``server_info["name"]``.
        pattern: Server name pattern from the CVE database.

    Returns:
        True if the server name matches the pattern.

    Example:
        >>> _match_server_name("mcp-remote-v2", "mcp-remote")
        True
        >>> _match_server_name("MCP-Inspector", "mcp-inspector")
        True
        >>> _match_server_name("my-server", "mcp-remote")
        False
    """
    return pattern.lower() in server_name.lower()


def _check_version_affected(
    server_version: str,
    affected_min: str | None,
    affected_max: str | None,
) -> bool | None:
    """Check if a server version falls within the affected range of a CVE.

    Returns ``None`` if the version cannot be parsed (caller should handle
    gracefully). If both ``affected_min`` and ``affected_max`` are None,
    all versions are considered affected.

    Args:
        server_version: The server's reported version string.
        affected_min: Minimum affected version (inclusive), or None for no lower bound.
        affected_max: Maximum affected version (inclusive), or None for no upper bound.

    Returns:
        True if affected, False if not, None if version is unparseable.

    Example:
        >>> _check_version_affected("0.1.0", "0.0.5", "0.1.15")
        True
        >>> _check_version_affected("0.2.0", "0.0.5", "0.1.15")
        False
        >>> _check_version_affected("1.0.0", None, None)
        True
    """
    # If no version bounds, all versions are affected
    if affected_min is None and affected_max is None:
        return True

    parsed = _parse_version(server_version)
    if parsed is None:
        return None

    if affected_min is not None:
        min_ver = _parse_version(affected_min)
        if min_ver is not None and parsed < min_ver:
            return False

    if affected_max is not None:
        max_ver = _parse_version(affected_max)
        if max_ver is not None and parsed > max_ver:
            return False

    return True


def _severity_from_cvss(cvss: float) -> Severity:
    """Map a CVSS score to a Severity level.

    Args:
        cvss: CVSS score (0.0–10.0).

    Returns:
        Corresponding Severity level.

    Example:
        >>> _severity_from_cvss(9.6)
        <Severity.CRITICAL: 'critical'>
        >>> _severity_from_cvss(7.5)
        <Severity.HIGH: 'high'>
    """
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _match_tool_namespace(
    tool_name: str,
    server_name: str,
) -> str | None:
    """Check if a tool name is well-known and the server doesn't match expectations.

    Args:
        tool_name: Name of a tool from the server's tool list.
        server_name: Server name from ``server_info["name"]``.

    Returns:
        A string describing the expected server identity if there's a mismatch,
        or None if no issue is found.

    Example:
        >>> _match_tool_namespace("read_file", "my-database-server")
        'filesystem, fs, @anthropic/filesystem'
        >>> _match_tool_namespace("read_file", "filesystem-mcp")
        >>> _match_tool_namespace("custom_tool", "any-server")
    """
    expected_servers = _WELL_KNOWN_TOOLS.get(tool_name)
    if expected_servers is None:
        return None

    server_lower = server_name.lower()
    for expected in expected_servers:
        if expected.lower() in server_lower:
            return None

    return ", ".join(expected_servers)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class SupplyChainScanner(BaseScanner):
    """Scanner for supply chain risks and dependency awareness (MCP04).

    Checks server identity, version against known CVEs, protocol version
    currency, and tool namespace provenance. All checks are static — no
    tool calls are made.

    Checks:
        MCP04-001: Unidentified server (missing/generic name or version)
        MCP04-002: Known vulnerable server version (CVE database match)
        MCP04-003: Outdated MCP protocol version
        MCP04-004: Tool namespace confusion (tool name from unexpected server)

    Attributes:
        name: Scanner identifier used in CLI (--checks supply_chain).
        owasp_id: OWASP MCP Top 10 category.
        description: What this scanner tests.
    """

    name = "supply_chain"
    owasp_id = "MCP04"
    description = "Tests for supply chain risks and dependency awareness"

    async def scan(self, context: ScanContext) -> list[Finding]:
        """Run all supply chain checks.

        Args:
            context: ScanContext with server_info and tools.

        Returns:
            List of Findings for supply chain issues.
        """
        findings: list[Finding] = []

        findings.extend(self._check_server_identity(context))
        findings.extend(self._check_known_cves(context))
        findings.extend(self._check_protocol_version(context))
        findings.extend(self._check_tool_namespaces(context))

        return findings

    def _check_server_identity(self, context: ScanContext) -> list[Finding]:
        """Check if the server can be identified (MCP04-001).

        Flags missing/generic server names and missing versions.
        If both are missing, produces a single MEDIUM finding.

        Args:
            context: ScanContext with server_info.

        Returns:
            List of Findings for identity issues.
        """
        findings: list[Finding] = []
        server_info = context.server_info
        name = server_info.get("name", "")
        version = server_info.get("version")

        name_missing = _is_generic_name(name)
        version_missing = _is_version_missing(version)

        if name_missing and version_missing:
            findings.append(
                Finding(
                    rule_id="MCP04-001",
                    owasp_id="MCP04",
                    title="Unidentified server: missing name and version",
                    description=(
                        "Server reports no usable name or version. Without "
                        "identity metadata, it is impossible to track what "
                        "software is running, match against known CVEs, or "
                        "verify provenance."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=(f"name={name!r}, version={version!r} — both missing or generic"),
                    remediation=(
                        "Configure the MCP server to report a specific, "
                        "unique name and a semantic version string during "
                        "initialization."
                    ),
                    metadata={"name": name, "version": version},
                )
            )
        elif name_missing:
            findings.append(
                Finding(
                    rule_id="MCP04-001",
                    owasp_id="MCP04",
                    title="Unidentified server: missing or generic name",
                    description=(
                        f"Server name {name!r} is missing or too generic. "
                        f"A specific server name is needed to track software "
                        f"identity and match against known vulnerabilities."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"name={name!r} is missing or generic",
                    remediation=(
                        "Configure the MCP server to report a specific, "
                        "unique name during initialization."
                    ),
                    metadata={"name": name},
                )
            )
        elif version_missing:
            findings.append(
                Finding(
                    rule_id="MCP04-001",
                    owasp_id="MCP04",
                    title="Unidentified server: missing version",
                    description=(
                        f"Server {name!r} does not report a version. "
                        f"Without version information, it is impossible "
                        f"to check for known vulnerabilities or verify "
                        f"that the server is up to date."
                    ),
                    severity=Severity.LOW,
                    evidence=f"name={name!r}, version={version!r} — version missing",
                    remediation=(
                        "Configure the MCP server to report a semantic "
                        "version string during initialization."
                    ),
                    metadata={"name": name, "version": version},
                )
            )

        return findings

    def _check_known_cves(self, context: ScanContext) -> list[Finding]:
        """Check server against the known CVE database (MCP04-002).

        Matches server name against CVE patterns, then checks version
        ranges. Unparseable versions produce an INFO-level finding
        noting the name match without version confirmation.

        Args:
            context: ScanContext with server_info.

        Returns:
            List of Findings for known CVEs.
        """
        findings: list[Finding] = []
        server_info = context.server_info
        name = server_info.get("name", "")
        version = server_info.get("version", "")

        if not name or not name.strip():
            return findings

        for cve in _KNOWN_CVES:
            if not _match_server_name(name, cve["server_pattern"]):
                continue

            # Name matches — check version
            if _is_version_missing(version):
                # Can't check version, but name matched
                findings.append(
                    Finding(
                        rule_id="MCP04-002",
                        owasp_id="MCP04",
                        title=f"Possible vulnerable server: {cve['cve_id']}",
                        description=(
                            f"Server name {name!r} matches known vulnerable "
                            f"software pattern {cve['server_pattern']!r} "
                            f"({cve['cve_id']}), but no version is reported "
                            f"so the affected range cannot be verified. "
                            f"{cve['description']}"
                        ),
                        severity=Severity.INFO,
                        evidence=(
                            f"Name matches {cve['cve_id']} "
                            f"(pattern: {cve['server_pattern']!r}), "
                            f"version unknown"
                        ),
                        remediation=(
                            f"Verify the server version and update if affected. "
                            f"{cve['cve_id']}: CVSS {cve['cvss']}."
                            + (
                                f" Fixed in {cve['fixed_version']}."
                                if cve.get("fixed_version")
                                else " No fixed version available — consider alternatives."
                            )
                        ),
                        metadata={
                            "cve_id": cve["cve_id"],
                            "cvss": cve["cvss"],
                            "server_pattern": cve["server_pattern"],
                            "related_owasp": cve["related_owasp"],
                        },
                    )
                )
                continue

            affected = _check_version_affected(version, cve["affected_min"], cve["affected_max"])

            if affected is None:
                # Unparseable version — report as INFO
                findings.append(
                    Finding(
                        rule_id="MCP04-002",
                        owasp_id="MCP04",
                        title=f"Possible vulnerable server: {cve['cve_id']}",
                        description=(
                            f"Server name {name!r} matches known vulnerable "
                            f"software {cve['server_pattern']!r} "
                            f"({cve['cve_id']}), but version {version!r} "
                            f"could not be parsed to check the affected range. "
                            f"{cve['description']}"
                        ),
                        severity=Severity.INFO,
                        evidence=(f"Name matches {cve['cve_id']}, version {version!r} unparseable"),
                        remediation=(
                            f"Verify the server version manually. "
                            f"{cve['cve_id']}: CVSS {cve['cvss']}."
                            + (
                                f" Fixed in {cve['fixed_version']}."
                                if cve.get("fixed_version")
                                else " No fixed version available — consider alternatives."
                            )
                        ),
                        metadata={
                            "cve_id": cve["cve_id"],
                            "cvss": cve["cvss"],
                            "server_pattern": cve["server_pattern"],
                            "version_raw": version,
                            "related_owasp": cve["related_owasp"],
                        },
                    )
                )
            elif affected:
                severity = _severity_from_cvss(cve["cvss"])
                findings.append(
                    Finding(
                        rule_id="MCP04-002",
                        owasp_id="MCP04",
                        title=(f"Known vulnerable server: {cve['cve_id']} (CVSS {cve['cvss']})"),
                        description=(
                            f"Server {name!r} version {version!r} is affected "
                            f"by {cve['cve_id']} (CVSS {cve['cvss']}). "
                            f"{cve['description']}"
                        ),
                        severity=severity,
                        evidence=(
                            f"{cve['cve_id']}: {name} {version} in affected "
                            f"range "
                            f"({cve['affected_min'] or '*'}–"
                            f"{cve['affected_max'] or '*'}), "
                            f"CVSS {cve['cvss']}"
                        ),
                        remediation=(
                            f"Update {cve['server_pattern']} immediately."
                            + (
                                f" Fixed in version {cve['fixed_version']}."
                                if cve.get("fixed_version")
                                else " No fixed version available — consider alternatives."
                            )
                            + f" See {cve['cve_id']} for details."
                        ),
                        metadata={
                            "cve_id": cve["cve_id"],
                            "cvss": cve["cvss"],
                            "server_pattern": cve["server_pattern"],
                            "affected_min": cve["affected_min"],
                            "affected_max": cve["affected_max"],
                            "fixed_version": cve["fixed_version"],
                            "related_owasp": cve["related_owasp"],
                        },
                    )
                )
            # else: not affected — no finding

        return findings

    def _check_protocol_version(self, context: ScanContext) -> list[Finding]:
        """Check if the server uses an outdated MCP protocol version (MCP04-003).

        Skips if protocolVersion is missing.

        Args:
            context: ScanContext with server_info.

        Returns:
            List of Findings for outdated protocol versions.
        """
        findings: list[Finding] = []
        protocol_version = context.server_info.get("protocolVersion")

        if not protocol_version:
            return findings

        if str(protocol_version) != _CURRENT_PROTOCOL_VERSION:
            findings.append(
                Finding(
                    rule_id="MCP04-003",
                    owasp_id="MCP04",
                    title="Outdated MCP protocol version",
                    description=(
                        f"Server reports protocol version "
                        f"{protocol_version!r}, but the current stable "
                        f"version is {_CURRENT_PROTOCOL_VERSION!r}. Older "
                        f"protocol versions may lack security features "
                        f"added in newer versions."
                    ),
                    severity=Severity.LOW,
                    evidence=(
                        f"protocolVersion={protocol_version!r}, "
                        f"current={_CURRENT_PROTOCOL_VERSION!r}"
                    ),
                    remediation=(
                        f"Update the MCP server to support protocol "
                        f"version {_CURRENT_PROTOCOL_VERSION}."
                    ),
                    metadata={
                        "reported_version": str(protocol_version),
                        "current_version": _CURRENT_PROTOCOL_VERSION,
                    },
                )
            )

        return findings

    def _check_tool_namespaces(self, context: ScanContext) -> list[Finding]:
        """Check for tool namespace confusion (MCP04-004).

        Flags well-known tool names served by unexpected servers. Skips
        if server name is missing (that's MCP04-001's responsibility).

        Args:
            context: ScanContext with tools and server_info.

        Returns:
            List of Findings for namespace confusion.
        """
        findings: list[Finding] = []
        server_name = context.server_info.get("name", "")

        if not server_name or not server_name.strip():
            return findings

        for tool in context.tools:
            tool_name = tool.get("name", "")
            if not tool_name:
                continue

            expected = _match_tool_namespace(tool_name, server_name)
            if expected is not None:
                findings.append(
                    Finding(
                        rule_id="MCP04-004",
                        owasp_id="MCP04",
                        title=(f"Tool namespace confusion: '{tool_name}' from unexpected server"),
                        description=(
                            f"Tool '{tool_name}' is a well-known tool name "
                            f"typically provided by servers matching "
                            f"[{expected}], but this server identifies as "
                            f"{server_name!r}. This could indicate a "
                            f"dependency confusion or impersonation attack."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=(
                            f"Tool '{tool_name}' expected from [{expected}], "
                            f"served by {server_name!r}"
                        ),
                        remediation=(
                            f"Verify that '{tool_name}' is intentionally "
                            f"provided by {server_name!r}. If this server "
                            f"is not the expected source, investigate "
                            f"potential impersonation or dependency confusion."
                        ),
                        tool_name=tool_name,
                        metadata={
                            "expected_servers": expected,
                            "actual_server": server_name,
                        },
                    )
                )

        return findings
