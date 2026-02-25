"""Scanner for shadow MCP servers (MCP09).

Assesses whether a connected MCP server exhibits characteristics of an
unmanaged, shadow, or development deployment. This scanner does NOT scan
networks for unknown servers — it evaluates the *connected* server's
metadata to determine if it looks like it shouldn't be in production.

Checks:
    MCP09-001: Development server indicators in name/version
    MCP09-002: Known development tool fingerprint (MCP Inspector, scaffolds)
    MCP09-003: Debug/test tool exposure
    MCP09-004: Governance metadata gap (tools exposed with no description)
    MCP09-005: Ephemeral deployment markers (UUIDs, hex names, snapshot versions)

References:
    - OWASP MCP Top 10: MCP09 — Shadow MCP Servers
    - CVE-2025-49596: MCP Inspector production exposure
"""

from __future__ import annotations

import logging
import re
from typing import Any

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

# Substrings in server name/version that indicate development environments.
_DEV_INDICATOR_PATTERNS: list[str] = [
    "dev",
    "test",
    "debug",
    "example",
    "demo",
    "sample",
    "localhost",
    "prototype",
    "staging",
    "experimental",
    "tmp",
    "temp",
]

# Known development-only tools and scaffolds. Each entry has a name pattern
# and optional version constraints. These tools have had real CVEs when
# exposed to production traffic.
_KNOWN_DEV_TOOLS: list[dict[str, Any]] = [
    {
        "name_pattern": "mcp inspector",
        "description": "MCP Inspector — CVE-2025-49596 poster child",
    },
    {
        "name_pattern": "mcp-inspector",
        "description": "MCP Inspector — CVE-2025-49596 poster child",
    },
    {
        "name_pattern": "create-mcp-server",
        "description": "create-mcp-server scaffold",
    },
    {
        "name_pattern": "mcp-server-template",
        "description": "MCP server template scaffold",
    },
    {
        "name_pattern": "mcp-starter",
        "description": "MCP starter scaffold",
    },
    {
        "name_pattern": "mcp-example",
        "description": "MCP example server",
    },
    {
        "name_pattern": "tutorial",
        "description": "Tutorial/quickstart server",
    },
    {
        "name_pattern": "quickstart",
        "description": "Tutorial/quickstart server",
    },
    {
        "name_pattern": "getting-started",
        "description": "Tutorial/quickstart server",
    },
    {
        "name_pattern": "hello-world",
        "description": "Tutorial/quickstart server",
    },
]

# Tool name prefixes that indicate debug/test tooling.
_DEBUG_TOOL_PREFIXES: list[str] = [
    "debug_",
    "test_",
    "dump_",
    "inspect_",
    "__internal_",
    "_dev_",
    "mock_",
    "sample_",
    "tmp_",
    "temp_",
]

# Exact tool names that are suspicious only in combination with other indicators.
_SUSPICIOUS_EXACT_NAMES: set[str] = {
    "debug",
    "test",
    "dump",
    "inspect",
    "healthcheck",
    "ping",
    "echo",
}

# Phrases in tool descriptions indicating development-only use.
_DEV_DESCRIPTION_PHRASES: list[str] = [
    "for development only",
    "debug purposes",
    "not for production",
    "testing only",
    "internal use",
]

# Ephemeral version patterns.
_EPHEMERAL_VERSIONS: set[str] = {
    "0.0.0",
    "0.0.1",
}

# Regex for UUID format (8-4-4-4-12 hex).
_UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

# Regex for 32 continuous hex chars (UUID without dashes).
_CONTINUOUS_HEX_PATTERN = re.compile(r"[0-9a-f]{32}", re.IGNORECASE)

# Regex for pure hex string (12+ chars) — Docker-default hostnames.
_DOCKER_HEX_PATTERN = re.compile(r"^[0-9a-f]{12,}$", re.IGNORECASE)

# Regex for container-* pattern.
_CONTAINER_PATTERN = re.compile(r"^container-", re.IGNORECASE)

# Regex for timestamp-like names (10+ digits).
_TIMESTAMP_PATTERN = re.compile(r"^\d{10,}$")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _has_dev_indicator(text: str) -> str | None:
    """Check if text contains a development indicator pattern.

    Performs case-insensitive substring matching against known
    development/test/debug patterns.

    Args:
        text: Server name or version string to check.

    Returns:
        The matched pattern string, or None if no match.

    Example:
        >>> _has_dev_indicator("my-dev-server")
        'dev'
        >>> _has_dev_indicator("production-api")
    """
    text_lower = text.lower()
    for pattern in _DEV_INDICATOR_PATTERNS:
        if pattern in text_lower:
            return pattern
    return None


def _match_known_dev_tool(
    name: str,
    version: str,
) -> dict[str, Any] | None:
    """Check if server name/version matches a known development tool.

    Args:
        name: Server name from ``server_info["name"]``.
        version: Server version from ``server_info["version"]``.

    Returns:
        Dict with 'name_pattern' and 'description' if matched, None otherwise.

    Example:
        >>> _match_known_dev_tool("MCP Inspector", "0.13.0")
        {'name_pattern': 'mcp inspector', 'description': '...'}
        >>> _match_known_dev_tool("my-api", "1.0.0")
    """
    name_lower = name.lower()

    # Special case: FastMCP is legitimate unless running in dev mode.
    if "fastmcp" in name_lower:
        version_lower = (version or "").lower()
        is_dev_version = "dev" in version_lower
        is_zero_x = version_lower.startswith("0.") if version_lower else False
        if is_dev_version or is_zero_x:
            return {
                "name_pattern": "fastmcp",
                "description": "FastMCP dev server (dev or 0.x version)",
            }
        return None

    for tool in _KNOWN_DEV_TOOLS:
        if tool["name_pattern"] in name_lower:
            return tool

    return None


def _is_debug_tool(tool_name: str) -> bool:
    """Check if a tool name matches debug/test naming patterns.

    Args:
        tool_name: Tool name to check.

    Returns:
        True if the tool name starts with a known debug/test prefix.

    Example:
        >>> _is_debug_tool("debug_dump_state")
        True
        >>> _is_debug_tool("get_data")
        False
    """
    name_lower = tool_name.lower()
    return any(name_lower.startswith(prefix) for prefix in _DEBUG_TOOL_PREFIXES)


def _has_dev_description(description: str) -> str | None:
    """Check if a tool description contains development-only phrases.

    Args:
        description: Tool description text.

    Returns:
        The matched phrase, or None if no match.

    Example:
        >>> _has_dev_description("Debug tool for development only")
        'for development only'
        >>> _has_dev_description("Process incoming requests")
    """
    desc_lower = description.lower()
    for phrase in _DEV_DESCRIPTION_PHRASES:
        if phrase in desc_lower:
            return phrase
    return None


def _has_ephemeral_markers(name: str, version: str) -> list[str]:
    """Check for ephemeral deployment markers in server name and version.

    Looks for UUIDs, Docker-default hex hostnames, auto-generated version
    strings, and timestamp-based names.

    Args:
        name: Server name to check.
        version: Server version to check.

    Returns:
        List of marker descriptions found. Empty if none.

    Example:
        >>> _has_ephemeral_markers("abc123def456ab", "0.0.0")
        ['Docker-default hex hostname', 'Auto-generated version: 0.0.0']
    """
    markers: list[str] = []

    # UUID in name
    if _UUID_PATTERN.search(name):
        markers.append("UUID in server name")
    elif _CONTINUOUS_HEX_PATTERN.search(name):
        markers.append("32-char hex string in server name (UUID without dashes)")

    # Docker-default hex hostname
    if _DOCKER_HEX_PATTERN.match(name):
        markers.append("Docker-default hex hostname")

    # Container-* pattern
    if _CONTAINER_PATTERN.match(name):
        markers.append("Container-prefixed hostname")

    # Timestamp-like name (10+ digits)
    if _TIMESTAMP_PATTERN.match(name):
        markers.append("Timestamp-like server name")

    # Version checks
    if version:
        version_lower = version.lower()

        # Exact ephemeral versions
        if version in _EPHEMERAL_VERSIONS:
            markers.append(f"Auto-generated version: {version}")

        # 0.x.y-dev pattern
        if re.match(r"^0\.\d+\.\d+-dev$", version_lower):
            markers.append(f"Dev pre-release version: {version}")

        # SNAPSHOT versions
        if "snapshot" in version_lower:
            markers.append(f"Snapshot version: {version}")

        # alpha0 / canary
        if "alpha0" in version_lower:
            markers.append(f"Alpha-zero version: {version}")
        if "canary" in version_lower:
            markers.append(f"Canary version: {version}")

    return markers


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class ShadowServersScanner(BaseScanner):
    """Scanner for shadow MCP servers (MCP09).

    Assesses whether a connected server exhibits characteristics of an
    unmanaged, shadow, or development deployment. Checks server metadata,
    tool names, descriptions, and deployment markers.

    Checks:
        MCP09-001: Development server indicators in name/version
        MCP09-002: Known development tool fingerprint
        MCP09-003: Debug/test tool exposure
        MCP09-004: Governance metadata gap
        MCP09-005: Ephemeral deployment markers

    Attributes:
        name: Scanner identifier used in CLI (--checks shadow_servers).
        owasp_id: OWASP MCP Top 10 category.
        description: What this scanner tests.
    """

    name = "shadow_servers"
    owasp_id = "MCP09"
    description = "Tests for shadow/unmanaged MCP server deployments"

    async def scan(self, context: ScanContext) -> list[Finding]:
        """Run all shadow server checks.

        Args:
            context: ScanContext with server_info and tools.

        Returns:
            List of Findings for shadow server indicators.
        """
        findings: list[Finding] = []

        findings.extend(self._check_dev_indicators(context))
        findings.extend(self._check_known_dev_tools(context))
        findings.extend(self._check_debug_tools(context))
        findings.extend(self._check_governance_gap(context))
        findings.extend(self._check_ephemeral_markers(context))

        return findings

    def _check_dev_indicators(self, context: ScanContext) -> list[Finding]:
        """Check server name and version for development indicators (MCP09-001).

        Scans server_info name and version for substrings like 'dev', 'test',
        'debug', 'staging', etc. Case-insensitive matching.

        Args:
            context: ScanContext with server_info.

        Returns:
            List of Findings for development indicators.
        """
        findings: list[Finding] = []
        server_info = context.server_info
        name = server_info.get("name", "")
        version = server_info.get("version", "")

        if name:
            matched = _has_dev_indicator(name)
            if matched:
                findings.append(
                    Finding(
                        rule_id="MCP09-001",
                        owasp_id="MCP09",
                        title=f"Development server indicator: '{name}'",
                        description=(
                            f"Server name '{name}' contains development "
                            f"indicator '{matched}'. Development servers "
                            f"exposed to production traffic lack hardening, "
                            f"monitoring, and access controls."
                        ),
                        severity=Severity.LOW,
                        evidence=f"name='{name}' contains '{matched}'",
                        remediation=(
                            "Use production-specific server names that don't "
                            "contain development indicators. Ensure development "
                            "and staging servers are not accessible from "
                            "production networks."
                        ),
                        metadata={"field": "name", "matched_pattern": matched},
                    )
                )

        if version:
            matched = _has_dev_indicator(version)
            if matched:
                findings.append(
                    Finding(
                        rule_id="MCP09-001",
                        owasp_id="MCP09",
                        title=f"Development server indicator: '{name}'",
                        description=(
                            f"Server version '{version}' contains development "
                            f"indicator '{matched}'. Development versions "
                            f"may include debug features, verbose logging, "
                            f"or disabled security controls."
                        ),
                        severity=Severity.LOW,
                        evidence=f"version='{version}' contains '{matched}'",
                        remediation=(
                            "Deploy production builds with stable version "
                            "strings. Remove development flags and debug "
                            "features before production deployment."
                        ),
                        metadata={"field": "version", "matched_pattern": matched},
                    )
                )

        return findings

    def _check_known_dev_tools(self, context: ScanContext) -> list[Finding]:
        """Check for known development tool fingerprints (MCP09-002).

        Matches server name/version against signatures of known
        development-only tools like MCP Inspector, scaffolds, and
        tutorial servers.

        Args:
            context: ScanContext with server_info.

        Returns:
            List of Findings for known dev tool matches.
        """
        findings: list[Finding] = []
        server_info = context.server_info
        name = server_info.get("name", "")
        version = server_info.get("version", "")

        if not name:
            return findings

        match = _match_known_dev_tool(name, version or "")
        if match is None:
            return findings

        severity = Severity.MEDIUM
        description_extra = ""

        # Escalate to HIGH if no auth is apparent
        # (we don't depend on the auth scanner, just note the risk)
        description_extra = (
            " Production exposure of development tools is high risk — "
            "these tools typically have no authentication, overly "
            "permissive capabilities, and known CVEs."
        )
        severity = Severity.HIGH

        findings.append(
            Finding(
                rule_id="MCP09-002",
                owasp_id="MCP09",
                title=f"Known development tool detected: '{name} {version}'",
                description=(
                    f"Server '{name}' (version: '{version}') matches known "
                    f"development tool: {match['description']}."
                    f"{description_extra}"
                ),
                severity=severity,
                evidence=(
                    f"name='{name}', version='{version}' matches pattern '{match['name_pattern']}'"
                ),
                remediation=(
                    "Remove development tools from production environments. "
                    "If this server must remain accessible, add authentication, "
                    "restrict network access, and monitor for abuse."
                ),
                metadata={
                    "matched_pattern": match["name_pattern"],
                    "tool_description": match["description"],
                },
            )
        )

        return findings

    def _check_debug_tools(self, context: ScanContext) -> list[Finding]:
        """Check for debug/test tool exposure (MCP09-003).

        Scans tool names for dev-only prefixes and descriptions for
        development-only phrases. Escalates severity when 3+ debug
        tools are found.

        Args:
            context: ScanContext with tools list.

        Returns:
            List of Findings for debug/test tools.
        """
        findings: list[Finding] = []
        debug_tools: list[str] = []

        for tool in context.tools:
            tool_name = tool.get("name", "")
            tool_desc = tool.get("description", "")

            if not tool_name:
                continue

            # Check prefixes
            if _is_debug_tool(tool_name):
                debug_tools.append(tool_name)
                findings.append(
                    Finding(
                        rule_id="MCP09-003",
                        owasp_id="MCP09",
                        title=f"Debug/test tool exposed: '{tool_name}'",
                        description=(
                            f"Tool '{tool_name}' has a debug/test naming "
                            f"pattern. Development tools should not be "
                            f"exposed in production environments."
                        ),
                        severity=Severity.LOW,
                        evidence=f"tool_name='{tool_name}' matches debug prefix",
                        remediation=(
                            "Remove debug and test tools from production "
                            "server configurations. Use feature flags or "
                            "build profiles to exclude development tools."
                        ),
                        tool_name=tool_name,
                        metadata={"match_type": "prefix"},
                    )
                )
                continue

            # Check descriptions for dev phrases
            if tool_desc:
                phrase = _has_dev_description(tool_desc)
                if phrase:
                    debug_tools.append(tool_name)
                    findings.append(
                        Finding(
                            rule_id="MCP09-003",
                            owasp_id="MCP09",
                            title=f"Debug/test tool exposed: '{tool_name}'",
                            description=(
                                f"Tool '{tool_name}' description contains "
                                f"development phrase '{phrase}'. Tools "
                                f"explicitly marked for development should "
                                f"not be exposed in production."
                            ),
                            severity=Severity.LOW,
                            evidence=(f"tool '{tool_name}' description contains '{phrase}'"),
                            remediation=(
                                "Remove development-only tools from production "
                                "server configurations."
                            ),
                            tool_name=tool_name,
                            metadata={"match_type": "description", "phrase": phrase},
                        )
                    )
                    continue

            # Check exact names — only suspicious in combination
            if tool_name.lower() in _SUSPICIOUS_EXACT_NAMES:
                # Don't emit individual finding for exact names alone;
                # they count toward the summary threshold
                debug_tools.append(tool_name)

        # Emit summary finding if 3+ debug/test tools found
        if len(debug_tools) >= 3:
            findings.append(
                Finding(
                    rule_id="MCP09-003",
                    owasp_id="MCP09",
                    title=(f"Multiple debug/test tools exposed ({len(debug_tools)} found)"),
                    description=(
                        f"Server exposes {len(debug_tools)} tools with "
                        f"debug/test characteristics: "
                        f"{', '.join(debug_tools)}. A high concentration "
                        f"of development tools strongly indicates a "
                        f"non-production deployment."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=(f"debug/test tools: {', '.join(debug_tools)}"),
                    remediation=(
                        "Audit all exposed tools and remove those intended "
                        "for development or testing. Use separate server "
                        "configurations for development and production."
                    ),
                    metadata={
                        "debug_tool_count": len(debug_tools),
                        "debug_tool_names": debug_tools,
                    },
                )
            )

        return findings

    def _check_governance_gap(self, context: ScanContext) -> list[Finding]:
        """Check for governance metadata gaps (MCP09-004).

        Flags servers that have a name (so MCP08-001 doesn't cover them)
        but no description while exposing 5+ tools. This combination
        indicates an unmanaged deployment with significant capability.

        Args:
            context: ScanContext with server_info and tools.

        Returns:
            List of Findings for governance gaps.
        """
        findings: list[Finding] = []
        server_info = context.server_info
        name = server_info.get("name", "")

        # Only fire if server has a name (otherwise MCP08-001 covers it)
        if not name:
            return findings

        description = server_info.get("description", "")
        tool_count = len(context.tools)

        if not description and tool_count >= 5:
            findings.append(
                Finding(
                    rule_id="MCP09-004",
                    owasp_id="MCP09",
                    title=(
                        f"Governance gap: {tool_count} tools exposed with no server description"
                    ),
                    description=(
                        f"Server '{name}' exposes {tool_count} tools but "
                        f"provides no description or documentation metadata. "
                        f"Servers with significant capabilities should have "
                        f"governance metadata for inventory management and "
                        f"security review."
                    ),
                    severity=Severity.LOW,
                    evidence=(
                        f"name='{name}', description='{description}', tool_count={tool_count}"
                    ),
                    remediation=(
                        "Add a description to the MCP server configuration "
                        "that documents its purpose, owner, and intended "
                        "deployment environment."
                    ),
                    metadata={
                        "server_name": name,
                        "tool_count": tool_count,
                    },
                )
            )

        return findings

    def _check_ephemeral_markers(self, context: ScanContext) -> list[Finding]:
        """Check for ephemeral deployment markers (MCP09-005).

        Looks for UUIDs, Docker-default hex hostnames, auto-generated
        versions, and timestamp-based names that suggest temporary or
        disposable deployments.

        Args:
            context: ScanContext with server_info.

        Returns:
            List of Findings for ephemeral markers.
        """
        findings: list[Finding] = []
        server_info = context.server_info
        name = server_info.get("name", "")
        version = server_info.get("version", "")

        if not name and not version:
            return findings

        markers = _has_ephemeral_markers(name or "", version or "")

        if markers:
            findings.append(
                Finding(
                    rule_id="MCP09-005",
                    owasp_id="MCP09",
                    title=(f"Ephemeral deployment marker: '{name}' (version: '{version}')"),
                    description=(
                        f"Server exhibits markers of a temporary or "
                        f"disposable deployment: {'; '.join(markers)}. "
                        f"Ephemeral deployments often lack security "
                        f"hardening, persistent logging, and access "
                        f"controls."
                    ),
                    severity=Severity.INFO,
                    evidence=f"markers: {'; '.join(markers)}",
                    remediation=(
                        "Use stable, meaningful server names and semantic "
                        "version strings for production deployments. Avoid "
                        "deploying auto-generated or temporary server "
                        "instances to production networks."
                    ),
                    metadata={
                        "markers": markers,
                        "server_name": name,
                        "server_version": version,
                    },
                )
            )

        return findings
