"""Authentication & Authorization scanner (MCP07).

Tests MCP servers for insufficient authentication and authorization
controls. Checks whether servers allow unauthenticated enumeration
and tool invocation, use unencrypted transports, or run on well-known
ports without auth.

Maps to: OWASP MCP Top 10 — MCP07: Insufficient Authentication & Authorization

CVE reference: CVE-2025-49596 (MCP Inspector — no auth, 0.0.0.0, CSRF)
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from counteragent.audit.scanner.base import BaseScanner, Finding, ScanContext, Severity

logger = logging.getLogger("counteragent.audit.scanner.auth")

# Well-known MCP ports that attackers and automated scanners target.
# Servers on these ports without auth are especially exposed.
_WELL_KNOWN_MCP_PORTS: dict[int, str] = {
    6274: "MCP Inspector (default)",
    6277: "MCP Inspector (alternate)",
    3001: "MCP Inspector (web UI)",
}

# Keywords in tool names/descriptions that indicate sensitive operations.
# Used to escalate severity when unauthenticated access reaches high-value tools.
_SENSITIVE_KEYWORDS: set[str] = {
    "secret",
    "password",
    "credential",
    "token",
    "key",
    "auth",
    "admin",
    "config",
    "database",
    "query",
    "execute",
    "shell",
    "file",
    "read",
    "write",
    "delete",
    "deploy",
    "user",
    "permission",
    "role",
}


def _classify_tool_sensitivity(tool: dict[str, Any]) -> bool:
    """Check if a tool's name or description suggests sensitive operations.

    Args:
        tool: Tool dict from ScanContext.tools containing 'name' and
            'description' fields.

    Returns:
        True if the tool name or description contains sensitive keywords,
        indicating it handles privileged operations that should require
        authentication.
    """
    name = tool.get("name", "").lower()
    desc = tool.get("description", "").lower()
    combined = f"{name} {desc}"
    return any(kw in combined for kw in _SENSITIVE_KEYWORDS)


def _extract_url_components(url: str) -> dict[str, Any]:
    """Parse a connection URL into security-relevant components.

    Args:
        url: The server URL (e.g., 'http://0.0.0.0:6274/sse').

    Returns:
        Dict with 'scheme', 'hostname', 'port', and 'is_tls' fields.
        Returns empty dict if URL is None or unparseable.
    """
    try:
        parsed = urlparse(url)
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        return {
            "scheme": parsed.scheme,
            "hostname": parsed.hostname or "",
            "port": port,
            "is_tls": parsed.scheme == "https",
        }
    except Exception:
        return {}


class AuthScanner(BaseScanner):
    """Scanner for authentication and authorization weaknesses (MCP07).

    Checks whether the MCP server:
    - Allows unauthenticated capability enumeration
    - Permits unauthenticated tool invocation
    - Uses unencrypted transport (HTTP without TLS)
    - Runs on well-known MCP ports without authentication

    Unlike the injection scanner which tests per-tool parameters, this
    scanner evaluates connection-level security properties.

    Attributes:
        name: Scanner identifier used in CLI (--checks auth).
        owasp_id: OWASP MCP Top 10 category.
        description: What this scanner tests.
    """

    name = "auth"
    owasp_id = "MCP07"
    description = "Tests for insufficient authentication and authorization"

    async def scan(self, context: ScanContext) -> list[Finding]:
        """Run all authentication checks against the target server.

        Args:
            context: ScanContext with server metadata, tools list,
                transport type, and optional connection URL.

        Returns:
            List of Findings for each authentication weakness detected.
        """
        findings: list[Finding] = []

        # Check 1: Unauthenticated enumeration
        finding = self._check_unauth_enumeration(context)
        if finding:
            findings.append(finding)

        # Check 2: Unauthenticated tool invocation
        finding = await self._check_unauth_invocation(context)
        if finding:
            findings.append(finding)

        # Check 3: Transport encryption (HTTP-based transports only)
        finding = self._check_transport_encryption(context)
        if finding:
            findings.append(finding)

        # Check 4: Well-known port detection (HTTP-based transports only)
        finding = self._check_default_port(context)
        if finding:
            findings.append(finding)

        return findings

    def _check_unauth_enumeration(self, context: ScanContext) -> Finding | None:
        """Check if the server allows unauthenticated capability enumeration.

        If we connected without credentials and successfully discovered
        tools, resources, or prompts, the server lacks enumeration controls.

        Args:
            context: ScanContext with tools, resources, and prompts lists.

        Returns:
            A Finding if unauthenticated enumeration succeeded, None otherwise.
        """
        total_capabilities = len(context.tools) + len(context.resources) + len(context.prompts)

        if total_capabilities == 0:
            logger.debug("No capabilities discovered — skipping unauth enum check")
            return None

        sensitive_tools = [t for t in context.tools if _classify_tool_sensitivity(t)]
        sensitive_names = [t.get("name", "unknown") for t in sensitive_tools]

        description = (
            f"Server allows unauthenticated enumeration of capabilities: "
            f"{len(context.tools)} tools, {len(context.resources)} resources, "
            f"{len(context.prompts)} prompts discovered without providing credentials."
        )
        if sensitive_tools:
            description += (
                f" {len(sensitive_tools)} tool(s) appear to handle sensitive operations: "
                f"{', '.join(sensitive_names)}."
            )

        # Severity depends on transport: stdio is local subprocess with no
        # network exposure, so auth findings are informational only.
        if context.transport_type == "stdio":
            severity = Severity.INFO
            description += (
                " Note: This server uses stdio transport (local subprocess), "
                "which has no network exposure. Authentication is typically "
                "enforced at the application level, not the transport level."
            )
        elif sensitive_tools:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        transport_note = (
            "stdio (local subprocess, no network exposure)"
            if context.transport_type == "stdio"
            else None
        )

        return Finding(
            rule_id="MCP07-001",
            owasp_id="MCP07",
            title="Unauthenticated capability enumeration",
            description=description,
            severity=severity,
            evidence=(
                f"Enumerated {total_capabilities} capabilities via "
                f"{context.transport_type} without authentication"
            ),
            remediation=(
                "Require authentication tokens or API keys before allowing "
                "capability enumeration. For stdio servers launched as "
                "subprocesses, authentication is typically managed by the "
                "client application. Consider restricting which tools are "
                "exposed based on the calling context. For HTTP servers, "
                "require Bearer tokens or OAuth credentials on all endpoints."
            ),
            metadata={
                "tools_count": len(context.tools),
                "resources_count": len(context.resources),
                "prompts_count": len(context.prompts),
                "sensitive_tools": sensitive_names,
                "transport": context.transport_type,
                "transport_note": transport_note,
            },
        )

    async def _check_unauth_invocation(self, context: ScanContext) -> Finding | None:
        """Check if tools can be invoked without authentication.

        Attempts to call a tool on the server. If the call succeeds
        (returns any result without auth error), the server allows
        unauthenticated tool execution.

        Picks the first available tool and uses minimal safe arguments
        to avoid side effects.

        Args:
            context: ScanContext with tools list and active session.

        Returns:
            A Finding if unauthenticated invocation succeeded, None otherwise.
        """
        if not context.tools or context.session is None:
            logger.debug("No tools or session — skipping unauth invocation check")
            return None

        # Pick the first tool to test
        tool = context.tools[0]
        tool_name = tool.get("name", "unknown")

        # Build minimal safe arguments
        args = self._build_safe_args(tool)

        try:
            result = await context.session.call_tool(tool_name, args)
            # If we got here without an auth error, invocation succeeded
            response_text = ""
            for block in getattr(result, "content", []):
                if hasattr(block, "text"):
                    response_text += block.text

            is_sensitive = _classify_tool_sensitivity(tool)

            description = (
                f"Tool '{tool_name}' was successfully called without "
                f"providing authentication credentials. "
                f"{'This tool appears to handle sensitive operations.' if is_sensitive else ''}"
            )

            # Severity depends on transport: stdio has no network exposure.
            if context.transport_type == "stdio":
                severity = Severity.INFO
                description += (
                    " Note: This server uses stdio transport (local subprocess), "
                    "which has no network exposure. The client process already "
                    "has full control over the server."
                )
            elif is_sensitive:
                severity = Severity.CRITICAL
            else:
                severity = Severity.HIGH

            transport_note = (
                "stdio (local subprocess, no network exposure)"
                if context.transport_type == "stdio"
                else None
            )

            logger.warning(
                "UNAUTH INVOCATION: %s callable without authentication",
                tool_name,
            )
            return Finding(
                rule_id="MCP07-002",
                owasp_id="MCP07",
                title=f"Unauthenticated tool invocation: '{tool_name}'",
                description=description,
                severity=severity,
                evidence=(
                    f"Tool '{tool_name}' returned a response "
                    f"({len(response_text)} chars) without authentication"
                ),
                remediation=(
                    "Implement authentication checks before tool execution. "
                    "Verify caller identity and authorization for each tool "
                    "invocation, not just at connection time."
                ),
                tool_name=tool_name,
                metadata={
                    "tool_tested": tool_name,
                    "response_length": len(response_text),
                    "is_sensitive": is_sensitive,
                    "transport": context.transport_type,
                    "transport_note": transport_note,
                },
            )

        except Exception as exc:
            error_str = str(exc).lower()
            # Check if the error is auth-related (good — server enforces auth)
            auth_indicators = ["auth", "unauthorized", "forbidden", "401", "403", "credential"]
            if any(indicator in error_str for indicator in auth_indicators):
                logger.info(
                    "Tool %s rejected unauthenticated call — auth enforced",
                    tool_name,
                )
                return None

            # Non-auth error — tool call failed for other reasons
            logger.debug(
                "Tool %s call failed (non-auth): %s",
                tool_name,
                exc,
            )
            return None

    def _check_transport_encryption(self, context: ScanContext) -> Finding | None:
        """Check if HTTP-based transports use TLS encryption.

        Unencrypted HTTP connections expose authentication tokens,
        tool arguments, and response data to network-level attackers.

        Args:
            context: ScanContext with transport_type and connection_url.

        Returns:
            A Finding if transport is unencrypted, None otherwise.
        """
        if context.transport_type == "stdio":
            # stdio is a local process — encryption is not applicable
            return None

        if not context.connection_url:
            logger.debug("No connection URL available — skipping TLS check")
            return None

        components = _extract_url_components(context.connection_url)
        if not components:
            return None

        if components["is_tls"]:
            logger.info("Transport uses TLS — encryption check passed")
            return None

        logger.warning("UNENCRYPTED TRANSPORT: %s", context.connection_url)
        return Finding(
            rule_id="MCP07-003",
            owasp_id="MCP07",
            title="Unencrypted MCP transport",
            description=(
                f"Server is accessible over unencrypted HTTP "
                f"({components['scheme']}://{components['hostname']}:{components['port']}). "
                f"Authentication tokens, tool arguments, and responses are visible "
                f"to network-level attackers."
            ),
            severity=Severity.HIGH,
            evidence=f"Connection URL scheme: {components['scheme']}",
            remediation=(
                "Enable TLS (HTTPS) on the MCP server endpoint. Use valid "
                "certificates and enforce HTTPS-only connections. For local "
                "development, use self-signed certificates or restrict binding "
                "to localhost (127.0.0.1)."
            ),
            metadata={
                "url": context.connection_url,
                "scheme": components["scheme"],
                "hostname": components["hostname"],
                "port": components["port"],
            },
        )

    def _check_default_port(self, context: ScanContext) -> Finding | None:
        """Check if the server runs on a well-known MCP port without auth.

        Well-known ports are targeted by automated scanners and attackers.
        Running unauthenticated services on these ports increases exposure.

        Args:
            context: ScanContext with connection_url.

        Returns:
            A Finding if server uses a well-known MCP port, None otherwise.
        """
        if context.transport_type == "stdio":
            return None

        if not context.connection_url:
            return None

        components = _extract_url_components(context.connection_url)
        if not components:
            return None

        port = components["port"]
        if port not in _WELL_KNOWN_MCP_PORTS:
            return None

        port_desc = _WELL_KNOWN_MCP_PORTS[port]

        logger.warning("DEFAULT PORT: %d (%s)", port, port_desc)
        return Finding(
            rule_id="MCP07-004",
            owasp_id="MCP07",
            title=f"Well-known MCP port {port} without authentication",
            description=(
                f"Server is running on port {port} ({port_desc}), "
                f"a well-known MCP port targeted by automated scanners. "
                f"Combined with no authentication, this makes the server "
                f"trivially discoverable and exploitable."
            ),
            severity=Severity.MEDIUM,
            evidence=f"Server port: {port} (known as: {port_desc})",
            remediation=(
                "Use a non-default port for production MCP servers, or "
                "ensure authentication is required before any operations. "
                "Consider binding to 127.0.0.1 if only local access is needed."
            ),
            metadata={
                "port": port,
                "port_description": port_desc,
            },
        )

    @staticmethod
    def _build_safe_args(tool: dict[str, Any]) -> dict[str, Any]:
        """Build minimal safe arguments for a tool invocation test.

        Uses harmless default values for each parameter type to test
        whether the tool can be called, without causing side effects.

        Args:
            tool: Tool dict from ScanContext.tools.

        Returns:
            Dict of parameter name -> safe default value.
        """
        safe_defaults: dict[str, Any] = {
            "string": "test",
            "integer": 1,
            "number": 1.0,
            "boolean": True,
            "array": [],
            "object": {},
        }

        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})
        args: dict[str, Any] = {}

        for name, prop in properties.items():
            param_type = prop.get("type", "string")
            args[name] = safe_defaults.get(param_type, "test")

        return args
