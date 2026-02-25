"""Scanner for insufficient audit and telemetry (MCP08).

Tests whether MCP servers provide adequate logging, monitoring,
and error handling capabilities. Without proper audit trails,
unauthorized actions go undetected and incident response is
impossible.

Checks:
    MCP08-001: Missing server identification (no name/version)
    MCP08-002: Error information disclosure (stack traces, paths)
    MCP08-003: No logging capability advertised
    MCP08-004: Sensitive data in error messages
    MCP08-005: Missing protocol version

References:
    - OWASP MCP Top 10: MCP08 — Lack of Audit and Telemetry
    - Microsoft Azure AI Security Guide
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


# Patterns indicating stack traces or internal implementation details
# in error messages. These should never be exposed to clients.
_ERROR_DISCLOSURE_PATTERNS: list[tuple[str, str]] = [
    # Python tracebacks
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"File \"[^\"]+\", line \d+", "Python file path with line number"),
    (r"raise \w+Error\(", "Python raise statement"),
    # File system paths
    (r"[A-Z]:\\[\w\\]+\.\w+", "Windows file path"),
    (r"/(?:home|usr|var|etc|opt|tmp)/[\w/]+\.\w+", "Unix file path"),
    (r"/app/[\w/]+\.\w+", "Container file path"),
    # Database errors
    (r"(?:SQL|sqlite|mysql|postgres|mongo)\w*Error", "Database error type"),
    (r"(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+[\w*]+\s+FROM", "SQL query fragment"),
    (r"relation \"[^\"]+\" does not exist", "PostgreSQL error"),
    # Internal implementation details
    (r"at \w+\.\w+\([\w.]+:\d+\)", "Java/JS stack frame"),
    (r"node_modules/[\w/@.-]+", "Node.js module path"),
    (r"site-packages/[\w/.-]+", "Python package path"),
    # Secret-adjacent patterns in errors
    (r"(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S+", "Credential in error"),
    (r"(?:DATABASE_URL|REDIS_URL|MONGO_URI)\s*[:=]", "Connection string in error"),
]

# Patterns indicating sensitive data that should never appear in errors
_SENSITIVE_DATA_PATTERNS: list[tuple[str, str]] = [
    (r"(?:Bearer|Basic)\s+[A-Za-z0-9+/=_-]{20,}", "Auth token in error"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email address in error"),
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "IP address in error"),
    (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private key in error"),
    (r"(?:sk|pk|api)[-_][a-zA-Z0-9]{20,}", "API key pattern in error"),
]


def _check_error_disclosure(error_text: str) -> list[dict[str, str]]:
    """Scan error text for information disclosure patterns.

    Args:
        error_text: Error message or traceback from the server.

    Returns:
        List of dicts with 'pattern' description and 'matched' text
        for each disclosure found.
    """
    findings: list[dict[str, str]] = []
    for pattern, description in _ERROR_DISCLOSURE_PATTERNS:
        match = re.search(pattern, error_text, re.IGNORECASE)
        if match:
            matched = match.group(0)
            if len(matched) > 100:
                matched = matched[:97] + "..."
            findings.append({"pattern": description, "matched": matched})
    return findings


def _check_sensitive_data(error_text: str) -> list[dict[str, str]]:
    """Scan error text for sensitive data exposure.

    Args:
        error_text: Error message from the server.

    Returns:
        List of dicts with 'pattern' description and 'matched' text
        for each sensitive data instance found.
    """
    findings: list[dict[str, str]] = []
    for pattern, description in _SENSITIVE_DATA_PATTERNS:
        match = re.search(pattern, error_text)
        if match:
            matched = match.group(0)
            # Redact most of the match for safety
            if len(matched) > 10:
                matched = matched[:5] + "..." + matched[-3:]
            findings.append({"pattern": description, "matched": matched})
    return findings


def _build_error_triggering_args(tool: dict[str, Any]) -> dict[str, Any]:
    """Build arguments designed to trigger error responses.

    Sends type-mismatched or boundary values to provoke error
    handling paths and expose verbose error messages.

    Args:
        tool: Tool dict with 'inputSchema' field.

    Returns:
        Dict of argument names to error-triggering values.
    """
    args: dict[str, Any] = {}
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})

    for param_name, param_schema in properties.items():
        param_type = param_schema.get("type", "string")
        if param_type == "string":
            # Extremely long string to trigger length validation errors
            args[param_name] = "A" * 10000
        elif param_type in ("integer", "number"):
            # Type mismatch — send string where number expected
            args[param_name] = "not_a_number"
        elif param_type == "boolean":
            args[param_name] = "not_a_boolean"
        elif param_type == "array":
            args[param_name] = "not_an_array"
        elif param_type == "object":
            args[param_name] = "not_an_object"
        else:
            args[param_name] = None

    return args


class AuditTelemetryScanner(BaseScanner):
    """Scanner for insufficient audit and telemetry (MCP08).

    Checks server identification, logging capabilities, error handling
    behavior, and information disclosure. Combines static analysis of
    server metadata with active error-triggering to test disclosure.

    Checks:
        MCP08-001: Missing server identification (name/version)
        MCP08-002: Error information disclosure (stack traces, paths)
        MCP08-003: No logging capability advertised
        MCP08-004: Sensitive data in error messages
        MCP08-005: Missing protocol version

    Attributes:
        name: Scanner identifier used in CLI (--checks audit_telemetry).
        owasp_id: OWASP MCP Top 10 category.
        description: What this scanner tests.
    """

    name = "audit_telemetry"
    owasp_id = "MCP08"
    description = "Tests for insufficient audit logging and telemetry"

    async def scan(self, context: ScanContext) -> list[Finding]:
        """Run all audit and telemetry checks.

        Static checks run against server_info. Active checks call
        tools with error-triggering inputs to test error handling.

        Args:
            context: ScanContext with server_info and tools list.

        Returns:
            List of Findings for audit/telemetry deficiencies.
        """
        findings: list[Finding] = []

        # Static checks on server metadata
        findings.extend(self._check_server_identification(context.server_info))
        findings.extend(self._check_protocol_version(context.server_info))
        findings.extend(self._check_logging_capability(context))

        # Active checks — trigger errors and analyze responses
        if context.session and context.tools:
            for tool in context.tools:
                error_findings = await self._check_error_disclosure(
                    context,
                    tool,
                )
                findings.extend(error_findings)

        return findings

    def _check_server_identification(
        self,
        server_info: dict[str, Any],
    ) -> list[Finding]:
        """Check if the server provides adequate identification.

        Servers without name and version information cannot be
        properly tracked in asset inventories or correlated with
        known vulnerabilities.

        Args:
            server_info: Server initialization metadata.

        Returns:
            List of Findings for missing identification fields.
        """
        findings: list[Finding] = []

        name = server_info.get("name", "")
        version = server_info.get("version", "")

        if not name:
            findings.append(
                Finding(
                    rule_id="MCP08-001",
                    owasp_id="MCP08",
                    title="Server does not identify itself",
                    description=(
                        "The MCP server did not provide a name in its "
                        "initialization response. Without server identification, "
                        "asset management, vulnerability tracking, and incident "
                        "response are impaired."
                    ),
                    severity=Severity.MEDIUM,
                    evidence="server_info.name is empty or missing",
                    remediation=(
                        "Configure the MCP server to return a meaningful name "
                        "in its initialization response. Use a consistent naming "
                        "convention across your server fleet."
                    ),
                    metadata={"server_info_keys": list(server_info.keys())},
                )
            )

        if not version:
            findings.append(
                Finding(
                    rule_id="MCP08-001",
                    owasp_id="MCP08",
                    title="Server does not report its version",
                    description=(
                        "The MCP server did not provide a version in its "
                        "initialization response. Without version information, "
                        "it is impossible to determine if the server is running "
                        "a known-vulnerable release."
                    ),
                    severity=Severity.MEDIUM,
                    evidence="server_info.version is empty or missing",
                    remediation=(
                        "Configure the MCP server to return a semantic version "
                        "string in its initialization response."
                    ),
                    metadata={"server_info_keys": list(server_info.keys())},
                )
            )

        return findings

    def _check_protocol_version(
        self,
        server_info: dict[str, Any],
    ) -> list[Finding]:
        """Check if the server reports its MCP protocol version.

        Args:
            server_info: Server initialization metadata.

        Returns:
            List containing a Finding if protocol version is missing.
        """
        protocol_version = server_info.get("protocolVersion", "")

        if not protocol_version:
            return [
                Finding(
                    rule_id="MCP08-005",
                    owasp_id="MCP08",
                    title="Server does not report protocol version",
                    description=(
                        "The MCP server did not report its protocol version. "
                        "Without this, clients cannot verify protocol "
                        "compatibility or detect downgrade attacks."
                    ),
                    severity=Severity.LOW,
                    evidence="server_info.protocolVersion is empty or missing",
                    remediation=(
                        "Ensure the server includes protocolVersion in its "
                        "initialization response per the MCP specification."
                    ),
                    metadata={"server_info_keys": list(server_info.keys())},
                )
            ]

        return []

    def _check_logging_capability(
        self,
        context: ScanContext,
    ) -> list[Finding]:
        """Check if the server advertises logging capabilities.

        The MCP specification defines a logging capability that
        servers can advertise. Servers without logging support
        provide no audit trail for tool invocations.

        Args:
            context: ScanContext with server_info and resources.

        Returns:
            List containing a Finding if no logging capability found.
        """
        # Check server capabilities for logging
        capabilities = context.server_info.get("capabilities", {})
        has_logging_capability = "logging" in capabilities

        # Check if any resources relate to logging/audit
        log_related_keywords = {"log", "audit", "trace", "monitor", "metric"}
        has_log_resources = any(
            any(
                kw in r.get("name", "").lower() or kw in r.get("description", "").lower()
                for kw in log_related_keywords
            )
            for r in context.resources
        )

        if not has_logging_capability and not has_log_resources:
            return [
                Finding(
                    rule_id="MCP08-003",
                    owasp_id="MCP08",
                    title="No logging capability advertised",
                    description=(
                        "The MCP server does not advertise logging capabilities "
                        "and exposes no logging-related resources. Without "
                        "server-side logging, tool invocations cannot be audited "
                        "and security incidents cannot be investigated."
                    ),
                    severity=Severity.MEDIUM,
                    evidence="No 'logging' in capabilities, no log-related resources",
                    remediation=(
                        "Implement the MCP logging capability to provide "
                        "structured audit logs. At minimum, log all tool "
                        "invocations with timestamps, arguments, caller "
                        "identity, and results."
                    ),
                    metadata={
                        "capabilities": list(capabilities.keys()),
                        "resource_count": len(context.resources),
                    },
                )
            ]

        return []

    async def _check_error_disclosure(
        self,
        context: ScanContext,
        tool: dict[str, Any],
    ) -> list[Finding]:
        """Call a tool with error-triggering inputs and analyze the response.

        Sends type-mismatched or boundary arguments to provoke error
        handling code paths, then checks if the error response contains
        stack traces, file paths, credentials, or other internal details.

        Args:
            context: ScanContext with active session.
            tool: Tool dict with name and inputSchema.

        Returns:
            List of Findings for information disclosure in errors.
        """
        findings: list[Finding] = []
        tool_name = tool.get("name", "unknown")
        error_args = _build_error_triggering_args(tool)

        try:
            result = await context.session.call_tool(tool_name, error_args)
            # Extract text from result — may be error or success
            response_text = ""
            if hasattr(result, "content"):
                for block in result.content:
                    if hasattr(block, "text"):
                        response_text += block.text
            elif isinstance(result, str):
                response_text = result
        except Exception as exc:
            # The exception message itself may disclose information
            response_text = str(exc)

        if not response_text:
            return findings

        # MCP08-002: Stack traces and implementation details
        disclosures = _check_error_disclosure(response_text)
        if disclosures:
            detail = "; ".join(f"{d['pattern']}: '{d['matched']}'" for d in disclosures[:3])
            if len(disclosures) > 3:
                detail += f" ... and {len(disclosures) - 3} more"

            findings.append(
                Finding(
                    rule_id="MCP08-002",
                    owasp_id="MCP08",
                    title=f"Error information disclosure in '{tool_name}'",
                    description=(
                        f"Tool '{tool_name}' exposed internal implementation "
                        f"details when called with error-triggering inputs: "
                        f"{detail}. This information aids attackers in "
                        f"understanding server architecture."
                    ),
                    severity=Severity.HIGH,
                    evidence=detail,
                    remediation=(
                        "Implement proper error handling that returns generic "
                        "error messages to clients. Log detailed errors "
                        "server-side only. Never expose stack traces, file "
                        "paths, or internal state in client-facing responses."
                    ),
                    tool_name=tool_name,
                    metadata={
                        "disclosures": disclosures,
                        "trigger_args": {k: str(v)[:50] for k, v in error_args.items()},
                    },
                )
            )

        # MCP08-004: Sensitive data in errors
        sensitive = _check_sensitive_data(response_text)
        if sensitive:
            detail = "; ".join(f"{s['pattern']}: '{s['matched']}'" for s in sensitive[:3])

            findings.append(
                Finding(
                    rule_id="MCP08-004",
                    owasp_id="MCP08",
                    title=f"Sensitive data in '{tool_name}' error response",
                    description=(
                        f"Tool '{tool_name}' exposed sensitive data in its "
                        f"error response: {detail}. Credentials, tokens, and "
                        f"personal data must never appear in error messages."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=detail,
                    remediation=(
                        "Sanitize all error responses before returning to "
                        "clients. Strip credentials, tokens, email addresses, "
                        "and internal identifiers from error messages."
                    ),
                    tool_name=tool_name,
                    metadata={"sensitive_findings": sensitive},
                )
            )

        return findings
