"""Scanner for context injection and over-sharing (MCP10).

Tests whether MCP servers leak session data, over-share context, or
expose information across sessions. Excessive context in responses,
session data leakage, and unscoped resources all increase the risk
of data exfiltration and cross-session information leaks.

Checks:
    MCP10-001: Excessive context in tool responses
    MCP10-002: Session data in tool responses
    MCP10-003: Error responses leak context
    MCP10-004: Resource over-exposure (no scoping)
    MCP10-005: Sensitive data in resource content

References:
    - OWASP MCP Top 10: MCP10 — Context Injection & Over-Sharing
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


# Patterns indicating session identifiers or internal state
# that should never appear in tool responses.
_SESSION_DATA_PATTERNS: list[tuple[str, str]] = [
    (r"session[_-]?id\s*[:=]\s*\S+", "Session ID"),
    (r"request[_-]?id\s*[:=]\s*\S+", "Request ID"),
    (r"trace[_-]?id\s*[:=]\s*\S+", "Trace ID"),
    (r"correlation[_-]?id\s*[:=]\s*\S+", "Correlation ID"),
    (r"internal[_-]?state\s*[:=]\s*\S+", "Internal state reference"),
    (r"thread[_-]?id\s*[:=]\s*\S+", "Thread ID"),
    (r"worker[_-]?id\s*[:=]\s*\S+", "Worker ID"),
    (r"transaction[_-]?id\s*[:=]\s*\S+", "Transaction ID"),
    (r"x-request-id\s*[:=]\s*\S+", "X-Request-ID header"),
]

# Patterns indicating credentials, PII, or internal identifiers
# in resource content.
_RESOURCE_SENSITIVE_PATTERNS: list[tuple[str, str]] = [
    # Credentials
    (r"(?:password|passwd|pwd)\s*[:=]\s*\S+", "Password"),
    (r"(?:api[_-]?key|apikey)\s*[:=]\s*\S+", "API key"),
    (r"(?:secret|token)\s*[:=]\s*\S+", "Secret/token"),
    (r"(?:Bearer|Basic)\s+[A-Za-z0-9+/=_-]{20,}", "Auth token"),
    (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private key"),
    (r"(?:sk|pk)[-_][a-zA-Z0-9]{20,}", "API key pattern"),
    # Connection strings
    (r"(?:DATABASE_URL|REDIS_URL|MONGO_URI)\s*[:=]\s*\S+", "Connection string"),
    (r"(?:postgres|mysql|mongodb)://\S+:\S+@\S+", "Database connection URI"),
    # PII
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email address"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern"),
    (r"\b(?:\d[ -]*?){13,16}\b", "Credit card number pattern"),
]

# Keywords suggesting a resource lacks session/user scoping.
_SCOPING_KEYWORDS: list[str] = [
    "user",
    "session",
    "tenant",
    "account",
    "org",
    "scope",
    "namespace",
    "owner",
]


def _find_session_data(text: str) -> list[dict[str, str]]:
    """Scan text for session identifiers and internal state.

    Args:
        text: Response text from a tool call.

    Returns:
        List of dicts with 'pattern' description and 'matched' text
        for each session data instance found.
    """
    findings: list[dict[str, str]] = []
    for pattern, description in _SESSION_DATA_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            matched = match.group(0)
            if len(matched) > 100:
                matched = matched[:97] + "..."
            findings.append({"pattern": description, "matched": matched})
    return findings


def _find_sensitive_in_resource(text: str) -> list[dict[str, str]]:
    """Scan resource content for credentials, PII, and internal identifiers.

    Args:
        text: Content of a resource.

    Returns:
        List of dicts with 'pattern' description and 'matched' text
        for each sensitive data instance found.
    """
    findings: list[dict[str, str]] = []
    for pattern, description in _RESOURCE_SENSITIVE_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            matched = match.group(0)
            # Redact most of the match for safety
            if len(matched) > 10:
                matched = matched[:5] + "..." + matched[-3:]
            findings.append({"pattern": description, "matched": matched})
    return findings


def _check_resource_scoping(resource: dict[str, Any]) -> bool:
    """Check whether a resource URI or description indicates session/user scoping.

    Args:
        resource: Resource dict with 'uri', 'name', and 'description' fields.

    Returns:
        True if the resource appears to be scoped to a user or session,
        False if it appears globally accessible.
    """
    uri = resource.get("uri", "").lower()
    name = resource.get("name", "").lower()
    description = resource.get("description", "").lower()
    combined = f"{uri} {name} {description}"
    return any(kw in combined for kw in _SCOPING_KEYWORDS)


def _compute_response_ratio(input_text: str, response_text: str) -> float:
    """Compute the ratio of response length to input length.

    A high ratio indicates the server returned significantly more data
    than the specificity of the input would warrant.

    Args:
        input_text: The serialized input arguments sent to the tool.
        response_text: The text content of the tool response.

    Returns:
        Ratio of response length to input length. Returns 0.0 if input
        is empty.
    """
    input_len = len(input_text)
    if input_len == 0:
        return 0.0
    return len(response_text) / input_len


def _build_minimal_args(tool: dict[str, Any]) -> dict[str, Any]:
    """Build minimal arguments for a tool to test response proportionality.

    Sends short, simple values for each parameter to create a baseline
    for evaluating whether the response is disproportionately large.

    Args:
        tool: Tool dict with 'inputSchema' field.

    Returns:
        Dict of argument names to minimal test values.
    """
    args: dict[str, Any] = {}
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})

    for param_name, param_schema in properties.items():
        param_type = param_schema.get("type", "string")
        if param_type == "string":
            args[param_name] = "test"
        elif param_type in ("integer", "number"):
            args[param_name] = 1
        elif param_type == "boolean":
            args[param_name] = True
        elif param_type == "array":
            args[param_name] = []
        elif param_type == "object":
            args[param_name] = {}
        else:
            args[param_name] = "test"

    return args


def _build_error_args(tool: dict[str, Any]) -> dict[str, Any]:
    """Build arguments designed to trigger error responses.

    Sends type-mismatched values to provoke error handling paths
    that may leak context from previous requests.

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
            args[param_name] = ""
        elif param_type in ("integer", "number"):
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


def _extract_response_text(result: Any) -> str:
    """Extract text content from an MCP tool call result.

    Args:
        result: The result from session.call_tool().

    Returns:
        Concatenated text content from the result.
    """
    response_text = ""
    if hasattr(result, "content"):
        for block in result.content:
            if hasattr(block, "text"):
                response_text += block.text
    elif isinstance(result, str):
        response_text = result
    return response_text


# Threshold for response-to-input ratio above which we flag excessive context.
_EXCESSIVE_RATIO_THRESHOLD = 50.0

# Minimum response length to consider for excessive context (avoids
# false positives on short responses with tiny inputs).
_MIN_RESPONSE_LENGTH = 500


class ContextSharingScanner(BaseScanner):
    """Scanner for context injection and over-sharing (MCP10).

    Checks tool responses for excessive data, session identifiers,
    and context leakage in errors. Also analyzes resources for
    over-exposure and sensitive data.

    Checks:
        MCP10-001: Excessive context in tool responses
        MCP10-002: Session data in tool responses
        MCP10-003: Error responses leak context
        MCP10-004: Resource over-exposure (no scoping)
        MCP10-005: Sensitive data in resource content

    Attributes:
        name: Scanner identifier used in CLI (--checks context_sharing).
        owasp_id: OWASP MCP Top 10 category.
        description: What this scanner tests.
    """

    name = "context_sharing"
    owasp_id = "MCP10"
    description = "Tests for context injection and over-sharing"

    async def scan(self, context: ScanContext) -> list[Finding]:
        """Run all context sharing checks.

        Static checks analyze resource metadata and content.
        Active checks call tools to inspect response behavior.

        Args:
            context: ScanContext with tools, resources, and session.

        Returns:
            List of Findings for context sharing issues.
        """
        findings: list[Finding] = []

        # Static checks on resources
        findings.extend(self._check_resource_scoping(context.resources))

        # Active checks — read resources for sensitive data
        if context.session and context.resources:
            for resource in context.resources:
                resource_findings = await self._check_resource_content(context, resource)
                findings.extend(resource_findings)

        # Active checks — call tools and analyze responses
        if context.session and context.tools:
            for tool in context.tools:
                findings.extend(await self._check_excessive_context(context, tool))
                findings.extend(await self._check_session_data_in_response(context, tool))
                findings.extend(await self._check_error_context_leakage(context, tool))

        return findings

    def _check_resource_scoping(
        self,
        resources: list[dict[str, Any]],
    ) -> list[Finding]:
        """Check whether resources have session or user scoping.

        Resources that are globally accessible without any scoping
        mechanism risk exposing one user's data to another.

        Args:
            resources: List of resource dicts from server enumeration.

        Returns:
            List of Findings for unscoped resources.
        """
        findings: list[Finding] = []

        for resource in resources:
            if not _check_resource_scoping(resource):
                uri = resource.get("uri", "unknown")
                name = resource.get("name", "unknown")
                findings.append(
                    Finding(
                        rule_id="MCP10-004",
                        owasp_id="MCP10",
                        title=f"Resource '{name}' has no access scoping",
                        description=(
                            f"Resource '{name}' (URI: {uri}) does not appear "
                            f"to be scoped to a user, session, or tenant. "
                            f"Globally accessible resources risk exposing data "
                            f"across sessions or users."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=f"URI '{uri}' contains no scoping identifiers",
                        remediation=(
                            "Scope resources to the current user or session. "
                            "Include user/session identifiers in resource URIs "
                            "and enforce access controls server-side."
                        ),
                        metadata={
                            "resource_uri": uri,
                            "resource_name": name,
                        },
                    )
                )

        return findings

    async def _check_resource_content(
        self,
        context: ScanContext,
        resource: dict[str, Any],
    ) -> list[Finding]:
        """Read a resource and check for sensitive data in its content.

        Args:
            context: ScanContext with active session.
            resource: Resource dict with URI and name.

        Returns:
            List of Findings for sensitive data in resource content.
        """
        findings: list[Finding] = []
        uri = resource.get("uri", "")
        name = resource.get("name", "unknown")

        try:
            result = await context.session.read_resource(uri)
            content_text = ""
            if hasattr(result, "contents"):
                for block in result.contents:
                    if hasattr(block, "text"):
                        content_text += block.text
            elif isinstance(result, str):
                content_text = result
        except Exception:
            # Cannot read resource — skip content check
            return findings

        if not content_text:
            return findings

        sensitive = _find_sensitive_in_resource(content_text)
        if sensitive:
            detail = "; ".join(f"{s['pattern']}: '{s['matched']}'" for s in sensitive[:3])
            if len(sensitive) > 3:
                detail += f" ... and {len(sensitive) - 3} more"

            severity = Severity.MEDIUM
            # Escalate to HIGH for credentials
            credential_types = {
                "Password",
                "API key",
                "Secret/token",
                "Auth token",
                "Private key",
                "API key pattern",
                "Connection string",
                "Database connection URI",
            }
            if any(s["pattern"] in credential_types for s in sensitive):
                severity = Severity.HIGH

            findings.append(
                Finding(
                    rule_id="MCP10-005",
                    owasp_id="MCP10",
                    title=f"Sensitive data in resource '{name}'",
                    description=(
                        f"Resource '{name}' (URI: {uri}) contains sensitive "
                        f"data: {detail}. Credentials, PII, and internal "
                        f"identifiers should not be exposed in resource content."
                    ),
                    severity=severity,
                    evidence=detail,
                    remediation=(
                        "Remove sensitive data from resource content. Use "
                        "server-side secret management and only expose "
                        "non-sensitive, user-appropriate data in resources."
                    ),
                    metadata={
                        "resource_uri": uri,
                        "sensitive_findings": sensitive,
                    },
                )
            )

        return findings

    async def _check_excessive_context(
        self,
        context: ScanContext,
        tool: dict[str, Any],
    ) -> list[Finding]:
        """Call a tool with minimal input and check for excessive response data.

        A disproportionately large response relative to a simple input
        suggests the tool is over-sharing context.

        Args:
            context: ScanContext with active session.
            tool: Tool dict with name and inputSchema.

        Returns:
            List of Findings for excessive context in responses.
        """
        findings: list[Finding] = []
        tool_name = tool.get("name", "unknown")
        minimal_args = _build_minimal_args(tool)
        input_text = str(minimal_args)

        try:
            result = await context.session.call_tool(tool_name, minimal_args)
            response_text = _extract_response_text(result)
        except Exception:
            return findings

        if not response_text or len(response_text) < _MIN_RESPONSE_LENGTH:
            return findings

        ratio = _compute_response_ratio(input_text, response_text)
        if ratio > _EXCESSIVE_RATIO_THRESHOLD:
            findings.append(
                Finding(
                    rule_id="MCP10-001",
                    owasp_id="MCP10",
                    title=f"Excessive context in '{tool_name}' response",
                    description=(
                        f"Tool '{tool_name}' returned {len(response_text)} "
                        f"characters in response to {len(input_text)} "
                        f"characters of input (ratio: {ratio:.1f}x). "
                        f"This suggests the tool returns significantly "
                        f"more data than requested."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=(
                        f"Response/input ratio: {ratio:.1f}x "
                        f"(threshold: {_EXCESSIVE_RATIO_THRESHOLD}x), "
                        f"response length: {len(response_text)}"
                    ),
                    remediation=(
                        "Limit tool responses to only the data requested. "
                        "Implement pagination or filtering to avoid "
                        "returning entire datasets for simple queries."
                    ),
                    tool_name=tool_name,
                    metadata={
                        "response_length": len(response_text),
                        "input_length": len(input_text),
                        "ratio": round(ratio, 1),
                    },
                )
            )

        return findings

    async def _check_session_data_in_response(
        self,
        context: ScanContext,
        tool: dict[str, Any],
    ) -> list[Finding]:
        """Call a tool and check for session identifiers in the response.

        Args:
            context: ScanContext with active session.
            tool: Tool dict with name and inputSchema.

        Returns:
            List of Findings for session data in tool responses.
        """
        findings: list[Finding] = []
        tool_name = tool.get("name", "unknown")
        minimal_args = _build_minimal_args(tool)

        try:
            result = await context.session.call_tool(tool_name, minimal_args)
            response_text = _extract_response_text(result)
        except Exception:
            return findings

        if not response_text:
            return findings

        session_data = _find_session_data(response_text)
        if session_data:
            detail = "; ".join(f"{s['pattern']}: '{s['matched']}'" for s in session_data[:3])
            if len(session_data) > 3:
                detail += f" ... and {len(session_data) - 3} more"

            findings.append(
                Finding(
                    rule_id="MCP10-002",
                    owasp_id="MCP10",
                    title=f"Session data in '{tool_name}' response",
                    description=(
                        f"Tool '{tool_name}' included session identifiers "
                        f"or internal state in its response: {detail}. "
                        f"Session data should not be exposed to clients."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=detail,
                    remediation=(
                        "Strip session identifiers, request IDs, and "
                        "internal state from tool responses. These values "
                        "are implementation details that aid attackers."
                    ),
                    tool_name=tool_name,
                    metadata={"session_data_findings": session_data},
                )
            )

        return findings

    async def _check_error_context_leakage(
        self,
        context: ScanContext,
        tool: dict[str, Any],
    ) -> list[Finding]:
        """Call a tool with error-triggering inputs and check for context leakage.

        Errors that contain data from previous requests or other sessions
        indicate cross-request context leakage.

        Args:
            context: ScanContext with active session.
            tool: Tool dict with name and inputSchema.

        Returns:
            List of Findings for context leakage in error responses.
        """
        findings: list[Finding] = []
        tool_name = tool.get("name", "unknown")
        error_args = _build_error_args(tool)

        try:
            result = await context.session.call_tool(tool_name, error_args)
            response_text = _extract_response_text(result)
        except Exception as exc:
            response_text = str(exc)

        if not response_text:
            return findings

        # Check for session data leaked in error responses
        session_data = _find_session_data(response_text)
        # Also check for sensitive data patterns in errors
        sensitive_data = _find_sensitive_in_resource(response_text)

        leaked_items = session_data + sensitive_data
        if leaked_items:
            detail = "; ".join(
                f"{item['pattern']}: '{item['matched']}'" for item in leaked_items[:3]
            )
            if len(leaked_items) > 3:
                detail += f" ... and {len(leaked_items) - 3} more"

            severity = Severity.MEDIUM
            # Escalate for credential leakage
            credential_types = {
                "Password",
                "API key",
                "Secret/token",
                "Auth token",
                "Private key",
                "API key pattern",
                "Connection string",
                "Database connection URI",
            }
            if any(item["pattern"] in credential_types for item in leaked_items):
                severity = Severity.HIGH

            findings.append(
                Finding(
                    rule_id="MCP10-003",
                    owasp_id="MCP10",
                    title=f"Error response leaks context in '{tool_name}'",
                    description=(
                        f"Tool '{tool_name}' leaked session data or "
                        f"sensitive information in its error response: "
                        f"{detail}. Error messages should not contain "
                        f"data from previous requests or other sessions."
                    ),
                    severity=severity,
                    evidence=detail,
                    remediation=(
                        "Sanitize error responses to remove session "
                        "identifiers, credentials, and data from other "
                        "requests. Return generic error messages to clients."
                    ),
                    tool_name=tool_name,
                    metadata={
                        "leaked_items": leaked_items,
                        "trigger_args": {k: str(v)[:50] for k, v in error_args.items()},
                    },
                )
            )

        return findings
