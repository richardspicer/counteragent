"""Scanner for token mismanagement and secret exposure (MCP01).

Tests whether MCP servers leak credentials, API keys, and secrets
through tool parameter schemas, tool responses, error messages, or
environment variable exposure. Secrets flowing through tool calls
increase the risk of credential theft and unauthorized access.

Checks:
    MCP01-001: Sensitive parameter names in tool schemas
    MCP01-002: Secret patterns in tool responses
    MCP01-003: Secrets in error responses
    MCP01-004: Environment variable leakage

References:
    - OWASP MCP Top 10: MCP01 — Token Mismanagement & Secret Exposure
"""

from __future__ import annotations

import logging
import re
from typing import Any

from counteragent.audit.scanner.base import (
    BaseScanner,
    Finding,
    ScanContext,
    Severity,
)

logger = logging.getLogger(__name__)


# Parameter names that indicate secrets flowing through tool calls.
# Matched case-insensitively with underscore/hyphen normalization.
_SENSITIVE_PARAM_NAMES: list[str] = [
    "token",
    "api_key",
    "apikey",
    "secret",
    "password",
    "passwd",
    "pwd",
    "credential",
    "auth",
    "auth_token",
    "access_token",
    "private_key",
    "connection_string",
]

# Known secret patterns with descriptions.
# Each tuple is (compiled regex, description).
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT"),
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "OpenAI API key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub PAT"),
    (re.compile(r"gho_[a-zA-Z0-9]{36}"), "GitHub OAuth token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key"),
    (
        re.compile(
            r"(?:aws_secret|AWS_SECRET)[_A-Z]*\s*[:=]\s*[A-Za-z0-9/+=]{20,}",
            re.IGNORECASE,
        ),
        "AWS Secret Key",
    ),
    (re.compile(r"xoxb-[0-9]{10,}-[a-zA-Z0-9]+"), "Slack bot token"),
    (re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{20,}"), "Bearer token"),
    (
        re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*[A-Za-z0-9_-]{20,}", re.IGNORECASE),
        "Generic API key assignment",
    ),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "Private key header"),
]

# Environment variable names that suggest secrets.
_SECRET_ENV_NAMES: list[str] = [
    "DATABASE_URL",
    "REDIS_URL",
    "MONGO_URI",
    "SECRET_KEY",
    "JWT_SECRET",
    "ENCRYPTION_KEY",
    "DB_PASSWORD",
    "API_SECRET",
    "AWS_SECRET_ACCESS_KEY",
    "PRIVATE_KEY",
]

# Pattern to detect env var assignments like KEY=value.
_ENV_VAR_PATTERN = re.compile(r"([A-Z][A-Z0-9_]{2,})=(\S+)")


def _normalize_param_name(name: str) -> str:
    """Normalize a parameter name for comparison.

    Converts to lowercase and replaces hyphens with underscores.

    Args:
        name: Parameter name from a tool schema.

    Returns:
        Normalized parameter name.
    """
    return name.lower().replace("-", "_")


def _find_sensitive_params(tool: dict[str, Any]) -> list[str]:
    """Find parameter names that suggest secrets in a tool's input schema.

    Args:
        tool: Tool dict with 'inputSchema' field.

    Returns:
        List of parameter names matching sensitive patterns.
    """
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})
    matches: list[str] = []

    for param_name in properties:
        normalized = _normalize_param_name(param_name)
        if normalized in _SENSITIVE_PARAM_NAMES:
            matches.append(param_name)

    return matches


def _find_secret_patterns(text: str) -> list[dict[str, str]]:
    """Scan text for known secret patterns.

    Args:
        text: Response text to scan for secrets.

    Returns:
        List of dicts with 'pattern' description and 'matched' (redacted)
        text for each secret found.
    """
    findings: list[dict[str, str]] = []
    for pattern, description in _SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            matched = match.group(0)
            redacted = _redact_secret(matched)
            findings.append({"pattern": description, "matched": redacted})
    return findings


def _redact_secret(value: str) -> str:
    """Redact a secret value, showing only first 5 and last 3 characters.

    Args:
        value: The secret value to redact.

    Returns:
        Redacted string with middle characters replaced by '***'.
    """
    if len(value) <= 8:
        return value[:3] + "***"
    return value[:5] + "***" + value[-3:]


def _find_env_var_leakage(text: str) -> list[dict[str, Any]]:
    """Scan text for environment variable patterns that suggest secret leakage.

    Args:
        text: Response text to scan.

    Returns:
        List of dicts with 'name', 'value' (redacted), and 'is_secret'
        for each env var found.
    """
    findings: list[dict[str, Any]] = []
    seen_names: set[str] = set()

    for match in _ENV_VAR_PATTERN.finditer(text):
        name = match.group(1)
        value = match.group(2)

        if name in seen_names:
            continue
        seen_names.add(name)

        # Check if this env var name suggests a secret
        is_secret = name in _SECRET_ENV_NAMES or any(
            kw in name for kw in ("SECRET", "PASSWORD", "KEY", "TOKEN", "CREDENTIAL")
        )

        if is_secret:
            # Also check if the value itself matches a known secret pattern
            value_is_secret = bool(_find_secret_patterns(value))
            findings.append(
                {
                    "name": name,
                    "value": _redact_secret(value),
                    "is_secret": True,  # nosec B105
                    "value_matches_secret_pattern": value_is_secret,
                }
            )

    return findings


def _build_minimal_args(tool: dict[str, Any]) -> dict[str, Any]:
    """Build minimal arguments for a tool call.

    Sends short, simple values for each parameter to create a baseline
    for evaluating tool responses.

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
    that may leak secrets.

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


class TokenExposureScanner(BaseScanner):
    """Scanner for token mismanagement and secret exposure (MCP01).

    Checks tool schemas for sensitive parameter names, scans tool
    responses for leaked secrets and credentials, inspects error
    responses for secret leakage, and detects environment variable
    exposure.

    Checks:
        MCP01-001: Sensitive parameter names in tool schemas
        MCP01-002: Secret patterns in tool responses
        MCP01-003: Secrets in error responses
        MCP01-004: Environment variable leakage

    Attributes:
        name: Scanner identifier used in CLI (--checks token_exposure).
        owasp_id: OWASP MCP Top 10 category.
        description: What this scanner tests.
    """

    name = "token_exposure"
    owasp_id = "MCP01"
    description = "Tests for token mismanagement and secret exposure"

    async def scan(self, context: ScanContext) -> list[Finding]:
        """Run all token exposure checks.

        Static checks analyze tool input schemas for sensitive parameters.
        Active checks call tools to inspect responses for leaked secrets.

        Args:
            context: ScanContext with tools and session.

        Returns:
            List of Findings for token exposure issues.
        """
        findings: list[Finding] = []

        # Static check — sensitive parameter names
        for tool in context.tools:
            findings.extend(self._check_sensitive_params(tool))

        # Active checks — call tools and analyze responses
        if context.session and context.tools:
            for tool in context.tools:
                findings.extend(await self._check_secrets_in_response(context, tool))
                findings.extend(await self._check_secrets_in_errors(context, tool))

        return findings

    def _check_sensitive_params(self, tool: dict[str, Any]) -> list[Finding]:
        """Check tool input schemas for parameter names that suggest secrets.

        Parameters named things like 'api_key', 'password', or 'token'
        indicate that secrets are flowing through tool calls, which
        increases exposure risk.

        Args:
            tool: Tool dict with name and inputSchema.

        Returns:
            List of Findings for sensitive parameter names.
        """
        findings: list[Finding] = []
        tool_name = tool.get("name", "unknown")
        sensitive_params = _find_sensitive_params(tool)

        if sensitive_params:
            param_list = ", ".join(f"'{p}'" for p in sensitive_params)
            findings.append(
                Finding(
                    rule_id="MCP01-001",
                    owasp_id="MCP01",
                    title=f"Sensitive parameter names in '{tool_name}'",
                    description=(
                        f"Tool '{tool_name}' has parameters that suggest "
                        f"secrets flowing through tool calls: {param_list}. "
                        f"Secrets in tool parameters risk exposure through "
                        f"logging, caching, or client-side storage."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Sensitive parameters: {param_list}",
                    remediation=(
                        "Avoid passing secrets through tool parameters. "
                        "Use server-side credential management (environment "
                        "variables, vault services) and reference secrets "
                        "by identifier rather than value."
                    ),
                    tool_name=tool_name,
                    metadata={
                        "sensitive_params": sensitive_params,
                    },
                )
            )

        return findings

    async def _check_secrets_in_response(
        self,
        context: ScanContext,
        tool: dict[str, Any],
    ) -> list[Finding]:
        """Call a tool and scan the response for leaked secrets.

        Args:
            context: ScanContext with active session.
            tool: Tool dict with name and inputSchema.

        Returns:
            List of Findings for secrets in tool responses.
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

        # Check for known secret patterns
        secret_matches = _find_secret_patterns(response_text)
        if secret_matches:
            detail = "; ".join(f"{s['pattern']}: '{s['matched']}'" for s in secret_matches[:3])
            if len(secret_matches) > 3:
                detail += f" ... and {len(secret_matches) - 3} more"

            findings.append(
                Finding(
                    rule_id="MCP01-002",
                    owasp_id="MCP01",
                    title=f"Secret patterns in '{tool_name}' response",
                    description=(
                        f"Tool '{tool_name}' returned content matching "
                        f"known secret patterns: {detail}. Credentials "
                        f"in tool responses can be captured by malicious "
                        f"clients or logged insecurely."
                    ),
                    severity=Severity.HIGH,
                    evidence=detail,
                    remediation=(
                        "Never include credentials, API keys, or tokens "
                        "in tool responses. Use server-side secret "
                        "management and only return non-sensitive data."
                    ),
                    tool_name=tool_name,
                    metadata={"secret_findings": secret_matches},
                )
            )

        # Check for env var leakage in normal responses
        env_findings = _find_env_var_leakage(response_text)
        if env_findings:
            findings.extend(self._build_env_var_findings(tool_name, env_findings))

        return findings

    async def _check_secrets_in_errors(
        self,
        context: ScanContext,
        tool: dict[str, Any],
    ) -> list[Finding]:
        """Call a tool with error-triggering inputs and scan for leaked secrets.

        Args:
            context: ScanContext with active session.
            tool: Tool dict with name and inputSchema.

        Returns:
            List of Findings for secrets in error responses.
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

        # Check for known secret patterns in error output
        secret_matches = _find_secret_patterns(response_text)
        if secret_matches:
            detail = "; ".join(f"{s['pattern']}: '{s['matched']}'" for s in secret_matches[:3])
            if len(secret_matches) > 3:
                detail += f" ... and {len(secret_matches) - 3} more"

            findings.append(
                Finding(
                    rule_id="MCP01-003",
                    owasp_id="MCP01",
                    title=f"Secrets in '{tool_name}' error response",
                    description=(
                        f"Tool '{tool_name}' leaked secret patterns in "
                        f"its error response: {detail}. Error messages "
                        f"that contain credentials enable credential "
                        f"harvesting through deliberate error triggering."
                    ),
                    severity=Severity.HIGH,
                    evidence=detail,
                    remediation=(
                        "Sanitize error responses to remove all "
                        "credentials, API keys, and tokens. Return "
                        "generic error messages to clients."
                    ),
                    tool_name=tool_name,
                    metadata={
                        "secret_findings": secret_matches,
                        "trigger_args": {k: str(v)[:50] for k, v in error_args.items()},
                    },
                )
            )

        # Check for env var leakage in error responses
        env_findings = _find_env_var_leakage(response_text)
        if env_findings:
            findings.extend(self._build_env_var_findings(tool_name, env_findings))

        return findings

    def _build_env_var_findings(
        self,
        tool_name: str,
        env_findings: list[dict[str, Any]],
    ) -> list[Finding]:
        """Build findings for environment variable leakage.

        Severity is MEDIUM for generic env vars, escalated to HIGH
        if the value matches a known secret pattern.

        Args:
            tool_name: Name of the tool that leaked env vars.
            env_findings: List of env var dicts from _find_env_var_leakage.

        Returns:
            List of Findings for env var leakage.
        """
        findings: list[Finding] = []

        names = [e["name"] for e in env_findings]
        detail = "; ".join(f"{e['name']}={e['value']}" for e in env_findings[:3])
        if len(env_findings) > 3:
            detail += f" ... and {len(env_findings) - 3} more"

        # Escalate to HIGH if any value matches a secret pattern
        severity = Severity.MEDIUM
        if any(e.get("value_matches_secret_pattern") for e in env_findings):
            severity = Severity.HIGH

        findings.append(
            Finding(
                rule_id="MCP01-004",
                owasp_id="MCP01",
                title=f"Environment variable leakage in '{tool_name}'",
                description=(
                    f"Tool '{tool_name}' exposed environment variables "
                    f"containing secrets: {detail}. Environment variables "
                    f"with credentials should never appear in tool output."
                ),
                severity=severity,
                evidence=detail,
                remediation=(
                    "Do not expose environment variables in tool "
                    "responses or error messages. Use structured "
                    "error handling that strips internal configuration."
                ),
                tool_name=tool_name,
                metadata={
                    "env_var_names": names,
                    "env_findings": env_findings,
                },
            )
        )

        return findings
