"""Command Injection scanner (MCP05).

Tests MCP tool parameters for command injection vulnerabilities by
injecting payloads with canary markers and checking if they appear
in tool responses, indicating the input reached a shell.

Also detects argument injection (CWE-88) and path traversal (CWE-22)
using pattern-matching and error-based detection modes.

Maps to: OWASP MCP Top 10 — MCP05: Command Injection via Tools
"""

from __future__ import annotations

import logging
import re
from typing import Any

from counteragent.audit.payloads.injection import InjectionPayload, get_injection_payloads
from counteragent.audit.scanner.base import BaseScanner, Finding, ScanContext, Severity

logger = logging.getLogger("counteragent.audit.scanner.injection")

# CWE mapping for rule_id generation based on technique prefix.
_TECHNIQUE_CWE: dict[str, str] = {
    "flag_injection": "CWE88",
    "short_flag": "CWE88",
    "path_traversal": "CWE22",
}


def _cwe_for_technique(technique: str) -> str:
    """Determine the CWE identifier for a given technique name.

    Args:
        technique: The payload technique name (e.g., 'flag_injection_help').

    Returns:
        CWE string like 'CWE78', 'CWE88', or 'CWE22'.
    """
    for prefix, cwe in _TECHNIQUE_CWE.items():
        if technique.startswith(prefix):
            return cwe
    return "CWE78"


# Default safe values for non-target parameters so the tool
# call has a reasonable chance of executing.
_SAFE_DEFAULTS: dict[str, Any] = {
    "string": "test",
    "integer": 1,
    "number": 1.0,
    "boolean": True,
    "array": [],
    "object": {},
}

# Remediation text per CWE.
_REMEDIATION: dict[str, str] = {
    "CWE78": (
        "Never pass user-controlled input to shell commands. "
        "Use parameterized APIs (e.g., subprocess with shell=False "
        "and explicit argument lists) instead of string interpolation."
    ),
    "CWE88": (
        "Validate that user-supplied arguments do not start with '-' or '--'. "
        "Use '--' as an argument separator before user input to prevent flag "
        "interpretation (e.g., ['git', 'diff', '--', user_ref])."
    ),
    "CWE22": (
        "Validate and canonicalize file paths before use. Reject paths containing "
        "'..', URL-encoded traversal sequences, or absolute paths. Use "
        "os.path.realpath() and verify the resolved path stays within the "
        "allowed base directory."
    ),
}


def _get_string_params(tool: dict[str, Any]) -> list[str]:
    """Extract names of string-type parameters from a tool's input schema.

    Args:
        tool: Tool dict from ScanContext.tools.

    Returns:
        List of parameter names that accept string input.
    """
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})
    return [name for name, prop in properties.items() if prop.get("type") == "string"]


def _build_args(
    tool: dict[str, Any],
    target_param: str,
    inject_value: str,
) -> dict[str, Any]:
    """Build a tool argument dict with one parameter injected.

    Sets the target parameter to the injection payload and fills
    all other parameters with safe defaults based on their types.

    Args:
        tool: Tool dict from ScanContext.tools.
        target_param: The parameter to inject into.
        inject_value: The injection payload string.

    Returns:
        Dict of parameter name -> value, ready for call_tool().
    """
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})
    args: dict[str, Any] = {}

    for name, prop in properties.items():
        if name == target_param:
            args[name] = inject_value
        else:
            param_type = prop.get("type", "string")
            args[name] = _SAFE_DEFAULTS.get(param_type, "test")

    return args


def _extract_text(result: Any) -> str:
    """Extract text content from an MCP call_tool result.

    The MCP SDK returns results with a .content list containing
    TextContent, ImageContent, etc. We extract all text parts.

    Args:
        result: The CallToolResult from session.call_tool().

    Returns:
        Concatenated text content from the result.
    """
    if result is None:
        return ""

    parts: list[str] = []
    for block in getattr(result, "content", []):
        if hasattr(block, "text"):
            parts.append(block.text)
    return "\n".join(parts)


def _check_pattern_match(response_text: str, payload: InjectionPayload) -> str | None:
    """Check if any response_patterns regex matches the response text.

    Args:
        response_text: The tool's response text.
        payload: The payload with response_patterns to check.

    Returns:
        The first matching pattern string, or None if no match.
    """
    for pattern in payload.response_patterns:
        if re.search(pattern, response_text):
            return pattern
    return None


class InjectionScanner(BaseScanner):
    """Scanner for command injection via MCP tools (MCP05).

    For each tool, identifies string parameters, injects payloads,
    calls the tool, and checks the response using the payload's
    detection mode:

    - canary: Look for a canary marker in the response (shell injection).
    - pattern: Match response against regex patterns (arg injection, path traversal).
    - error_based: Check if error messages reference the injected flag/path.

    Attributes:
        name: Scanner identifier used in CLI (--checks injection).
        owasp_id: OWASP MCP Top 10 category.
        description: What this scanner tests.
    """

    name = "injection"
    owasp_id = "MCP05"
    description = "Tests for command injection via MCP tool parameters"

    async def scan(self, context: ScanContext) -> list[Finding]:
        """Test all tools for command injection vulnerabilities.

        Args:
            context: ScanContext with tools list and active session.

        Returns:
            List of Findings for each confirmed injection.

        Raises:
            ValueError: If context.session is None.
        """
        if context.session is None:
            raise ValueError("InjectionScanner requires an active session in ScanContext")

        findings: list[Finding] = []
        payloads = get_injection_payloads(platform="all")

        for tool in context.tools:
            tool_name = tool.get("name", "unknown")
            string_params = _get_string_params(tool)

            if not string_params:
                logger.debug("Skipping %s — no string parameters", tool_name)
                continue

            logger.info(
                "Testing %s — %d string params × %d payloads",
                tool_name,
                len(string_params),
                len(payloads),
            )

            for param_name in string_params:
                for payload in payloads:
                    finding = await self._test_param(context, tool, tool_name, param_name, payload)
                    if finding:
                        findings.append(finding)
                        # One confirmed injection per param is enough —
                        # skip remaining payloads for this param.
                        break

        return findings

    async def _test_param(
        self,
        context: ScanContext,
        tool: dict[str, Any],
        tool_name: str,
        param_name: str,
        payload: InjectionPayload,
    ) -> Finding | None:
        """Test a single parameter with a single payload.

        Dispatches to the appropriate detection strategy based on
        the payload's detection_mode field.

        Args:
            context: Active ScanContext.
            tool: The tool dict.
            tool_name: Name of the tool being tested.
            param_name: The parameter to inject into.
            payload: The InjectionPayload to test.

        Returns:
            A Finding if injection is confirmed, None otherwise.
        """
        args = _build_args(tool, param_name, payload.value)

        try:
            result = await context.session.call_tool(tool_name, args)
            response_text = _extract_text(result)
            is_error = getattr(result, "isError", False)
        except Exception as exc:
            logger.debug(
                "Tool call failed: %s.%s with %s — %s",
                tool_name,
                param_name,
                payload.technique,
                exc,
            )
            return None

        if payload.detection_mode == "canary":
            return self._detect_canary(response_text, tool_name, param_name, payload)
        elif payload.detection_mode == "pattern":
            return self._detect_pattern(response_text, tool_name, param_name, payload)
        elif payload.detection_mode == "error_based":
            return self._detect_error_based(response_text, is_error, tool_name, param_name, payload)

        return None

    def _detect_canary(
        self,
        response_text: str,
        tool_name: str,
        param_name: str,
        payload: InjectionPayload,
    ) -> Finding | None:
        """Detect injection via canary marker in response.

        Args:
            response_text: The tool's response text.
            tool_name: Name of the tool being tested.
            param_name: The parameter that was injected.
            payload: The InjectionPayload used.

        Returns:
            A Finding if canary found (and not just reflected), None otherwise.
        """
        if payload.canary and payload.canary in response_text:
            # Guard against false positives from tools that reflect input:
            # if the full payload string appears in the response, the canary
            # is likely just reflected, not executed by a shell.
            if payload.value in response_text:
                logger.debug(
                    "Canary found but full payload reflected — likely echo, not injection: "
                    "%s.%s via %s",
                    tool_name,
                    param_name,
                    payload.technique,
                )
                return None

            logger.warning(
                "INJECTION CONFIRMED: %s.%s via %s",
                tool_name,
                param_name,
                payload.technique,
            )
            cwe = _cwe_for_technique(payload.technique)
            return Finding(
                rule_id=f"MCP05-{cwe}-{payload.technique}",
                owasp_id="MCP05",
                title=f"Command injection in '{tool_name}' parameter '{param_name}'",
                description=(
                    f"The '{param_name}' parameter of tool '{tool_name}' is vulnerable "
                    f"to command injection via {payload.technique}. The injected payload "
                    f"was executed by a shell, confirmed by canary marker in the response."
                ),
                severity=Severity.CRITICAL,
                evidence=f"Payload: {payload.value!r} | Canary found in response",
                remediation=_REMEDIATION.get(cwe, _REMEDIATION["CWE78"]),
                tool_name=tool_name,
                metadata={
                    "parameter": param_name,
                    "technique": payload.technique,
                    "platform": payload.platform,
                    "payload": payload.value,
                    "cwe": cwe,
                    "detection_mode": "canary",
                },
            )

        return None

    def _detect_pattern(
        self,
        response_text: str,
        tool_name: str,
        param_name: str,
        payload: InjectionPayload,
    ) -> Finding | None:
        """Detect injection via regex pattern match on response.

        Args:
            response_text: The tool's response text.
            tool_name: Name of the tool being tested.
            param_name: The parameter that was injected.
            payload: The InjectionPayload used.

        Returns:
            A Finding if a pattern matched, None otherwise.
        """
        matched_pattern = _check_pattern_match(response_text, payload)
        if matched_pattern is None:
            return None

        # Guard: skip if the entire response is just the payload reflected back
        stripped_response = response_text.strip()
        if stripped_response == payload.value or stripped_response == repr(payload.value):
            logger.debug(
                "Pattern matched but response is just reflected payload: %s.%s via %s",
                tool_name,
                param_name,
                payload.technique,
            )
            return None

        cwe = _cwe_for_technique(payload.technique)
        severity = Severity.HIGH if cwe == "CWE88" else Severity.CRITICAL

        logger.warning(
            "INJECTION CONFIRMED (pattern): %s.%s via %s (matched: %s)",
            tool_name,
            param_name,
            payload.technique,
            matched_pattern,
        )
        return Finding(
            rule_id=f"MCP05-{cwe}-{payload.technique}",
            owasp_id="MCP05",
            title=f"{'Argument' if cwe == 'CWE88' else 'Path traversal'} injection "
            f"in '{tool_name}' parameter '{param_name}'",
            description=(
                f"The '{param_name}' parameter of tool '{tool_name}' is vulnerable "
                f"to {payload.description.lower()}. Response matched pattern: "
                f"'{matched_pattern}'."
            ),
            severity=severity,
            evidence=(
                f"Payload: {payload.value!r} | Matched pattern: {matched_pattern!r} in response"
            ),
            remediation=_REMEDIATION.get(cwe, _REMEDIATION["CWE78"]),
            tool_name=tool_name,
            metadata={
                "parameter": param_name,
                "technique": payload.technique,
                "platform": payload.platform,
                "payload": payload.value,
                "cwe": cwe,
                "detection_mode": "pattern",
                "matched_pattern": matched_pattern,
            },
        )

    def _detect_error_based(
        self,
        response_text: str,
        is_error: bool,
        tool_name: str,
        param_name: str,
        payload: InjectionPayload,
    ) -> Finding | None:
        """Detect injection via error messages referencing injected flags.

        If the tool returns an error mentioning the injected flag or path,
        it confirms the input reached the CLI parser — a weaker signal than
        canary but still a valid finding.

        Args:
            response_text: The tool's response text.
            is_error: Whether the tool result was flagged as an error.
            tool_name: Name of the tool being tested.
            param_name: The parameter that was injected.
            payload: The InjectionPayload used.

        Returns:
            A Finding (MEDIUM severity) if error references the payload, None otherwise.
        """
        if not is_error and "error" not in response_text.lower():
            return None

        # Check if the error message references the injected value
        # (e.g., "unknown option --output" or "unrecognized option '-o'")
        # e.g., "--output" from "--output=/dev/null"
        inject_key = payload.value.split("=")[0].split()[0]
        if inject_key not in response_text:
            return None

        cwe = _cwe_for_technique(payload.technique)
        logger.warning(
            "INJECTION DETECTED (error-based): %s.%s via %s",
            tool_name,
            param_name,
            payload.technique,
        )
        return Finding(
            rule_id=f"MCP05-{cwe}-{payload.technique}",
            owasp_id="MCP05",
            title=f"Argument injection (error-based) in '{tool_name}' parameter '{param_name}'",
            description=(
                f"The '{param_name}' parameter of tool '{tool_name}' passed "
                f"user input to a CLI parser. The error message references the "
                f"injected flag '{inject_key}', confirming the input was "
                f"interpreted as a command-line argument."
            ),
            severity=Severity.MEDIUM,
            evidence=(f"Payload: {payload.value!r} | Error message references '{inject_key}'"),
            remediation=_REMEDIATION.get(cwe, _REMEDIATION["CWE78"]),
            tool_name=tool_name,
            metadata={
                "parameter": param_name,
                "technique": payload.technique,
                "platform": payload.platform,
                "payload": payload.value,
                "cwe": cwe,
                "detection_mode": "error_based",
            },
        )
