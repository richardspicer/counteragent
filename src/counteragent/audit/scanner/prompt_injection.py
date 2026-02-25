"""Prompt Injection via Tool Responses scanner (MCP06).

Tests whether MCP tool responses contain content that could hijack
the calling LLM agent. Calls each tool with benign inputs and
analyzes the returned content for injection patterns.

Attack vector: A compromised or malicious MCP server returns tool
responses containing prompt injection payloads. When the LLM agent
processes these responses, the embedded instructions can override
the agent's system prompt, exfiltrate data, or redirect behavior.

This complements MCP03 (tool_poisoning) which checks tool
*descriptions* — MCP06 checks tool *outputs*.

Maps to: OWASP MCP Top 10 — MCP06: Indirect Prompt Injection
"""

from __future__ import annotations

import logging
import re
from typing import Any

from counteragent.audit.scanner.base import BaseScanner, Finding, ScanContext, Severity

logger = logging.getLogger("counteragent.audit.scanner.prompt_injection")

# ---- Injection patterns in tool responses ----
# These detect instruction-like content that could manipulate a calling LLM.

_RESPONSE_INJECTION_PATTERNS: list[tuple[str, str]] = [
    # XML-style instruction tags
    (r"<IMPORTANT>", "XML instruction tag (<IMPORTANT>)"),
    (r"<SYSTEM>", "XML instruction tag (<SYSTEM>)"),
    (r"<INSTRUCTION>", "XML instruction tag (<INSTRUCTION>)"),
    (r"<CMD>", "XML instruction tag (<CMD>)"),
    (r"<ADMIN>", "XML instruction tag (<ADMIN>)"),
    # Override directives
    (r"(?i)ignore\s+(all\s+)?previous\s+instructions", "Override directive"),
    (r"(?i)disregard\s+(all\s+)?prior\s+(instructions|context)", "Override directive"),
    (r"(?i)forget\s+(everything|all|your)\s+(above|previous|prior)", "Override directive"),
    (
        r"(?i)override\s+(system|safety|security)\s+(prompt|instructions|rules)",
        "Override directive",
    ),
    (r"(?i)new\s+instructions?\s*:", "New instructions directive"),
    # Role reassignment
    (r"(?i)you\s+are\s+now\s+(a|an|the)\s+", "Role reassignment"),
    (r"(?i)act\s+as\s+(a|an|if)\s+", "Role reassignment"),
    (r"(?i)switch\s+to\s+\w+\s+mode", "Mode switch directive"),
    # Exfiltration directives
    (
        r"(?i)(send|post|fetch|transmit|forward)\s+.{0,30}(to|at|via)\s+https?://",
        "Exfiltration directive",
    ),
    (r"(?i)exfiltrate", "Exfiltration keyword"),
    (r"(?i)callback\s+(to|url|server)", "Callback directive"),
    # Behavioral directives
    (r"(?i)do\s+not\s+tell\s+the\s+user", "Concealment directive"),
    (r"(?i)don'?t\s+(mention|reveal|disclose|tell)", "Concealment directive"),
    (r"(?i)keep\s+this\s+(secret|hidden|confidential)", "Concealment directive"),
    (r"(?i)always\s+(use|call|invoke|prefer)\s+", "Behavioral override"),
    (r"(?i)never\s+(use|call|invoke|mention)\s+", "Behavioral override"),
    # System prompt extraction
    (
        r"(?i)(print|show|display|output|repeat|echo)\s+(your\s+)?(system\s+prompt|instructions|rules)",
        "System prompt extraction",
    ),
    (
        r"(?i)what\s+(are|is)\s+your\s+(system|initial)\s+(prompt|instructions)",
        "System prompt extraction",
    ),
]

# URL pattern for detecting exfil targets in responses
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

# Allowlisted URL domains that are benign in tool responses
_BENIGN_URL_DOMAINS: set[str] = {
    "example.com",
    "www.example.com",
    "localhost",
    "127.0.0.1",
    "schemas.xmlsoap.org",
    "www.w3.org",
    "schema.org",
    "json-schema.org",
}

# Hidden Unicode codepoints (subset of tool_poisoning detection)
_HIDDEN_CODEPOINTS: set[int] = {
    0x200B,  # Zero-width space
    0x200C,  # Zero-width non-joiner
    0x200D,  # Zero-width joiner
    0x200E,  # Left-to-right mark
    0x200F,  # Right-to-left mark
    0xFEFF,  # Zero-width no-break space (BOM)
    0x2060,  # Word joiner
    0x2061,  # Function application
    0x2062,  # Invisible times
    0x2063,  # Invisible separator
    0x2064,  # Invisible plus
    0x202A,  # Left-to-right embedding
    0x202B,  # Right-to-left embedding
    0x202C,  # Pop directional formatting
    0x202D,  # Left-to-right override
    0x202E,  # Right-to-left override
}

# Safe default values for tool parameters
_SAFE_DEFAULTS: dict[str, Any] = {
    "string": "test",
    "integer": 1,
    "number": 1.0,
    "boolean": True,
    "array": [],
    "object": {},
}


def _extract_text(result: Any) -> str:
    """Extract text content from an MCP call_tool result.

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


def _build_safe_args(tool: dict[str, Any]) -> dict[str, Any]:
    """Build benign arguments for calling a tool.

    Uses safe default values based on parameter types. The goal is
    to get a valid response from the tool, not to test input handling.

    Args:
        tool: Tool dict from ScanContext.tools.

    Returns:
        Dict of parameter name -> safe value.
    """
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})
    args: dict[str, Any] = {}
    for name, prop in properties.items():
        param_type = prop.get("type", "string")
        args[name] = _SAFE_DEFAULTS.get(param_type, "test")
    return args


def _find_injection_patterns(text: str) -> list[dict[str, str]]:
    """Scan text for prompt injection patterns.

    Args:
        text: Text to analyze.

    Returns:
        List of dicts with 'pattern_desc' and 'matched_text' keys.
    """
    found: list[dict[str, str]] = []
    for pattern, desc in _RESPONSE_INJECTION_PATTERNS:
        match = re.search(pattern, text)
        if match:
            matched = match.group(0)
            if len(matched) > 80:
                matched = matched[:77] + "..."
            found.append({"pattern_desc": desc, "matched_text": matched})
    return found


def _find_suspicious_urls(text: str) -> list[str]:
    """Extract URLs from text, excluding benign domains.

    Args:
        text: Text to scan for URLs.

    Returns:
        List of suspicious URLs found.
    """
    urls = _URL_PATTERN.findall(text)
    suspicious: list[str] = []
    for url in urls:
        # Extract domain from URL
        domain_match = re.match(r"https?://([^/:]+)", url)
        if domain_match:
            domain = domain_match.group(1).lower()
            if domain not in _BENIGN_URL_DOMAINS:
                suspicious.append(url)
    return suspicious


def _find_hidden_unicode(text: str) -> int:
    """Count hidden Unicode characters in text.

    Args:
        text: Text to scan.

    Returns:
        Count of hidden Unicode characters found.
    """
    return sum(1 for char in text if ord(char) in _HIDDEN_CODEPOINTS)


def _find_cross_tool_references(
    text: str,
    all_tool_names: list[str],
    current_tool: str,
) -> list[str]:
    """Find references to other tools in a tool's response.

    A tool response that names other tools and instructs the agent
    to call them is a cross-tool manipulation indicator.

    Args:
        text: Tool response text.
        all_tool_names: Names of all tools on the server.
        current_tool: Name of the tool that produced this response.

    Returns:
        List of other tool names referenced in the response.
    """
    referenced: list[str] = []
    text_lower = text.lower()
    for name in all_tool_names:
        if name != current_tool and name.lower() in text_lower:
            referenced.append(name)
    return referenced


class PromptInjectionScanner(BaseScanner):
    """Scanner for indirect prompt injection via tool responses (MCP06).

    Calls each tool with benign inputs and analyzes the responses for
    content that could hijack the calling LLM agent. Does NOT test
    tool *descriptions* (that's MCP03) — this tests what comes back
    when tools are actually invoked.

    Checks:
        MCP06-001: Injection patterns in tool responses
        MCP06-002: Hidden Unicode characters in responses
        MCP06-003: Suspicious URLs in responses (exfil targets)
        MCP06-004: Cross-tool manipulation references
        MCP06-005: Anomalous response length (may hide instructions)

    Attributes:
        name: Scanner identifier used in CLI (--checks prompt_injection).
        owasp_id: OWASP MCP Top 10 category.
        description: What this scanner tests.
    """

    name = "prompt_injection"
    owasp_id = "MCP06"
    description = "Tests tool responses for indirect prompt injection content"

    # Response length threshold (characters). Responses beyond this
    # may contain hidden instructions buried in verbose output.
    _RESPONSE_LENGTH_THRESHOLD = 2000

    async def scan(self, context: ScanContext) -> list[Finding]:
        """Call all tools with benign inputs and analyze responses.

        Args:
            context: ScanContext with tools list and active session.

        Returns:
            List of Findings for injection indicators in responses.

        Raises:
            ValueError: If context.session is None.
        """
        findings: list[Finding] = []

        if not context.tools:
            logger.debug("No tools discovered — skipping prompt injection checks")
            return findings

        if context.session is None:
            raise ValueError("PromptInjectionScanner requires an active session in ScanContext")

        all_tool_names = [t.get("name", "") for t in context.tools]

        for tool in context.tools:
            tool_name = tool.get("name", "unknown")
            args = _build_safe_args(tool)

            try:
                result = await context.session.call_tool(tool_name, args)
                response_text = _extract_text(result)
            except Exception as exc:
                logger.debug(
                    "Tool call failed for %s: %s",
                    tool_name,
                    exc,
                )
                continue

            if not response_text:
                logger.debug("Empty response from %s — skipping", tool_name)
                continue

            # MCP06-001: Injection patterns
            findings.extend(self._check_injection_patterns(tool_name, response_text))

            # MCP06-002: Hidden Unicode
            finding = self._check_hidden_unicode(tool_name, response_text)
            if finding:
                findings.append(finding)

            # MCP06-003: Suspicious URLs
            findings.extend(self._check_suspicious_urls(tool_name, response_text))

            # MCP06-004: Cross-tool references
            finding = self._check_cross_tool_refs(
                tool_name,
                response_text,
                all_tool_names,
            )
            if finding:
                findings.append(finding)

            # MCP06-005: Anomalous response length
            finding = self._check_response_length(tool_name, response_text)
            if finding:
                findings.append(finding)

        return findings

    def _check_injection_patterns(
        self,
        tool_name: str,
        response: str,
    ) -> list[Finding]:
        """Check tool response for prompt injection patterns.

        Args:
            tool_name: Name of the tool that produced the response.
            response: The tool's text response.

        Returns:
            List of Findings for each injection pattern detected.
        """
        findings: list[Finding] = []
        patterns = _find_injection_patterns(response)

        for match in patterns:
            findings.append(
                Finding(
                    rule_id="MCP06-001",
                    owasp_id="MCP06",
                    title=f"Injection pattern in '{tool_name}' response",
                    description=(
                        f"Tool '{tool_name}' returned a response containing "
                        f"a prompt injection pattern: {match['pattern_desc']}. "
                        f"Matched text: '{match['matched_text']}'. When the "
                        f"calling LLM agent processes this response, the "
                        f"embedded instructions could override its behavior."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=(
                        f"Pattern '{match['pattern_desc']}' matched: '{match['matched_text']}'"
                    ),
                    remediation=(
                        "Sanitize tool responses before returning them to the "
                        "agent. Strip instruction-like content, XML tags that "
                        "could be interpreted as directives, and override "
                        "language. Consider response content filtering at the "
                        "MCP client level."
                    ),
                    tool_name=tool_name,
                    metadata={
                        "pattern": match["pattern_desc"],
                        "matched_text": match["matched_text"],
                    },
                )
            )

        return findings

    def _check_hidden_unicode(
        self,
        tool_name: str,
        response: str,
    ) -> Finding | None:
        """Check tool response for hidden Unicode characters.

        Args:
            tool_name: Name of the tool.
            response: The tool's text response.

        Returns:
            A Finding if hidden Unicode is detected, None otherwise.
        """
        count = _find_hidden_unicode(response)
        if count == 0:
            return None

        return Finding(
            rule_id="MCP06-002",
            owasp_id="MCP06",
            title=f"Hidden Unicode in '{tool_name}' response",
            description=(
                f"Tool '{tool_name}' returned a response containing "
                f"{count} hidden Unicode character(s) (zero-width spaces, "
                f"directional overrides, invisible formatters). These can "
                f"conceal injected instructions from human reviewers "
                f"while being processed by the LLM."
            ),
            severity=Severity.HIGH,
            evidence=f"{count} hidden Unicode character(s) in response",
            remediation=(
                "Strip non-printable and zero-width Unicode characters "
                "from tool responses. Implement response sanitization "
                "in the MCP server or client middleware."
            ),
            tool_name=tool_name,
            metadata={"hidden_char_count": count},
        )

    def _check_suspicious_urls(
        self,
        tool_name: str,
        response: str,
    ) -> list[Finding]:
        """Check tool response for suspicious URLs.

        URLs in tool responses can be exfiltration targets — the
        injected instruction tells the agent to send data to an
        attacker-controlled endpoint.

        Args:
            tool_name: Name of the tool.
            response: The tool's text response.

        Returns:
            List of Findings for each suspicious URL found.
        """
        urls = _find_suspicious_urls(response)
        findings: list[Finding] = []

        for url in urls:
            findings.append(
                Finding(
                    rule_id="MCP06-003",
                    owasp_id="MCP06",
                    title=f"Suspicious URL in '{tool_name}' response",
                    description=(
                        f"Tool '{tool_name}' returned a response containing "
                        f"the URL '{url}'. URLs in tool responses can serve "
                        f"as exfiltration targets when combined with "
                        f"injection directives — the agent may be instructed "
                        f"to send user data to this endpoint."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"URL found: {url}",
                    remediation=(
                        "Validate and allowlist URLs in tool responses. "
                        "Block or flag responses containing URLs to external "
                        "domains that are not part of the tool's expected "
                        "behavior."
                    ),
                    tool_name=tool_name,
                    metadata={"url": url},
                )
            )

        return findings

    def _check_cross_tool_refs(
        self,
        tool_name: str,
        response: str,
        all_tool_names: list[str],
    ) -> Finding | None:
        """Check if a tool response references other tools.

        A response that names other tools and contains behavioral
        language could be attempting cross-tool manipulation — making
        the agent call a different tool with attacker-controlled args.

        Args:
            tool_name: Name of the tool that produced the response.
            response: The tool's text response.
            all_tool_names: Names of all tools on the server.

        Returns:
            A Finding if cross-tool references are detected with
            behavioral language, None otherwise.
        """
        referenced = _find_cross_tool_references(
            response,
            all_tool_names,
            tool_name,
        )
        if not referenced:
            return None

        # Only flag if the response also contains behavioral language
        # (calling another tool by name alone could be legitimate help text)
        behavioral_patterns = [
            r"(?i)(call|use|invoke|run|execute)\s+",
            r"(?i)(now|next|then)\s+(call|use|invoke|run)",
            r"(?i)you\s+(should|must|need\s+to)\s+",
        ]
        has_behavioral = any(re.search(p, response) for p in behavioral_patterns)

        if not has_behavioral:
            return None

        return Finding(
            rule_id="MCP06-004",
            owasp_id="MCP06",
            title=f"Cross-tool manipulation in '{tool_name}' response",
            description=(
                f"Tool '{tool_name}' returned a response that references "
                f"other tools ({', '.join(referenced)}) combined with "
                f"behavioral directives. This pattern indicates the "
                f"response is attempting to manipulate the agent into "
                f"calling other tools with attacker-influenced arguments."
            ),
            severity=Severity.HIGH,
            evidence=(f"Referenced tools: {', '.join(referenced)} with behavioral language"),
            remediation=(
                "Tool responses should not contain instructions for the "
                "agent to call other tools. Implement response validation "
                "that flags cross-tool references combined with "
                "directive language."
            ),
            tool_name=tool_name,
            metadata={"referenced_tools": referenced},
        )

    def _check_response_length(
        self,
        tool_name: str,
        response: str,
    ) -> Finding | None:
        """Flag anomalously long responses that may hide instructions.

        Legitimate tool responses are typically concise. Extremely long
        responses provide space for hidden injection content.

        Args:
            tool_name: Name of the tool.
            response: The tool's text response.

        Returns:
            A Finding if the response exceeds the length threshold,
            None otherwise.
        """
        if len(response) <= self._RESPONSE_LENGTH_THRESHOLD:
            return None

        return Finding(
            rule_id="MCP06-005",
            owasp_id="MCP06",
            title=f"Anomalously long response from '{tool_name}'",
            description=(
                f"Tool '{tool_name}' returned a response of "
                f"{len(response)} characters (threshold: "
                f"{self._RESPONSE_LENGTH_THRESHOLD}). Excessively long "
                f"responses can hide injected instructions within "
                f"legitimate-looking content."
            ),
            severity=Severity.MEDIUM,
            evidence=f"Response length: {len(response)} chars",
            remediation=(
                "Set maximum response length limits on MCP tools. "
                "Review unusually verbose tool responses for embedded "
                "instructions or unnecessary content."
            ),
            tool_name=tool_name,
            metadata={
                "response_length": len(response),
                "threshold": self._RESPONSE_LENGTH_THRESHOLD,
            },
        )
