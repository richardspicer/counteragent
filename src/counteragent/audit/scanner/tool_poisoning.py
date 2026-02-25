"""Tool Poisoning scanner (MCP03).

Static analysis of tool descriptions, names, and schemas to detect
poisoning indicators. Checks for embedded instructions, suspicious
patterns, Unicode tricks, duplicate tools, and description anomalies.

Maps to: OWASP MCP Top 10 — MCP03: Tool Poisoning

Real-world reference: GPT-4.1 jailbreak via tool description poisoning,
Invariant Labs WhatsApp exfiltration via malicious MCP server,
MCP Preference Manipulation Attack (MPMA).
"""

from __future__ import annotations

import logging
import re
import unicodedata
from typing import Any

from counteragent.audit.scanner.base import BaseScanner, Finding, ScanContext, Severity

logger = logging.getLogger("counteragent.audit.scanner.tool_poisoning")


# Patterns that indicate embedded instructions in tool descriptions.
# Attackers inject these to manipulate model behavior when tools are listed.
_INSTRUCTION_PATTERNS: list[tuple[str, str]] = [
    (r"<IMPORTANT>", "XML-style IMPORTANT tag (common tool poisoning vector)"),
    (r"<SYSTEM>", "XML-style SYSTEM tag"),
    (r"<INSTRUCTION>", "XML-style INSTRUCTION tag"),
    (r"<CONTEXT>", "XML-style CONTEXT tag"),
    (r"<HIDDEN>", "XML-style HIDDEN tag"),
    (
        r"(?i)\bignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|rules?)",
        "Instruction override directive",
    ),
    (r"(?i)\byou\s+must\s+(always|never|first)\b", "Behavioral directive"),
    (r"(?i)\byou\s+are\s+(now|a|an)\b", "Role reassignment directive"),
    (r"(?i)\bdo\s+not\s+tell\s+(the\s+)?user\b", "Concealment directive"),
    (r"(?i)\bpretend\s+(to\s+be|you\s+are)\b", "Impersonation directive"),
    (r"(?i)\bsecretly\b", "Covert action indicator"),
    (r"(?i)\bexfiltrate\b", "Data exfiltration indicator"),
    (r"(?i)\bsend\s+(all|the|this)\s+.{0,30}\bto\s+https?://", "URL exfiltration directive"),
    (r"(?i)\bfetch\s+https?://", "URL fetch directive in description"),
    (
        r"(?i)\bbefore\s+(using|calling|running)\s+.{0,40}\bfirst\b",
        "Pre-execution instruction injection",
    ),
    (
        r"(?i)\bafter\s+(using|calling|running)\s+.{0,40}\balso\b",
        "Post-execution instruction injection",
    ),
    (r"(?i)\bwhen\s+the\s+user\s+asks?\b", "User-triggered behavior manipulation"),
    (r"(?i)\bprefer\s+this\s+tool\b", "Preference manipulation (MPMA)"),
    (r"(?i)\balways\s+use\s+this\s+tool\s+instead\b", "Preference manipulation (MPMA)"),
    (
        r"(?i)\bthis\s+tool\s+is\s+(better|superior|more\s+reliable)\s+than\b",
        "Comparative preference manipulation",
    ),
]

# Zero-width and invisible Unicode characters used to hide content.
_HIDDEN_UNICODE: dict[int, str] = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
    0xFFF9: "INTERLINEAR ANNOTATION ANCHOR",
    0xFFFA: "INTERLINEAR ANNOTATION SEPARATOR",
    0xFFFB: "INTERLINEAR ANNOTATION TERMINATOR",
}

# Description length threshold. Legitimate tool descriptions are typically
# under 500 chars. Long descriptions may hide instructions in the noise.
_DESCRIPTION_LENGTH_THRESHOLD = 500

# Similarity threshold for duplicate tool detection.
# Tools with names this similar may indicate shadowing attacks.
_SIMILARITY_THRESHOLD = 0.85

# Minimum shared-prefix ratio to consider two tool names as intentional variants
# (e.g., git_diff_staged / git_diff_unstaged) rather than shadowing attacks.
_PREFIX_RATIO_THRESHOLD = 0.5


def _levenshtein_ratio(s1: str, s2: str) -> float:
    """Calculate normalized Levenshtein similarity ratio between two strings.

    Args:
        s1: First string.
        s2: Second string.

    Returns:
        Similarity ratio between 0.0 (completely different) and 1.0 (identical).
    """
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if not len1 or not len2:
        return 0.0

    # Build distance matrix
    matrix: list[list[int]] = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    for i in range(len1 + 1):
        matrix[i][0] = i
    for j in range(len2 + 1):
        matrix[0][j] = j

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost,
            )

    max_len = max(len1, len2)
    return 1.0 - (matrix[len1][len2] / max_len)


def _shared_prefix_length(s1: str, s2: str) -> int:
    """Return length of common prefix between two strings.

    Args:
        s1: First string.
        s2: Second string.

    Returns:
        Number of leading characters that are identical in both strings.
    """
    for i in range(min(len(s1), len(s2))):
        if s1[i] != s2[i]:
            return i
    return min(len(s1), len(s2))


def _find_hidden_unicode(text: str) -> list[dict[str, Any]]:
    """Scan text for hidden or invisible Unicode characters.

    Args:
        text: String to scan for hidden characters.

    Returns:
        List of dicts with 'char', 'codepoint', 'name', and 'position'
        for each hidden character found.
    """
    found: list[dict[str, Any]] = []
    for i, char in enumerate(text):
        cp = ord(char)
        if cp in _HIDDEN_UNICODE:
            found.append(
                {
                    "char": repr(char),
                    "codepoint": f"U+{cp:04X}",
                    "name": _HIDDEN_UNICODE[cp],
                    "position": i,
                }
            )
        elif unicodedata.category(char) in ("Cf", "Mn", "Cc") and cp not in (
            0x09,
            0x0A,
            0x0D,
        ):
            # Cf = Format, Mn = Nonspacing Mark, Cc = Control
            # Skip common whitespace (tab, newline, carriage return)
            name = unicodedata.name(char, f"U+{cp:04X}")
            found.append(
                {
                    "char": repr(char),
                    "codepoint": f"U+{cp:04X}",
                    "name": name,
                    "position": i,
                }
            )
    return found


def _check_homoglyphs(name: str) -> list[dict[str, str]]:
    """Detect characters that visually resemble ASCII but are from other scripts.

    Homoglyph attacks use Cyrillic, Greek, or other script characters
    that look identical to Latin letters, creating tool names that appear
    the same but are technically different.

    Args:
        name: Tool name to check for homoglyphs.

    Returns:
        List of dicts with 'char', 'position', 'script', and 'looks_like'
        for each suspicious character.
    """
    # Common homoglyph mappings: non-ASCII char -> ASCII lookalike
    homoglyph_map: dict[str, str] = {
        "\u0430": "a",  # Cyrillic а
        "\u0435": "e",  # Cyrillic е
        "\u043e": "o",  # Cyrillic о
        "\u0440": "p",  # Cyrillic р
        "\u0441": "c",  # Cyrillic с
        "\u0445": "x",  # Cyrillic х
        "\u0443": "y",  # Cyrillic у
        "\u03b1": "a",  # Greek α
        "\u03bf": "o",  # Greek ο
        "\u03c1": "p",  # Greek ρ
        "\u0391": "A",  # Greek Α
        "\u0392": "B",  # Greek Β
        "\u0395": "E",  # Greek Ε
        "\u0397": "H",  # Greek Η
        "\u039a": "K",  # Greek Κ
        "\u039c": "M",  # Greek Μ
        "\u039d": "N",  # Greek Ν
        "\u039f": "O",  # Greek Ο
        "\u03a1": "P",  # Greek Ρ
        "\u03a4": "T",  # Greek Τ
        "\u03a7": "X",  # Greek Χ
    }

    found: list[dict[str, str]] = []
    for i, char in enumerate(name):
        if char in homoglyph_map:
            script = unicodedata.name(char, "UNKNOWN").split()[0]
            found.append(
                {
                    "char": char,
                    "position": str(i),
                    "script": script,
                    "looks_like": homoglyph_map[char],
                }
            )
    return found


class ToolPoisoningScanner(BaseScanner):
    """Scanner for tool poisoning indicators (MCP03).

    Performs static analysis of tool descriptions, names, and schemas
    to detect poisoning vectors. Does NOT invoke tools — analyzes the
    enumerated metadata to identify:

    - Embedded instructions in descriptions (prompt injection via tools)
    - Hidden Unicode characters that conceal content
    - Homoglyph attacks in tool names (visual spoofing)
    - Duplicate/shadowed tools with similar names
    - Anomalously long descriptions that may hide instructions

    Attributes:
        name: Scanner identifier used in CLI (--checks tool_poisoning).
        owasp_id: OWASP MCP Top 10 category.
        description: What this scanner tests.
    """

    name = "tool_poisoning"
    owasp_id = "MCP03"
    description = "Tests for tool poisoning via descriptions, names, and schemas"

    async def scan(self, context: ScanContext) -> list[Finding]:
        """Run all tool poisoning checks against enumerated tools.

        Args:
            context: ScanContext with tools list from server enumeration.

        Returns:
            List of Findings for each poisoning indicator detected.
        """
        findings: list[Finding] = []

        if not context.tools:
            logger.debug("No tools discovered — skipping tool poisoning checks")
            return findings

        for tool in context.tools:
            findings.extend(self._check_embedded_instructions(tool))
            findings.extend(self._check_hidden_unicode(tool))
            findings.extend(self._check_homoglyphs(tool))
            finding = self._check_description_length(tool)
            if finding:
                findings.append(finding)

        # Cross-tool checks
        findings.extend(self._check_duplicate_tools(context.tools))

        return findings

    def _check_embedded_instructions(self, tool: dict[str, Any]) -> list[Finding]:
        """Scan tool description for embedded instruction patterns.

        Attackers inject directives like '<IMPORTANT>', 'ignore previous
        instructions', or 'secretly exfiltrate' into tool descriptions.
        When an LLM reads the tool list, these instructions can hijack
        its behavior.

        Args:
            tool: Tool dict with 'name' and 'description' fields.

        Returns:
            List of Findings for each instruction pattern matched.
        """
        findings: list[Finding] = []
        name = tool.get("name", "unknown")
        desc = tool.get("description", "")

        if not desc:
            return findings

        for pattern, pattern_desc in _INSTRUCTION_PATTERNS:
            match = re.search(pattern, desc)
            if match:
                matched_text = match.group(0)
                # Truncate long matches for readability
                if len(matched_text) > 80:
                    matched_text = matched_text[:77] + "..."

                findings.append(
                    Finding(
                        rule_id="MCP03-001",
                        owasp_id="MCP03",
                        title=f"Embedded instruction in tool '{name}'",
                        description=(
                            f"Tool '{name}' description contains a suspicious "
                            f"pattern: {pattern_desc}. Matched text: "
                            f"'{matched_text}'. This could manipulate LLM "
                            f"behavior when the tool list is presented."
                        ),
                        severity=Severity.HIGH,
                        evidence=f"Pattern '{pattern_desc}' matched: '{matched_text}'",
                        remediation=(
                            "Review and sanitize tool descriptions. Remove any "
                            "text that could be interpreted as instructions by "
                            "an LLM. Tool descriptions should only explain the "
                            "tool's legitimate purpose and parameters."
                        ),
                        tool_name=name,
                        metadata={
                            "pattern": pattern_desc,
                            "matched_text": matched_text,
                        },
                    )
                )

        return findings

    def _check_hidden_unicode(self, tool: dict[str, Any]) -> list[Finding]:
        """Scan tool name and description for hidden Unicode characters.

        Zero-width characters, directional overrides, and invisible
        formatters can hide content from human reviewers while being
        processed by LLMs differently.

        Args:
            tool: Tool dict with 'name' and 'description' fields.

        Returns:
            List of Findings for hidden Unicode characters found.
        """
        findings: list[Finding] = []
        name = tool.get("name", "unknown")

        for field_name, text in [("name", name), ("description", tool.get("description", ""))]:
            hidden_chars = _find_hidden_unicode(text)
            if hidden_chars:
                char_summary = ", ".join(
                    f"{h['name']} ({h['codepoint']})" for h in hidden_chars[:5]
                )
                if len(hidden_chars) > 5:
                    char_summary += f" ... and {len(hidden_chars) - 5} more"

                findings.append(
                    Finding(
                        rule_id="MCP03-002",
                        owasp_id="MCP03",
                        title=f"Hidden Unicode in tool '{name}' {field_name}",
                        description=(
                            f"Tool '{name}' {field_name} contains "
                            f"{len(hidden_chars)} hidden Unicode character(s): "
                            f"{char_summary}. These can conceal malicious "
                            f"content from human reviewers."
                        ),
                        severity=Severity.HIGH,
                        evidence=(f"{len(hidden_chars)} hidden character(s) in {field_name}"),
                        remediation=(
                            "Strip all non-printable and zero-width Unicode "
                            "characters from tool names and descriptions. Only "
                            "standard ASCII and common UTF-8 characters should "
                            "be present."
                        ),
                        tool_name=name,
                        metadata={
                            "field": field_name,
                            "hidden_chars": hidden_chars[:10],
                            "total_count": len(hidden_chars),
                        },
                    )
                )

        return findings

    def _check_homoglyphs(self, tool: dict[str, Any]) -> list[Finding]:
        """Check tool name for homoglyph characters (visual spoofing).

        Attackers can register tools with names like 'read_file' (Cyrillic i)
        that look identical to legitimate tools but execute different code.

        Args:
            tool: Tool dict with 'name' field.

        Returns:
            List of Findings for homoglyph characters found.
        """
        name = tool.get("name", "unknown")
        homoglyphs = _check_homoglyphs(name)

        if not homoglyphs:
            return []

        char_detail = ", ".join(
            f"'{h['char']}' at position {h['position']} "
            f"({h['script']}, looks like '{h['looks_like']}')"
            for h in homoglyphs
        )

        return [
            Finding(
                rule_id="MCP03-003",
                owasp_id="MCP03",
                title=f"Homoglyph characters in tool name '{name}'",
                description=(
                    f"Tool name '{name}' contains characters from non-Latin "
                    f"scripts that visually resemble ASCII letters: "
                    f"{char_detail}. This could be a tool shadowing attack "
                    f"where a malicious tool impersonates a legitimate one."
                ),
                severity=Severity.CRITICAL,
                evidence=f"{len(homoglyphs)} homoglyph(s) in tool name",
                remediation=(
                    "Reject tool names containing mixed-script characters. "
                    "Enforce ASCII-only naming for tool identifiers, or "
                    "implement confusable detection (Unicode TR39)."
                ),
                tool_name=name,
                metadata={
                    "homoglyphs": homoglyphs,
                },
            )
        ]

    def _check_description_length(self, tool: dict[str, Any]) -> Finding | None:
        """Flag anomalously long descriptions that may hide instructions.

        Legitimate tool descriptions are typically concise. Extremely
        long descriptions provide space to embed instructions that
        human reviewers may not notice.

        Args:
            tool: Tool dict with 'name' and 'description' fields.

        Returns:
            A Finding if description exceeds threshold, None otherwise.
        """
        name = tool.get("name", "unknown")
        desc = tool.get("description", "")

        if len(desc) <= _DESCRIPTION_LENGTH_THRESHOLD:
            return None

        return Finding(
            rule_id="MCP03-004",
            owasp_id="MCP03",
            title=f"Anomalously long description for tool '{name}'",
            description=(
                f"Tool '{name}' has a description of {len(desc)} characters "
                f"(threshold: {_DESCRIPTION_LENGTH_THRESHOLD}). Excessively "
                f"long descriptions can hide embedded instructions or "
                f"manipulative content that reviewers may overlook."
            ),
            severity=Severity.MEDIUM,
            evidence=f"Description length: {len(desc)} chars",
            remediation=(
                "Keep tool descriptions concise and focused on the tool's "
                "purpose. Review long descriptions for embedded instructions "
                "or unnecessary content."
            ),
            tool_name=name,
            metadata={
                "description_length": len(desc),
                "threshold": _DESCRIPTION_LENGTH_THRESHOLD,
            },
        )

    def _check_duplicate_tools(self, tools: list[dict[str, Any]]) -> list[Finding]:
        """Detect tools with suspiciously similar names (shadowing).

        Tool shadowing attacks register tools with names nearly identical
        to legitimate ones, hoping the LLM will call the malicious version.

        Args:
            tools: List of all tool dicts from server enumeration.

        Returns:
            List of Findings for tool name pairs that are suspiciously similar.
        """
        findings: list[Finding] = []
        names = [t.get("name", "") for t in tools]

        # Compare all pairs
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                if names[i] == names[j]:
                    # Exact duplicate
                    findings.append(
                        Finding(
                            rule_id="MCP03-005",
                            owasp_id="MCP03",
                            title=f"Duplicate tool name: '{names[i]}'",
                            description=(
                                f"Two tools share the exact name '{names[i]}'. "
                                f"This causes ambiguity in tool selection and "
                                f"could indicate a tool shadowing attack."
                            ),
                            severity=Severity.CRITICAL,
                            evidence=f"Exact duplicate: '{names[i]}'",
                            remediation=(
                                "Remove duplicate tool registrations. Each tool "
                                "name must be unique within a server."
                            ),
                            tool_name=names[i],
                            metadata={
                                "tool_a": names[i],
                                "tool_b": names[j],
                                "similarity": 1.0,
                            },
                        )
                    )
                else:
                    ratio = _levenshtein_ratio(names[i], names[j])
                    if ratio >= _SIMILARITY_THRESHOLD:
                        prefix_len = _shared_prefix_length(names[i], names[j])
                        min_len = min(len(names[i]), len(names[j]))
                        prefix_ratio = prefix_len / min_len if min_len > 0 else 0.0
                        shared_prefix = names[i][:prefix_len]

                        # Tools sharing a significant common prefix are likely
                        # intentional variants (e.g., git_diff_staged /
                        # git_diff_unstaged), not shadowing attacks.
                        if prefix_ratio >= _PREFIX_RATIO_THRESHOLD:
                            severity = Severity.INFO
                            description = (
                                f"Tools '{names[i]}' and '{names[j]}' have "
                                f"names that are {ratio:.0%} similar with "
                                f"shared prefix '{shared_prefix}' "
                                f"({prefix_ratio:.0%} of shorter name). "
                                f"Same-server tools sharing a common prefix "
                                f"are typically intentional variants, not "
                                f"shadowing attacks."
                            )
                        else:
                            severity = Severity.HIGH
                            description = (
                                f"Tools '{names[i]}' and '{names[j]}' have "
                                f"names that are {ratio:.0%} similar. This "
                                f"could indicate a tool shadowing attack "
                                f"where a malicious tool mimics a "
                                f"legitimate one."
                            )

                        findings.append(
                            Finding(
                                rule_id="MCP03-005",
                                owasp_id="MCP03",
                                title=(f"Similar tool names: '{names[i]}' and '{names[j]}'"),
                                description=description,
                                severity=severity,
                                evidence=(
                                    f"Levenshtein similarity: {ratio:.2%} "
                                    f"(threshold: "
                                    f"{_SIMILARITY_THRESHOLD:.0%})"
                                ),
                                remediation=(
                                    "Investigate tools with similar names. "
                                    "Ensure each tool serves a distinct "
                                    "purpose and is from a trusted source."
                                ),
                                tool_name=names[i],
                                metadata={
                                    "tool_a": names[i],
                                    "tool_b": names[j],
                                    "similarity": round(ratio, 4),
                                    "shared_prefix": shared_prefix,
                                    "prefix_ratio": round(prefix_ratio, 4),
                                    "same_server": True,
                                },
                            )
                        )

        return findings
