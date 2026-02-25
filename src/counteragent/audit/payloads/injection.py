"""Command injection payload library for MCP05 testing.

Provides categorized payloads for detecting command injection
vulnerabilities in MCP tool parameters. Payloads use canary markers
that appear in output only if injection succeeds.

Each payload includes a canary string that scanners check for in
the tool's response to determine if injection occurred.

Payload categories:
- shell: Shell metacharacter injection (CWE-78)
- argument: Argument/flag injection (CWE-88)
- path_traversal: Path traversal (CWE-22)
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

# Unique marker that should never appear in legitimate output.
# If this shows up in a tool response, injection succeeded.
CANARY = "MCP_AUDIT_CANARY_7f3a9b2e"


@dataclass(frozen=True)
class InjectionPayload:
    """A single injection test payload.

    Attributes:
        value: The string to inject into a tool parameter.
        canary: The marker to look for in the response.
        technique: Human-readable name of the injection technique.
        platform: Target OS ('unix', 'windows', 'any').
        description: What this payload tests for.
        detection_mode: How to detect success — 'canary', 'pattern', or 'error_based'.
        response_patterns: Regex patterns to match on response (for 'pattern' mode).
    """

    value: str
    canary: str
    technique: str
    platform: str = "any"
    description: str = ""
    detection_mode: str = "canary"
    response_patterns: tuple[str, ...] = field(default_factory=tuple)


def _unix_payloads() -> list[InjectionPayload]:
    """Unix/Linux command injection payloads (CWE-78)."""
    return [
        InjectionPayload(
            value=f"; echo {CANARY}",
            canary=CANARY,
            technique="semicolon_chaining",
            platform="unix",
            description="Semicolon command separator — terminates prior command, runs echo",
        ),
        InjectionPayload(
            value=f"| echo {CANARY}",
            canary=CANARY,
            technique="pipe_injection",
            platform="unix",
            description="Pipe operator — pipes prior output into echo canary",
        ),
        InjectionPayload(
            value=f"&& echo {CANARY}",
            canary=CANARY,
            technique="and_chaining",
            platform="unix",
            description="AND operator — runs echo if prior command succeeds",
        ),
        InjectionPayload(
            value=f"|| echo {CANARY}",
            canary=CANARY,
            technique="or_chaining",
            platform="unix",
            description="OR operator — runs echo if prior command fails",
        ),
        InjectionPayload(
            value=f"$(echo {CANARY})",
            canary=CANARY,
            technique="command_substitution_dollar",
            platform="unix",
            description="Dollar-paren command substitution",
        ),
        InjectionPayload(
            value=f"`echo {CANARY}`",
            canary=CANARY,
            technique="command_substitution_backtick",
            platform="unix",
            description="Backtick command substitution",
        ),
        InjectionPayload(
            value=f"\necho {CANARY}\n",
            canary=CANARY,
            technique="newline_injection",
            platform="unix",
            description="Newline injection — starts new command on new line",
        ),
    ]


def _windows_payloads() -> list[InjectionPayload]:
    """Windows command injection payloads (CWE-78)."""
    return [
        InjectionPayload(
            value=f"& echo {CANARY}",
            canary=CANARY,
            technique="ampersand_chaining",
            platform="windows",
            description="Ampersand command separator (Windows CMD)",
        ),
        InjectionPayload(
            value=f"| echo {CANARY}",
            canary=CANARY,
            technique="pipe_injection",
            platform="windows",
            description="Pipe operator (Windows CMD)",
        ),
        InjectionPayload(
            value=f"&& echo {CANARY}",
            canary=CANARY,
            technique="and_chaining",
            platform="windows",
            description="AND operator (Windows CMD)",
        ),
        InjectionPayload(
            value=f"|| echo {CANARY}",
            canary=CANARY,
            technique="or_chaining",
            platform="windows",
            description="OR operator (Windows CMD)",
        ),
    ]


def _argument_injection_payloads() -> list[InjectionPayload]:
    """Argument/flag injection payloads (CWE-88).

    These detect tools that pass user input as subprocess arguments
    without sanitizing flag-like values. When a value like '--help'
    is interpreted as a CLI flag instead of a data argument, argument
    injection is confirmed.
    """
    return [
        InjectionPayload(
            value="--help",
            canary="",
            technique="flag_injection_help",
            platform="any",
            description="Flag injection via --help — triggers help text if interpreted as flag",
            detection_mode="pattern",
            response_patterns=(
                r"(?i)usage:",
                r"(?i)options:",
                r"(?i)--help",
                r"(?i)SYNOPSIS",
            ),
        ),
        InjectionPayload(
            value="--version",
            canary="",
            technique="flag_injection_version",
            platform="any",
            description="Flag injection via --version — triggers version output if interpreted",
            detection_mode="pattern",
            response_patterns=(
                r"(?i)version \d+\.\d+",
                r"(?i)git version \d+",
                r"(?i)\d+\.\d+\.\d+",
            ),
        ),
        InjectionPayload(
            value="--output=/dev/null",
            canary="",
            technique="flag_injection_output",
            platform="unix",
            description="Flag injection via --output — redirects output if interpreted as flag",
            detection_mode="error_based",
            response_patterns=(),
        ),
        InjectionPayload(
            value=f"--exec=echo {CANARY}",
            canary=CANARY,
            technique="flag_injection_exec",
            platform="unix",
            description="Flag injection via --exec — executes command if interpreted as flag",
            detection_mode="canary",
            response_patterns=(),
        ),
        InjectionPayload(
            value="-o /dev/null",
            canary="",
            technique="short_flag_injection",
            platform="unix",
            description="Short flag injection via -o — redirects output if interpreted",
            detection_mode="error_based",
            response_patterns=(),
        ),
    ]


def _path_traversal_payloads() -> list[InjectionPayload]:
    """Path traversal payloads (CWE-22).

    These detect tools that use path parameters without validating
    directory boundaries. If the response contains content from
    outside the expected directory, traversal succeeded.
    """
    return [
        InjectionPayload(
            value="../../../etc/passwd",
            canary="",
            technique="path_traversal_unix",
            platform="unix",
            description="Unix path traversal via ../ sequences",
            detection_mode="pattern",
            response_patterns=(
                r"root:.*:0:0:",
                r"/bin/bash",
                r"/bin/sh",
            ),
        ),
        InjectionPayload(
            value="..%2F..%2F..%2Fetc%2Fpasswd",
            canary="",
            technique="path_traversal_encoded",
            platform="unix",
            description="URL-encoded path traversal via %2F sequences",
            detection_mode="pattern",
            response_patterns=(
                r"root:.*:0:0:",
                r"/bin/bash",
                r"/bin/sh",
            ),
        ),
        InjectionPayload(
            value="....//....//....//etc/passwd",
            canary="",
            technique="path_traversal_double_dot",
            platform="unix",
            description="Double-dot path traversal bypass via ....// sequences",
            detection_mode="pattern",
            response_patterns=(
                r"root:.*:0:0:",
                r"/bin/bash",
                r"/bin/sh",
            ),
        ),
        InjectionPayload(
            value="..\\..\\..\\windows\\win.ini",
            canary="",
            technique="path_traversal_windows",
            platform="windows",
            description="Windows path traversal via ..\\ sequences",
            detection_mode="pattern",
            response_patterns=(
                r"(?i)\[fonts\]",
                r"(?i)\[extensions\]",
                r"(?i)for 16-bit app support",
            ),
        ),
    ]


# Map of category names to payload functions.
_CATEGORY_MAP: dict[str, Callable[[], list[InjectionPayload]]] = {
    "shell": lambda: _unix_payloads() + _windows_payloads(),
    "argument": _argument_injection_payloads,
    "path_traversal": _path_traversal_payloads,
}


def get_injection_payloads(
    platform: str = "all",
    categories: list[str] | None = None,
) -> list[InjectionPayload]:
    """Get injection payloads filtered by platform and category.

    Args:
        platform: Target platform filter. Options:
            - 'all': All payloads (unix + windows + any)
            - 'unix': Unix/Linux payloads + platform-agnostic
            - 'windows': Windows payloads + platform-agnostic
        categories: Payload categories to include. Options:
            - None: All categories (shell, argument, path_traversal)
            - List of category names to include (e.g., ['shell', 'argument'])

    Returns:
        List of InjectionPayload objects for testing.

    Example:
        >>> payloads = get_injection_payloads(platform="unix", categories=["shell"])
        >>> for p in payloads:
        ...     print(f"{p.technique}: {p.value!r}")
    """
    cats = list(_CATEGORY_MAP.keys()) if categories is None else categories

    payloads: list[InjectionPayload] = []
    for cat in cats:
        if cat in _CATEGORY_MAP:
            payloads.extend(_CATEGORY_MAP[cat]())

    if platform == "all":
        return payloads

    return [p for p in payloads if p.platform in (platform, "any")]
