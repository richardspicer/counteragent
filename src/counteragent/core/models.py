"""Shared data models for counteragent.

Contains core types used across scan, proxy, and other subcommands.
Severity, Finding, and ScanContext are consumed by all scanner modules
and the orchestration layer.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """CVSS-aligned severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A single security finding from a scanner module.

    Attributes:
        rule_id: Unique identifier for this check (e.g., 'MCP05-001').
        owasp_id: OWASP MCP Top 10 category (e.g., 'MCP05').
        title: Short human-readable title.
        description: Detailed description of the vulnerability.
        severity: CVSS-aligned severity level.
        evidence: Raw evidence supporting the finding (e.g., server response).
        remediation: Recommended fix or mitigation.
        tool_name: Name of the MCP tool that triggered the finding, if applicable.
        metadata: Additional context (e.g., payload used, response time).
        timestamp: When the finding was generated.

    Example:
        >>> finding = Finding(
        ...     rule_id="MCP05-001",
        ...     owasp_id="MCP05",
        ...     title="Command injection in 'run_query' tool",
        ...     description="The tool parameter 'query' is passed to a shell...",
        ...     severity=Severity.CRITICAL,
        ...     evidence="Server returned shell output for injected payload",
        ...     remediation="Sanitize input parameters before shell execution",
        ...     tool_name="run_query",
        ... )
    """

    rule_id: str
    owasp_id: str
    title: str
    description: str
    severity: Severity
    evidence: str = ""
    remediation: str = ""
    tool_name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class ScanContext:
    """Context passed to each scanner module during a scan.

    Attributes:
        server_info: Server metadata from MCP initialization.
        tools: List of tools exposed by the server.
        resources: List of resources exposed by the server.
        prompts: List of prompts exposed by the server.
        transport_type: Transport used to connect ('stdio', 'sse', 'streamable-http').
        connection_url: Server URL for HTTP-based transports (SSE, Streamable HTTP).
            None for stdio connections. Used by auth scanner for TLS and port checks.
        session: The active MCP ClientSession for calling tools/resources.
            Type is Any to avoid coupling scanner modules to the SDK.
        config: Scanner-specific configuration overrides.
    """

    server_info: dict[str, Any] = field(default_factory=dict)
    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    transport_type: str = "stdio"
    connection_url: str | None = None
    session: Any = None
    config: dict[str, Any] = field(default_factory=dict)
