"""Scanner base class and re-exports from core.models.

BaseScanner is scan-specific. Severity, Finding, and ScanContext are
re-exported from counteragent.core.models for backward compatibility.
"""

from abc import ABC, abstractmethod

from counteragent.core.models import Finding, ScanContext, Severity

__all__ = ["BaseScanner", "Finding", "ScanContext", "Severity"]


class BaseScanner(ABC):
    """Abstract base class for all scanner modules.

    Each scanner targets a specific OWASP MCP Top 10 category.
    Subclasses must implement `scan()` which returns a list of Findings.

    Attributes:
        name: Human-readable scanner name.
        owasp_id: Primary OWASP MCP Top 10 category this scanner covers.
        description: What this scanner checks for.

    Example:
        >>> class InjectionScanner(BaseScanner):
        ...     name = "injection"
        ...     owasp_id = "MCP05"
        ...     description = "Tests for command injection via MCP tools"
        ...
        ...     async def scan(self, context: ScanContext) -> list[Finding]:
        ...         findings = []
        ...         # ... test each tool for injection ...
        ...         return findings
    """

    name: str = ""
    owasp_id: str = ""
    description: str = ""

    @abstractmethod
    async def scan(self, context: ScanContext) -> list[Finding]:
        """Execute the scanner against the target MCP server.

        Args:
            context: ScanContext containing server metadata, tools,
                resources, and configuration.

        Returns:
            List of Finding objects for any vulnerabilities detected.

        Raises:
            ScanError: If the scanner encounters an unrecoverable error.
        """
        ...
