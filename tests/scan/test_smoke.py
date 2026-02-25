"""Smoke tests for counteragent package."""

from counteragent import __version__
from counteragent.core.models import Finding, ScanContext, Severity


def test_version():
    """Package version is set."""
    assert __version__ == "0.1.0"


def test_severity_levels():
    """All severity levels are defined."""
    assert len(Severity) == 5
    assert Severity.CRITICAL.value == "critical"


def test_finding_creation():
    """Finding dataclass can be instantiated with required fields."""
    finding = Finding(
        rule_id="MCP05-001",
        owasp_id="MCP05",
        title="Test finding",
        description="Test description",
        severity=Severity.HIGH,
    )
    assert finding.rule_id == "MCP05-001"
    assert finding.severity == Severity.HIGH
    assert finding.tool_name is None


def test_scan_context_defaults():
    """ScanContext has sensible defaults."""
    ctx = ScanContext()
    assert ctx.tools == []
    assert ctx.resources == []
    assert ctx.transport_type == "stdio"
