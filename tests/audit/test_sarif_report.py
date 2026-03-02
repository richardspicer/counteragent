"""Tests for SARIF 2.1.0 report generation.

Validates that generate_sarif_report produces spec-compliant SARIF
output with correct severity mapping, rule deduplication, and result
indexing.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from counteragent.audit.reporting.sarif_report import (
    _SEVERITY_MAP,
    _build_rules,
    _sarif_level,
    _security_severity,
    generate_sarif_report,
)
from counteragent.core.models import Finding, Severity

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class _FakeScanResult:
    """Minimal ScanResult stand-in for report generation."""

    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings
        self.server_info: dict = {"name": "test-server"}
        self.tools_scanned = 3
        self.scanners_run = ["injection", "auth"]
        self.started_at = datetime(2025, 1, 1, tzinfo=UTC)
        self.finished_at = datetime(2025, 1, 1, 0, 5, tzinfo=UTC)
        self.errors: list[dict] = []


def _make_finding(
    rule_id: str = "MCP05-001",
    owasp_id: str = "MCP05",
    title: str = "Test finding",
    description: str = "A test vulnerability",
    severity: Severity = Severity.HIGH,
    tool_name: str | None = "run_query",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        owasp_id=owasp_id,
        title=title,
        description=description,
        severity=severity,
        evidence="test evidence",
        remediation="fix it",
        tool_name=tool_name,
        metadata={"payload": "test"},
        timestamp=datetime(2025, 1, 1, 0, 2, tzinfo=UTC),
    )


@pytest.fixture()
def sample_findings() -> list[Finding]:
    return [
        _make_finding(
            rule_id="MCP05-001",
            owasp_id="MCP05",
            title="Command injection",
            severity=Severity.CRITICAL,
        ),
        _make_finding(
            rule_id="MCP07-001",
            owasp_id="MCP07",
            title="Missing auth",
            severity=Severity.HIGH,
        ),
        _make_finding(
            rule_id="MCP05-001",
            owasp_id="MCP05",
            title="Command injection duplicate",
            severity=Severity.CRITICAL,
        ),
        _make_finding(
            rule_id="MCP02-001",
            owasp_id="MCP02",
            title="Privilege escalation",
            severity=Severity.MEDIUM,
        ),
    ]


@pytest.fixture()
def sarif_output(sample_findings: list[Finding], tmp_path: Path) -> dict:
    """Generate SARIF and return parsed JSON."""
    result = _FakeScanResult(sample_findings)
    out = tmp_path / "scan.sarif"
    generate_sarif_report(result, out)
    return json.loads(out.read_text())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSarifReportStructure:
    """Test SARIF 2.1.0 top-level structure."""

    def test_top_level_keys(self, sarif_output: dict) -> None:
        """SARIF output has required top-level keys."""
        assert sarif_output["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert sarif_output["version"] == "2.1.0"
        assert "runs" in sarif_output
        assert len(sarif_output["runs"]) == 1

    def test_tool_driver(self, sarif_output: dict) -> None:
        """Tool driver has name, version, informationUri, and rules."""
        driver = sarif_output["runs"][0]["tool"]["driver"]
        assert driver["name"] == "counteragent"
        assert "version" in driver
        assert "informationUri" in driver
        assert "rules" in driver


class TestSarifRulesDeduplication:
    """Test that rules are deduplicated by rule_id."""

    def test_unique_rules(self, sarif_output: dict) -> None:
        """Multiple findings with same rule_id produce one rule entry."""
        rules = sarif_output["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        # 4 findings but only 3 unique rule_ids
        assert len(rules) == 3
        assert rule_ids == ["MCP05-001", "MCP07-001", "MCP02-001"]

    def test_first_occurrence_wins(self, sample_findings: list[Finding]) -> None:
        """When rule_id repeats, first finding's metadata is used."""
        rules = _build_rules(sample_findings)
        mcp05_rule = next(r for r in rules if r["id"] == "MCP05-001")
        assert mcp05_rule["name"] == "Command injection"


class TestSarifSeverityMapping:
    """Test Finding.severity → SARIF level + security-severity."""

    @pytest.mark.parametrize(
        ("severity", "expected_level", "expected_score"),
        [
            (Severity.CRITICAL, "error", 9.0),
            (Severity.HIGH, "error", 7.0),
            (Severity.MEDIUM, "warning", 4.0),
            (Severity.LOW, "note", 0.1),
            (Severity.INFO, "note", 0.0),
        ],
    )
    def test_severity_mapping(
        self, severity: Severity, expected_level: str, expected_score: float
    ) -> None:
        """Each severity maps to correct SARIF level and score."""
        assert _sarif_level(severity) == expected_level
        assert _security_severity(severity) == expected_score

    def test_all_severities_covered(self) -> None:
        """Every Severity enum member has a mapping."""
        for sev in Severity:
            assert sev in _SEVERITY_MAP


class TestSarifResultCount:
    """Test result count matches finding count."""

    def test_result_count(self, sarif_output: dict) -> None:
        """Number of results equals number of findings."""
        results = sarif_output["runs"][0]["results"]
        assert len(results) == 4


class TestSarifEmptyFindings:
    """Test SARIF output with zero findings."""

    def test_empty_findings(self, tmp_path: Path) -> None:
        """Zero findings produces valid SARIF with empty results and rules."""
        result = _FakeScanResult([])
        out = tmp_path / "empty.sarif"
        generate_sarif_report(result, out)
        sarif = json.loads(out.read_text())

        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []


class TestSarifRuleIndexConsistency:
    """Test ruleIndex references are correct."""

    def test_rule_index_matches(self, sarif_output: dict) -> None:
        """Each result's ruleIndex points to its rule in the rules array."""
        run = sarif_output["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        for result in run["results"]:
            idx = result["ruleIndex"]
            assert 0 <= idx < len(rules)
            assert rules[idx]["id"] == result["ruleId"]


class TestSarifSchemaValidation:
    """Validate SARIF output against the 2.1.0 JSON Schema."""

    def test_schema_validation(self, sarif_output: dict) -> None:
        """Output validates against SARIF 2.1.0 JSON Schema."""
        jsonschema = pytest.importorskip("jsonschema")

        # Minimal SARIF 2.1.0 schema for structural validation.
        # The full schema is large; this covers required keys and types
        # that GitHub Code Scanning checks.
        schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "required": ["$schema", "version", "runs"],
            "properties": {
                "$schema": {"type": "string"},
                "version": {"type": "string", "const": "2.1.0"},
                "runs": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "required": ["tool", "results"],
                        "properties": {
                            "tool": {
                                "type": "object",
                                "required": ["driver"],
                                "properties": {
                                    "driver": {
                                        "type": "object",
                                        "required": [
                                            "name",
                                            "version",
                                            "informationUri",
                                            "rules",
                                        ],
                                        "properties": {
                                            "name": {"type": "string"},
                                            "version": {"type": "string"},
                                            "informationUri": {
                                                "type": "string",
                                                "format": "uri",
                                            },
                                            "rules": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "required": ["id"],
                                                    "properties": {
                                                        "id": {"type": "string"},
                                                        "name": {"type": "string"},
                                                        "properties": {
                                                            "type": "object",
                                                            "required": ["security-severity"],
                                                        },
                                                    },
                                                },
                                            },
                                        },
                                    }
                                },
                            },
                            "results": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": [
                                        "ruleId",
                                        "ruleIndex",
                                        "level",
                                        "message",
                                    ],
                                    "properties": {
                                        "ruleId": {"type": "string"},
                                        "ruleIndex": {
                                            "type": "integer",
                                            "minimum": 0,
                                        },
                                        "level": {
                                            "type": "string",
                                            "enum": [
                                                "none",
                                                "note",
                                                "warning",
                                                "error",
                                            ],
                                        },
                                        "message": {
                                            "type": "object",
                                            "required": ["text"],
                                            "properties": {"text": {"type": "string"}},
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        }

        jsonschema.validate(sarif_output, schema)

    def test_empty_sarif_schema_validation(self, tmp_path: Path) -> None:
        """Empty-findings SARIF also validates against schema."""
        jsonschema = pytest.importorskip("jsonschema")

        result = _FakeScanResult([])
        out = tmp_path / "empty.sarif"
        generate_sarif_report(result, out)
        sarif = json.loads(out.read_text())

        # Same structural schema — just validate it doesn't fail
        schema = {
            "type": "object",
            "required": ["$schema", "version", "runs"],
            "properties": {
                "version": {"const": "2.1.0"},
                "runs": {"type": "array", "minItems": 1},
            },
        }
        jsonschema.validate(sarif, schema)


class TestSarifSecuritySeverityOnRules:
    """Verify security-severity property is present on all rules."""

    def test_all_rules_have_security_severity(self, sarif_output: dict) -> None:
        """Every rule has a security-severity property (required for GitHub)."""
        rules = sarif_output["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            props = rule.get("properties", {})
            assert "security-severity" in props
            # Must be a string representation of a float
            float(props["security-severity"])


class TestDictToFinding:
    """Test round-trip finding serialization."""

    def test_round_trip(self) -> None:
        """finding_to_dict -> dict_to_finding produces equivalent Finding."""
        from counteragent.audit.reporting.json_report import (
            dict_to_finding,
            finding_to_dict,
        )

        original = _make_finding()
        serialized = finding_to_dict(original)
        restored = dict_to_finding(serialized)

        assert restored.rule_id == original.rule_id
        assert restored.owasp_id == original.owasp_id
        assert restored.title == original.title
        assert restored.severity == original.severity
        assert restored.evidence == original.evidence
        assert restored.tool_name == original.tool_name
        assert restored.metadata == original.metadata
