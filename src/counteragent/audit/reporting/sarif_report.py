"""SARIF 2.1.0 report output for scan results.

Serializes ScanResult into a SARIF 2.1.0 JSON document suitable
for GitHub Code Scanning integration (upload-sarif action) and
other SARIF-compatible tools.
"""

from __future__ import annotations

import json
from importlib.metadata import version
from pathlib import Path
from typing import Any

from counteragent.core.models import Finding, Severity

# SARIF severity mapping: Finding.severity → (SARIF level, security-severity score)
_SEVERITY_MAP: dict[Severity, tuple[str, float]] = {
    Severity.CRITICAL: ("error", 9.0),
    Severity.HIGH: ("error", 7.0),
    Severity.MEDIUM: ("warning", 4.0),
    Severity.LOW: ("note", 0.1),
    Severity.INFO: ("note", 0.0),
}


def _sarif_level(severity: Severity) -> str:
    """Map a Finding severity to a SARIF level string.

    Args:
        severity: The Finding severity enum value.

    Returns:
        SARIF level: 'error', 'warning', or 'note'.
    """
    return _SEVERITY_MAP[severity][0]


def _security_severity(severity: Severity) -> float:
    """Map a Finding severity to a SARIF security-severity score.

    Args:
        severity: The Finding severity enum value.

    Returns:
        Numeric security-severity value for GitHub Code Scanning.
    """
    return _SEVERITY_MAP[severity][1]


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """Build deduplicated SARIF rule objects from findings.

    Each unique rule_id produces exactly one rule entry. If multiple
    findings share a rule_id, the first occurrence determines the
    rule metadata.

    Args:
        findings: All findings from the scan.

    Returns:
        List of SARIF rule objects, ordered by first appearance.
    """
    seen: dict[str, int] = {}
    rules: list[dict[str, Any]] = []

    for finding in findings:
        if finding.rule_id in seen:
            continue

        level = _sarif_level(finding.severity)
        score = _security_severity(finding.severity)

        rule: dict[str, Any] = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "defaultConfiguration": {"level": level},
            "helpUri": (
                "https://github.com/richardspicer/counteragent"
                f"/blob/main/docs/owasp_mapping.md#{finding.owasp_id}"
            ),
            "properties": {
                "security-severity": str(score),
                "tags": ["security", finding.owasp_id],
            },
        }
        seen[finding.rule_id] = len(rules)
        rules.append(rule)

    return rules


def _build_results(
    findings: list[Finding],
    rule_index: dict[str, int],
) -> list[dict[str, Any]]:
    """Build SARIF result objects from findings.

    Args:
        findings: All findings from the scan.
        rule_index: Mapping of rule_id to index in the rules array.

    Returns:
        List of SARIF result objects, one per finding.
    """
    results: list[dict[str, Any]] = []

    for finding in findings:
        level = _sarif_level(finding.severity)

        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": level,
            "message": {"text": finding.description},
            "properties": {
                "owasp_id": finding.owasp_id,
                "tool_name": finding.tool_name,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
                "metadata": finding.metadata,
            },
        }
        results.append(result)

    return results


def generate_sarif_report(scan_result: Any, output_path: str | Path) -> Path:
    """Generate a SARIF 2.1.0 report from scan results.

    Produces a JSON file conforming to the SARIF 2.1.0 specification,
    suitable for upload to GitHub Code Scanning via the upload-sarif
    action. Findings are mapped to rules (deduplicated by rule_id)
    and results (one per finding).

    Args:
        scan_result: A ScanResult from the orchestrator.
        output_path: File path to write the SARIF report.

    Returns:
        Path to the written report file.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rules = _build_rules(scan_result.findings)
    rule_index = {rule["id"]: idx for idx, rule in enumerate(rules)}
    results = _build_results(scan_result.findings, rule_index)

    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "counteragent",
                        "version": version("counteragent"),
                        "informationUri": ("https://github.com/richardspicer/counteragent"),
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    output_path.write_text(json.dumps(sarif, indent=2, default=str))
    return output_path
