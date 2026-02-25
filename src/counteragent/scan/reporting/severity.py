"""CVSS-aligned severity scoring for scan findings.

Maps scanner findings to CVSS v3.1 severity levels and provides
scoring utilities for report generation.
"""

from counteragent.core.models import Severity

# CVSS v3.1 score ranges mapped to severity levels
CVSS_RANGES: dict[Severity, tuple[float, float]] = {
    Severity.CRITICAL: (9.0, 10.0),
    Severity.HIGH: (7.0, 8.9),
    Severity.MEDIUM: (4.0, 6.9),
    Severity.LOW: (0.1, 3.9),
    Severity.INFO: (0.0, 0.0),
}


def severity_from_cvss(score: float) -> Severity:
    """Convert a CVSS v3.1 score to a Severity level.

    Args:
        score: CVSS v3.1 base score (0.0 to 10.0).

    Returns:
        The corresponding Severity enum value.

    Raises:
        ValueError: If the score is outside the valid range.

    Example:
        >>> severity_from_cvss(9.1)
        <Severity.CRITICAL: 'critical'>
    """
    if not 0.0 <= score <= 10.0:
        raise ValueError(f"CVSS score must be between 0.0 and 10.0, got {score}")

    for severity, (low, high) in CVSS_RANGES.items():
        if low <= score <= high:
            return severity

    return Severity.INFO
