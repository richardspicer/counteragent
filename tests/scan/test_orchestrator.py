"""Tests for the scan orchestrator.

End-to-end tests that run the full scan pipeline:
connect -> enumerate -> scan -> collect findings.
"""

import sys

import pytest

from counteragent.core.connection import MCPConnection
from counteragent.scan.orchestrator import run_scan

VULN_INJECTION_SERVER = "fixtures/vulnerable_servers/vuln_injection.py"
PYTHON = sys.executable


class TestOrchestrator:
    """End-to-end orchestrator tests."""

    @pytest.mark.asyncio
    async def test_full_scan(self):
        """Full scan pipeline produces findings."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            result = await run_scan(conn)

            assert result.tools_scanned == 4
            assert "injection" in result.scanners_run
            assert len(result.findings) >= 1
            assert result.finished_at is not None
            assert result.errors == []

    @pytest.mark.asyncio
    async def test_scan_with_specific_checks(self):
        """Can filter to specific scanner modules."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            result = await run_scan(conn, check_names=["injection"])

            assert result.scanners_run == ["injection"]
            assert len(result.findings) >= 1

    @pytest.mark.asyncio
    async def test_scan_with_unknown_check(self):
        """Unknown check names are recorded as errors."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            result = await run_scan(conn, check_names=["nonexistent"])

            assert len(result.errors) == 1
            assert "nonexistent" in result.errors[0]["error"]
