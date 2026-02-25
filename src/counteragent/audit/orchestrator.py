"""Scan orchestrator.

Coordinates the full scan lifecycle: connect to server, enumerate
capabilities, run selected scanners, collect findings. This is the
main entry point called by the CLI's scan command.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from counteragent.audit.scanner.registry import get_all_scanners, get_scanner
from counteragent.core.connection import MCPConnection
from counteragent.core.discovery import enumerate_server
from counteragent.core.models import Finding

logger = logging.getLogger("counteragent.audit.orchestrator")


@dataclass
class ScanResult:
    """Complete results from a scan run.

    Attributes:
        findings: All findings from all scanners.
        server_info: Server metadata from the MCP handshake.
        tools_scanned: Number of tools that were tested.
        scanners_run: Names of scanners that were executed.
        started_at: When the scan started.
        finished_at: When the scan completed.
        errors: Any scanner-level errors that occurred.
    """

    findings: list[Finding] = field(default_factory=list)
    server_info: dict[str, Any] = field(default_factory=dict)
    tools_scanned: int = 0
    scanners_run: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    errors: list[dict[str, str]] = field(default_factory=list)


async def run_scan(
    conn: MCPConnection,
    check_names: list[str] | None = None,
) -> ScanResult:
    """Execute a full scan against a connected MCP server.

    Enumerates the server's capabilities, then runs each selected
    scanner module and collects findings.

    Args:
        conn: An active MCPConnection (already entered as context manager).
        check_names: Optional list of scanner names to run. If None,
            runs all registered scanners.

    Returns:
        ScanResult with all findings and metadata.

    Example:
        async with MCPConnection.stdio("python", ["server.py"]) as conn:
            result = await run_scan(conn)
            for f in result.findings:
                print(f"{f.severity.value}: {f.title}")
    """
    result = ScanResult()

    # Enumerate server capabilities
    logger.info("Enumerating server capabilities...")
    context = await enumerate_server(conn)
    result.server_info = context.server_info
    result.tools_scanned = len(context.tools)

    logger.info(
        "Found %d tools, %d resources, %d prompts",
        len(context.tools),
        len(context.resources),
        len(context.prompts),
    )

    # Select scanners
    if check_names:
        scanners = []
        for name in check_names:
            try:
                scanners.append(get_scanner(name))
            except KeyError as exc:
                result.errors.append({"scanner": name, "error": str(exc)})
                logger.error("Scanner not found: %s", name)
    else:
        scanners = get_all_scanners()

    # Run each scanner
    for scanner in scanners:
        logger.info("Running scanner: %s (%s)", scanner.name, scanner.owasp_id)
        result.scanners_run.append(scanner.name)

        try:
            findings = await scanner.scan(context)
            result.findings.extend(findings)
            logger.info("Scanner %s complete — %d findings", scanner.name, len(findings))
        except Exception as exc:
            logger.error("Scanner %s failed: %s", scanner.name, exc, exc_info=True)
            result.errors.append(
                {
                    "scanner": scanner.name,
                    "error": str(exc),
                }
            )

    result.finished_at = datetime.now(UTC)
    return result
