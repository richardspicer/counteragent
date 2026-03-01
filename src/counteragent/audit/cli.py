"""CLI for the scan subcommand.

Provides commands for scanning MCP servers, enumerating capabilities,
and generating reports. Maps to the OWASP MCP Top 10.
"""

from __future__ import annotations

import asyncio
import logging
import shlex

import typer
from rich.console import Console
from rich.table import Table

from counteragent.audit.orchestrator import run_scan
from counteragent.audit.reporting.json_report import generate_json_report
from counteragent.audit.reporting.sarif_report import generate_sarif_report
from counteragent.core.connection import MCPConnection
from counteragent.core.discovery import enumerate_server

app = typer.Typer(
    no_args_is_help=True,
    help="Scan MCP servers for security vulnerabilities",
)
console = Console()


def _build_connection(
    transport: str,
    command: str | None,
    url: str | None,
) -> MCPConnection:
    """Create an MCPConnection from CLI arguments.

    Args:
        transport: Transport type ('stdio', 'sse', 'streamable-http').
        command: Server command for stdio transport.
        url: Server URL for SSE or Streamable HTTP transport.

    Returns:
        Configured MCPConnection (not yet connected).

    Raises:
        typer.BadParameter: If required args are missing for the transport.
    """
    if transport == "stdio":
        if not command:
            raise typer.BadParameter("--command is required for stdio transport")
        # Split command string respecting quotes and escaped spaces
        parts = shlex.split(command)
        return MCPConnection.stdio(command=parts[0], args=parts[1:])
    elif transport == "sse":
        if not url:
            raise typer.BadParameter("--url is required for SSE transport")
        return MCPConnection.sse(url=url)
    elif transport == "streamable-http":
        if not url:
            raise typer.BadParameter("--url is required for streamable-http transport")
        return MCPConnection.streamable_http(url=url)
    else:
        raise typer.BadParameter(f"Unknown transport: {transport}")


@app.command()
def scan(
    transport: str = typer.Option(
        ...,
        help="Transport type: 'stdio', 'sse', or 'streamable-http'",
    ),
    command: str | None = typer.Option(
        None,
        help="Server command for stdio transport (e.g., 'python my_server.py')",
    ),
    url: str | None = typer.Option(
        None,
        help="Server URL for SSE or Streamable HTTP transport",
    ),
    checks: str | None = typer.Option(
        None,
        help="Comma-separated list of checks to run (e.g., 'injection')",
    ),
    format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Output format: 'json' or 'sarif'",
    ),
    output: str | None = typer.Option(
        None,
        help="Output file path (default: results/scan.json or results/scan.sarif)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
    ),
) -> None:
    """Scan an MCP server for security vulnerabilities."""
    if format not in ("json", "sarif"):
        raise typer.BadParameter(f"Unknown format: {format}. Use 'json' or 'sarif'.")

    if output is None:
        output = "results/scan.sarif" if format == "sarif" else "results/scan.json"

    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s — %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(name)s — %(message)s")

    console.print("[bold blue]counteragent audit[/bold blue] — MCP Security Scanner\n")

    conn = _build_connection(transport, command, url)
    check_names = [c.strip() for c in checks.split(",")] if checks else None

    async def _do_scan() -> None:
        async with conn:
            console.print(
                f"[green]Connected[/green] to "
                f"{conn.init_result.serverInfo.name if conn.init_result.serverInfo else 'server'} "
                f"via {conn.transport_type}"
            )
            result = await run_scan(conn, check_names=check_names)

            # Summary
            console.print("\n[bold]Scan Complete[/bold]")
            console.print(f"  Tools scanned: {result.tools_scanned}")
            console.print(f"  Scanners run:  {', '.join(result.scanners_run)}")
            console.print(f"  Findings:      {len(result.findings)}")

            if result.findings:
                console.print("\n[bold red]Findings:[/bold red]")
                for f in result.findings:
                    sev_color = {
                        "critical": "red",
                        "high": "bright_red",
                        "medium": "yellow",
                        "low": "blue",
                        "info": "dim",
                    }.get(f.severity.value, "white")
                    console.print(
                        f"  [{sev_color}]{f.severity.value.upper()}[/{sev_color}] {f.title}"
                    )
                    console.print(f"    {f.description}")
                    console.print(f"    Remediation: {f.remediation}")
                    console.print()

            if result.errors:
                console.print(f"\n[yellow]Errors ({len(result.errors)}):[/yellow]")
                for err in result.errors:
                    console.print(f"  {err['scanner']}: {err['error']}")

            # Save report
            if format == "sarif":
                report_path = generate_sarif_report(result, output)
            else:
                report_path = generate_json_report(result, output)
            console.print(f"\n[dim]Report saved to {report_path}[/dim]")

    try:
        asyncio.run(_do_scan())
    except ConnectionError as exc:
        console.print(f"[red]Connection failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        raise typer.Exit(130) from None


@app.command(name="list-checks")
def list_checks() -> None:
    """List all available scanner modules and their OWASP mappings."""
    from counteragent.audit.scanner.registry import _REGISTRY

    console.print("[bold blue]counteragent audit[/bold blue] — Available Checks\n")

    # Full OWASP MCP Top 10 list with implementation status
    all_checks = [
        ("injection", "MCP05", "Command Injection via Tools"),
        ("auth", "MCP07", "Insufficient Authentication/Authorization"),
        ("token_exposure", "MCP01", "Token Mismanagement & Secret Exposure"),
        ("permissions", "MCP02", "Privilege Escalation via Tools"),
        ("tool_poisoning", "MCP03", "Tool Poisoning"),
        ("prompt_injection", "MCP06", "Indirect Prompt Injection"),
        ("audit_telemetry", "MCP08", "Insufficient Audit & Telemetry"),
        ("supply_chain", "MCP04", "Supply Chain & Integrity"),
        ("shadow_servers", "MCP09", "Shadow MCP Servers"),
        ("context_sharing", "MCP10", "Context Over-Sharing"),
    ]

    table = Table(title="Scanner Modules")
    table.add_column("Module", style="cyan")
    table.add_column("OWASP ID", style="green")
    table.add_column("Description")
    table.add_column("Status")

    for module, owasp_id, desc in all_checks:
        status = "[green]Ready[/green]" if module in _REGISTRY else "[dim]Planned[/dim]"
        table.add_row(module, owasp_id, desc, status)

    console.print(table)


@app.command()
def enumerate(
    transport: str = typer.Option(
        ...,
        help="Transport type: 'stdio', 'sse', or 'streamable-http'",
    ),
    command: str | None = typer.Option(
        None,
        help="Server command for stdio transport",
    ),
    url: str | None = typer.Option(
        None,
        help="Server URL for SSE or Streamable HTTP transport",
    ),
) -> None:
    """Enumerate MCP server capabilities without scanning."""
    console.print("[bold blue]counteragent audit[/bold blue] — Server Enumeration\n")

    conn = _build_connection(transport, command, url)

    async def _do_scan() -> None:
        async with conn:
            ctx = await enumerate_server(conn)

            console.print(f"[bold]Server:[/bold] {ctx.server_info.get('name', 'unknown')}")
            console.print(f"[bold]Protocol:[/bold] {ctx.server_info.get('protocolVersion', '?')}")

            if ctx.tools:
                console.print(f"\n[bold]Tools ({len(ctx.tools)}):[/bold]")
                table = Table()
                table.add_column("Name", style="cyan")
                table.add_column("Description")
                table.add_column("Parameters")
                for tool in ctx.tools:
                    params = ", ".join(tool.get("inputSchema", {}).get("properties", {}).keys())
                    table.add_row(tool["name"], tool.get("description", "")[:80], params)
                console.print(table)

            if ctx.resources:
                console.print(f"\n[bold]Resources ({len(ctx.resources)}):[/bold]")
                for r in ctx.resources:
                    console.print(f"  {r['uri']} — {r.get('description', '')}")

            if ctx.prompts:
                console.print(f"\n[bold]Prompts ({len(ctx.prompts)}):[/bold]")
                for p in ctx.prompts:
                    console.print(f"  {p['name']} — {p.get('description', '')}")

    try:
        asyncio.run(_do_scan())
    except ConnectionError as exc:
        console.print(f"[red]Connection failed:[/red] {exc}")
        raise typer.Exit(1) from exc


@app.command()
def report(
    input: str = typer.Option(
        ...,
        help="Path to saved scan results JSON file",
    ),
    format: str = typer.Option(
        "sarif",
        "--format",
        "-f",
        help="Report format: 'json' or 'sarif'",
    ),
    output: str | None = typer.Option(
        None,
        help="Output file path (defaults to input path with new extension)",
    ),
) -> None:
    """Generate a report from saved scan results.

    Loads a JSON scan result file produced by `counteragent audit scan`
    and converts it to the requested format.
    """
    import json as json_mod
    from dataclasses import dataclass, field
    from pathlib import Path
    from typing import Any

    from counteragent.audit.reporting.json_report import dict_to_finding

    console.print("[bold blue]counteragent audit[/bold blue] — Report Generator\n")

    if format not in ("json", "sarif"):
        console.print(f"[red]Unknown format: {format}. Use 'json' or 'sarif'.[/red]")
        raise typer.Exit(1)

    input_path = Path(input)
    if not input_path.exists():
        console.print(f"[red]Input file not found:[/red] {input_path}")
        raise typer.Exit(1)

    # Determine output path
    if output is None:
        ext = ".sarif" if format == "sarif" else ".json"
        output_path = input_path.with_suffix(ext)
    else:
        output_path = Path(output)

    # Load saved scan results
    raw = json_mod.loads(input_path.read_text())
    findings = [dict_to_finding(f) for f in raw.get("findings", [])]

    # Reconstruct a minimal ScanResult-like object for the report generators
    @dataclass
    class _ReportData:
        findings: list[Any] = field(default_factory=list)
        server_info: dict[str, Any] = field(default_factory=dict)
        tools_scanned: int = 0
        scanners_run: list[str] = field(default_factory=list)
        started_at: Any = None
        finished_at: Any = None
        errors: list[dict[str, str]] = field(default_factory=list)

    scan_data = raw.get("scan", {})
    report_data = _ReportData(
        findings=findings,
        server_info=scan_data.get("server", {}),
        tools_scanned=scan_data.get("tools_scanned", 0),
        scanners_run=scan_data.get("scanners_run", []),
        errors=raw.get("errors", []),
    )

    if format == "sarif":
        result_path = generate_sarif_report(report_data, output_path)
    else:
        result_path = generate_json_report(report_data, output_path)

    console.print(f"[green]Report generated:[/green] {result_path}")
