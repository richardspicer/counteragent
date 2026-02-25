"""CLI for the scan subcommand.

Provides commands for scanning MCP servers, enumerating capabilities,
and generating reports. Maps to the OWASP MCP Top 10.
"""

from __future__ import annotations

import asyncio
import logging

import typer
from rich.console import Console
from rich.table import Table

from counteragent.core.connection import MCPConnection
from counteragent.core.discovery import enumerate_server
from counteragent.scan.orchestrator import run_scan
from counteragent.scan.reporting.json_report import generate_json_report

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
        # Split command string into executable + args
        parts = command.split()
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
def run(
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
    output: str = typer.Option(
        "results/scan.json",
        help="Output file path for scan results",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
    ),
) -> None:
    """Scan an MCP server for security vulnerabilities."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s — %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(name)s — %(message)s")

    console.print("[bold blue]counteragent scan[/bold blue] — MCP Security Scanner\n")

    conn = _build_connection(transport, command, url)
    check_names = [c.strip() for c in checks.split(",")] if checks else None

    async def _run() -> None:
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
            report_path = generate_json_report(result, output)
            console.print(f"\n[dim]Report saved to {report_path}[/dim]")

    try:
        asyncio.run(_run())
    except ConnectionError as exc:
        console.print(f"[red]Connection failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        raise typer.Exit(130) from None


@app.command(name="list-checks")
def list_checks() -> None:
    """List all available scanner modules and their OWASP mappings."""
    from counteragent.scan.scanner.registry import _REGISTRY

    console.print("[bold blue]counteragent scan[/bold blue] — Available Checks\n")

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
    console.print("[bold blue]counteragent scan[/bold blue] — Server Enumeration\n")

    conn = _build_connection(transport, command, url)

    async def _run() -> None:
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
        asyncio.run(_run())
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
        "html",
        help="Report format: 'html', 'json', or 'sarif'",
    ),
    output: str | None = typer.Option(
        None,
        help="Output file path (defaults to input path with new extension)",
    ),
) -> None:
    """Generate a report from saved scan results."""
    console.print("[bold blue]counteragent scan[/bold blue] — Report Generator")
    # TODO: Implement HTML and SARIF report generation
    console.print("[yellow]Report generation not yet implemented — coming soon.[/yellow]")
