"""CLI for the scan subcommand — mcp-audit migration target."""

import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def run() -> None:
    """Run security scan against an MCP server. [Not yet migrated]"""
    typer.echo("scan module not yet migrated — see Phase B")
    raise typer.Exit(code=1)


@app.command("list-checks")
def list_checks() -> None:
    """List available security checks. [Not yet migrated]"""
    typer.echo("scan module not yet migrated — see Phase B")
    raise typer.Exit(code=1)
