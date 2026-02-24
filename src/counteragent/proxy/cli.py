"""CLI for the proxy subcommand — mcp-proxy migration target."""

import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def start() -> None:
    """Start MCP traffic interceptor. [Not yet migrated]"""
    typer.echo("proxy module not yet migrated — see Phase C")
    raise typer.Exit(code=1)
