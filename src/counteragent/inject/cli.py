"""CLI for the inject subcommand — Phase 2 placeholder."""

import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def run() -> None:
    """Run injection campaign against an agent. [Phase 2 — not yet implemented]"""
    typer.echo("inject module not yet implemented — see Phase 2")
    raise typer.Exit(code=1)
