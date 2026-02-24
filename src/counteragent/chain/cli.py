"""CLI for the chain subcommand — Phase 3 placeholder."""

import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def run() -> None:
    """Run attack chain simulation. [Phase 3 — not yet implemented]"""
    typer.echo("chain module not yet implemented — see Phase 3")
    raise typer.Exit(code=1)
