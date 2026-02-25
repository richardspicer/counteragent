"""Root CLI for CounterAgent — mounts all subcommand apps."""

import typer

from counteragent.audit.cli import app as audit_app
from counteragent.chain.cli import app as chain_app
from counteragent.inject.cli import app as inject_app
from counteragent.proxy.cli import app as proxy_app

app = typer.Typer(
    name="counteragent",
    help="AI Agent Red Team Platform — OWASP MCP Top 10",
    no_args_is_help=True,
)

app.add_typer(audit_app, name="audit", help="Scan MCP servers for vulnerabilities")
app.add_typer(proxy_app, name="proxy", help="Intercept and replay MCP traffic")
app.add_typer(inject_app, name="inject", help="Tool poisoning & prompt injection [Phase 2]")
app.add_typer(chain_app, name="chain", help="Multi-agent attack chains [Phase 3]")
