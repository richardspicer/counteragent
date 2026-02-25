"""CLI for the proxy subcommand — MCP traffic interceptor.

Provides commands for starting the interactive proxy, replaying captured
sessions, exporting session data, and inspecting session contents.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer

from counteragent.core.models import Transport

if TYPE_CHECKING:
    from counteragent.proxy.replay import ReplayResult, ReplaySessionResult

app = typer.Typer(
    no_args_is_help=True,
    help="Intercept and replay MCP traffic",
)

_VALID_TRANSPORTS = ("stdio", "sse", "streamable-http")


@app.command()
def start(
    transport: str = typer.Option(
        ...,
        help="MCP transport type: 'stdio', 'sse', or 'streamable-http'.",
    ),
    target_command: str | None = typer.Option(
        None,
        help="Server command (stdio only).",
    ),
    target_url: str | None = typer.Option(
        None,
        help="Server URL (SSE/HTTP only).",
    ),
    intercept: bool = typer.Option(
        False,
        help="Start in intercept mode.",
    ),
    listen_port: int = typer.Option(
        8888,
        help="Local port for SSE/HTTP.",
    ),
    session_file: str | None = typer.Option(
        None,
        help="Auto-save session to this file.",
    ),
) -> None:
    """Start the proxy with TUI."""
    transport_lower = transport.lower()
    if transport_lower not in _VALID_TRANSPORTS:
        typer.echo(
            f"Error: Invalid transport '{transport}'. "
            f"Must be one of: {', '.join(_VALID_TRANSPORTS)}",
            err=True,
        )
        raise typer.Exit(code=1)

    if transport_lower == "stdio" and not target_command:
        typer.echo("Error: --target-command is required for stdio transport.", err=True)
        raise typer.Exit(code=1)
    if transport_lower in ("sse", "streamable-http") and not target_url:
        typer.echo("Error: --target-url is required for SSE/HTTP transport.", err=True)
        raise typer.Exit(code=1)

    from counteragent.proxy.tui.app import ProxyApp

    transport_enum = Transport(transport_lower.replace("-", "_"))
    tui_app = ProxyApp(
        transport=transport_enum,
        server_command=target_command,
        server_url=target_url,
        intercept=intercept,
        session_file=Path(session_file) if session_file else None,
    )
    tui_app.run()


@app.command()
def replay(
    session_file: str = typer.Option(
        ...,
        help="Path to a saved session file.",
    ),
    target_command: str | None = typer.Option(
        None,
        help="Server command for replay (stdio).",
    ),
    target_url: str | None = typer.Option(
        None,
        help="Server URL for replay (SSE/HTTP, future).",
    ),
    output: str | None = typer.Option(
        None,
        help="Save replay results to JSON.",
    ),
    timeout: float = typer.Option(
        10.0,
        help="Per-message response timeout (seconds).",
    ),
    no_handshake: bool = typer.Option(
        False,
        "--no-handshake",
        help="Skip auto-handshake (if session already includes initialize).",
    ),
) -> None:
    """Replay a saved session against a live server."""
    import asyncio
    import shlex

    from counteragent.core.models import Direction
    from counteragent.proxy.session_store import SessionStore

    if not target_command and not target_url:
        typer.echo("Error: Either --target-command or --target-url is required.", err=True)
        raise typer.Exit(code=1)

    if target_url:
        typer.echo("Error: SSE/HTTP replay is not yet implemented. Use --target-command.", err=True)
        raise typer.Exit(code=1)

    session_path = Path(session_file)
    if not session_path.exists():
        typer.echo(f"Error: Session file not found: {session_file}", err=True)
        raise typer.Exit(code=1)

    try:
        store = SessionStore.load(session_path)
    except Exception as exc:
        typer.echo(f"Error: Failed to load session: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    messages = store.get_messages()
    c2s_messages = [m for m in messages if m.direction == Direction.CLIENT_TO_SERVER]

    if not c2s_messages:
        typer.echo("No client-to-server messages to replay.")
        return

    if target_command is None:
        typer.echo("Error: --target-command is required.", err=True)
        raise typer.Exit(code=1)
    parts = shlex.split(target_command)
    command = parts[0]
    args = parts[1:]

    typer.echo(f'Replaying {len(c2s_messages)} messages against "{target_command}"...')

    try:
        session_result = asyncio.run(
            _run_replay(command, args, messages, timeout, not no_handshake)
        )
    except (OSError, FileNotFoundError) as exc:
        typer.echo(f"Error: Failed to start server: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except KeyboardInterrupt:
        typer.echo("\nReplay interrupted.")
        raise typer.Exit(code=130) from None

    succeeded = 0
    failed = 0
    for i, r in enumerate(session_result.results):
        method = r.original_request.method or "(response)"
        msg_id = r.original_request.jsonrpc_id

        if r.original_request.jsonrpc_id is not None:
            id_str = f" (id={msg_id})"
        else:
            id_str = " (notification)"

        if r.error:
            typer.echo(f"  #{i:03d} → {method}{id_str} ✗ {r.error}")
            failed += 1
        elif r.response is not None:
            typer.echo(f"  #{i:03d} → {method}{id_str} ✓ {r.duration_ms:.0f}ms")
            succeeded += 1
        else:
            typer.echo(f"  #{i:03d} → {method}{id_str} ✓")
            succeeded += 1

    typer.echo("")
    total = succeeded + failed
    parts_summary = [f"{succeeded}/{total} succeeded"]
    if failed:
        parts_summary.append(f"{failed} failed")
    typer.echo(f"Results: {', '.join(parts_summary)}")

    if output:
        output_path = Path(output)
        _save_replay_results(session_result, output_path, target_command)
        typer.echo(f"Results saved to {output_path}")


def _save_replay_results(
    session_result: ReplaySessionResult,
    output_path: Path,
    target_command: str | None,
) -> None:
    """Serialize replay results to JSON.

    Args:
        session_result: The full replay session result.
        output_path: File path to write the JSON output.
        target_command: The server command used for replay.
    """
    import json
    from typing import Any

    def _serialize_result(r: ReplayResult) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "original_request": r.original_request.raw.model_dump(
                by_alias=True, exclude_none=True
            ),
            "sent_message": r.sent_message.message.model_dump(
                by_alias=True, exclude_none=True
            ),
            "response": (
                r.response.message.model_dump(by_alias=True, exclude_none=True)
                if r.response
                else None
            ),
            "error": r.error,
            "duration_ms": r.duration_ms,
        }
        return entry

    data = {
        "target_command": target_command,
        "target_url": session_result.target_url,
        "results": [_serialize_result(r) for r in session_result.results],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


async def _run_replay(
    command: str,
    args: list[str],
    messages: list,
    timeout: float,
    auto_handshake: bool,
) -> ReplaySessionResult:
    """Run the replay against a stdio server adapter.

    Args:
        command: The server executable command.
        args: Arguments to pass to the server command.
        messages: List of ProxyMessages to replay.
        timeout: Per-message response timeout in seconds.
        auto_handshake: Whether to send a synthetic handshake.

    Returns:
        A ReplaySessionResult with results for each replayed message.
    """
    from counteragent.proxy.adapters.stdio import StdioServerAdapter
    from counteragent.proxy.replay import ReplaySessionResult, replay_messages

    async with StdioServerAdapter(command=command, args=args) as adapter:
        results = await replay_messages(
            messages, adapter, timeout=timeout, auto_handshake=auto_handshake
        )
    return ReplaySessionResult(
        results=results,
        target_command=f"{command} {' '.join(args)}".strip(),
    )


@app.command(name="export")
def export_session(
    session_file: str = typer.Option(
        ...,
        help="Path to a saved session file.",
    ),
    output: str = typer.Option(
        ...,
        help="Output file path.",
    ),
    output_format: str = typer.Option(
        "json",
        help="Export format (currently only 'json').",
    ),
) -> None:
    """Export a session to JSON."""
    from counteragent.proxy.session_store import SessionStore

    if output_format.lower() != "json":
        typer.echo(
            f"Error: Unsupported export format '{output_format}'. Only 'json' is supported.",
            err=True,
        )
        raise typer.Exit(code=1)

    session_path = Path(session_file)
    if not session_path.exists():
        typer.echo(f"Error: Session file not found: {session_file}", err=True)
        raise typer.Exit(code=1)

    try:
        store = SessionStore.load(session_path)
    except Exception as exc:
        typer.echo(f"Error: Failed to load session: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    output_path = Path(output)
    try:
        store.save(output_path)
    except Exception as exc:
        typer.echo(f"Error: Failed to write export: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    messages = store.get_messages()
    typer.echo(f"Exported {len(messages)} messages to {output_path}")


@app.command()
def inspect(
    session_file: str = typer.Option(
        ...,
        help="Path to a saved session file.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show full JSON payloads.",
    ),
) -> None:
    """Print session contents to stdout (non-interactive)."""
    import json

    from counteragent.proxy.session_store import SessionStore

    session_path = Path(session_file)
    if not session_path.exists():
        typer.echo(f"Error: Session file not found: {session_file}", err=True)
        raise typer.Exit(code=1)

    try:
        store = SessionStore.load(session_path)
    except Exception as exc:
        typer.echo(f"Error: Failed to load session: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    session = store.to_proxy_session()
    messages = store.get_messages()

    typer.echo(f"Session: {session.id}")
    typer.echo(f"Transport: {session.transport.value}")
    if session.server_command:
        typer.echo(f"Server command: {session.server_command}")
    if session.server_url:
        typer.echo(f"Server URL: {session.server_url}")
    typer.echo(f"Started: {session.started_at.isoformat()}")
    typer.echo(f"Messages: {len(messages)}")
    if session.metadata:
        typer.echo(f"Metadata: {json.dumps(session.metadata)}")
    typer.echo("---")

    for msg in messages:
        direction = "\u2192" if msg.direction.value == "client_to_server" else "\u2190"
        method_str = msg.method or "(response)"
        id_str = f" id={msg.jsonrpc_id}" if msg.jsonrpc_id is not None else ""
        modified_str = " [MODIFIED]" if msg.modified else ""
        corr_str = f" corr={msg.correlated_id[:8]}..." if msg.correlated_id else ""

        typer.echo(
            f"  #{msg.sequence:03d} {direction} {method_str}{id_str}{corr_str}{modified_str}"
        )

        if verbose:
            payload = msg.raw.model_dump(by_alias=True, exclude_none=True)
            typer.echo(f"       {json.dumps(payload, indent=2)}")
            if msg.original_raw is not None:
                original = msg.original_raw.model_dump(by_alias=True, exclude_none=True)
                typer.echo(f"       [original] {json.dumps(original, indent=2)}")
