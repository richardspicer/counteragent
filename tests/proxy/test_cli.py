"""Smoke test for counteragent proxy CLI."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from mcp.types import JSONRPCMessage, JSONRPCRequest, JSONRPCResponse

from counteragent.core.models import Direction, Transport
from counteragent.proxy.cli import app
from counteragent.proxy.models import ProxyMessage
from counteragent.proxy.session_store import SessionStore


def _create_test_session(path: Path) -> SessionStore:
    """Create and save a test session with a request-response pair."""
    store = SessionStore(
        session_id="test-session-001",
        transport=Transport.STDIO,
        server_command="python server.py",
        metadata={"note": "cli test"},
    )
    req = ProxyMessage(
        id=str(uuid.uuid4()),
        sequence=0,
        timestamp=datetime.now(tz=UTC),
        direction=Direction.CLIENT_TO_SERVER,
        transport=Transport.STDIO,
        raw=JSONRPCMessage(
            JSONRPCRequest(jsonrpc="2.0", id=1, method="tools/list")
        ),
        jsonrpc_id=1,
        method="tools/list",
        correlated_id=None,
        modified=False,
        original_raw=None,
    )
    resp = ProxyMessage(
        id=str(uuid.uuid4()),
        sequence=1,
        timestamp=datetime.now(tz=UTC),
        direction=Direction.SERVER_TO_CLIENT,
        transport=Transport.STDIO,
        raw=JSONRPCMessage(
            JSONRPCResponse(jsonrpc="2.0", id=1, result={"tools": []})
        ),
        jsonrpc_id=1,
        method=None,
        correlated_id=req.id,
        modified=False,
        original_raw=None,
    )
    store.append(req)
    store.append(resp)
    store.save(path)
    return store


def test_start_help():
    """start --help exits cleanly."""
    runner = CliRunner()
    result = runner.invoke(app, ["start", "--help"])
    assert result.exit_code == 0
    assert "--transport" in result.output


class TestProxyValidation:
    """proxy start command validates transport/target combinations."""

    def test_stdio_requires_target_command(self) -> None:
        runner = CliRunner()
        result = runner.invoke(app, ["start", "--transport", "stdio"])
        assert result.exit_code != 0
        assert "target-command" in result.output.lower() or "required" in result.output.lower()

    def test_sse_requires_target_url(self) -> None:
        runner = CliRunner()
        result = runner.invoke(app, ["start", "--transport", "sse"])
        assert result.exit_code != 0
        assert "target-url" in result.output.lower() or "required" in result.output.lower()

    def test_streamable_http_requires_target_url(self) -> None:
        runner = CliRunner()
        result = runner.invoke(app, ["start", "--transport", "streamable-http"])
        assert result.exit_code != 0
        assert "target-url" in result.output.lower() or "required" in result.output.lower()


class TestExportCommand:
    """export command loads a session and writes to output path."""

    def test_export_json(self, tmp_path: Path) -> None:
        session_file = tmp_path / "input.json"
        _create_test_session(session_file)
        output_file = tmp_path / "output.json"

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["export", "--session-file", str(session_file), "--output", str(output_file)],
        )
        assert result.exit_code == 0
        assert "Exported 2 messages" in result.output
        assert output_file.exists()

        # Verify the exported file is valid session JSON
        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert data["id"] == "test-session-001"
        assert len(data["messages"]) == 2

    def test_export_missing_session_file(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            app,
            ["export", "--session-file", str(tmp_path / "nope.json"), "--output", "out.json"],
        )
        assert result.exit_code != 0


class TestInspectCommand:
    """inspect command prints session summary to stdout."""

    def test_inspect_basic(self, tmp_path: Path) -> None:
        session_file = tmp_path / "session.json"
        _create_test_session(session_file)

        runner = CliRunner()
        result = runner.invoke(app, ["inspect", "--session-file", str(session_file)])
        assert result.exit_code == 0
        assert "test-session-001" in result.output
        assert "stdio" in result.output
        assert "python server.py" in result.output
        assert "Messages: 2" in result.output
        assert "tools/list" in result.output
        assert "(response)" in result.output

    def test_inspect_verbose(self, tmp_path: Path) -> None:
        session_file = tmp_path / "session.json"
        _create_test_session(session_file)

        runner = CliRunner()
        result = runner.invoke(
            app, ["inspect", "--session-file", str(session_file), "-v"]
        )
        assert result.exit_code == 0
        assert '"jsonrpc"' in result.output
        assert '"tools/list"' in result.output

    def test_inspect_missing_session_file(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            app, ["inspect", "--session-file", str(tmp_path / "nope.json")]
        )
        assert result.exit_code != 0


class TestReplayCommand:
    """replay command CLI tests."""

    def test_replay_help(self) -> None:
        """replay --help exits cleanly and shows expected flags."""
        runner = CliRunner()
        result = runner.invoke(app, ["replay", "--help"])
        assert result.exit_code == 0
        assert "--session-file" in result.output
        assert "--target-command" in result.output
        assert "--timeout" in result.output
        assert "--no-handshake" in result.output
        assert "--output" in result.output

    def test_replay_missing_session(self, tmp_path: Path) -> None:
        """Missing session file errors cleanly."""
        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "replay",
                "--session-file", str(tmp_path / "nonexistent.json"),
                "--target-command", "python server.py",
            ],
        )
        assert result.exit_code != 0
