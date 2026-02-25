"""Tests for counteragent.proxy.tui.widgets.message_detail — MessageDetailPanel."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest, JSONRPCResponse
from textual.app import App, ComposeResult
from textual.widgets import RichLog

from counteragent.core.models import Direction, Transport
from counteragent.proxy.models import ProxyMessage
from counteragent.proxy.replay import ReplayResult
from counteragent.proxy.tui.widgets.message_detail import MessageDetailPanel


def _make_proxy_message(method: str = "tools/list", seq: int = 0, msg_id: int = 1) -> ProxyMessage:
    """Build a ProxyMessage for testing."""
    return ProxyMessage(
        id=str(uuid.uuid4()),
        sequence=seq,
        timestamp=datetime.now(tz=UTC),
        direction=Direction.CLIENT_TO_SERVER,
        transport=Transport.STDIO,
        raw=JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=msg_id, method=method)),
        jsonrpc_id=msg_id,
        method=method,
        correlated_id=None,
        modified=False,
        original_raw=None,
    )


class DetailTestApp(App[None]):
    """Minimal app for testing MessageDetailPanel in isolation."""

    def compose(self) -> ComposeResult:
        yield MessageDetailPanel()


class TestMessageDetailPanel:
    """MessageDetailPanel shows JSON-RPC payload and metadata."""

    async def test_initial_empty_state(self) -> None:
        app = DetailTestApp()
        async with app.run_test():
            panel = app.query_one(MessageDetailPanel)
            # Should exist and not crash
            assert panel is not None

    async def test_show_message_displays_payload(self) -> None:
        app = DetailTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageDetailPanel)
            pm = _make_proxy_message("tools/call", seq=5, msg_id=42)
            panel.show_message(pm)
            await pilot.pause()
            log = panel.query_one("#detail-log", RichLog)
            text = "\n".join(str(line) for line in log.lines)
            assert "tools/call" in text

    async def test_show_message_displays_metadata(self) -> None:
        app = DetailTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageDetailPanel)
            pm = _make_proxy_message("tools/list", seq=3)
            panel.show_message(pm)
            await pilot.pause()
            log = panel.query_one("#detail-log", RichLog)
            text = "\n".join(str(line) for line in log.lines)
            assert "#3" in text
            assert "CLIENT_TO_SERVER" in text or "client_to_server" in text

    async def test_clear_resets_panel(self) -> None:
        app = DetailTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageDetailPanel)
            pm = _make_proxy_message()
            panel.show_message(pm)
            await pilot.pause()
            log = panel.query_one("#detail-log", RichLog)
            log.clear()
            await pilot.pause()
            assert len(log.lines) == 0


def _make_response_proxy_message(
    msg_id: int = 1, result: dict | None = None
) -> ProxyMessage:
    """Build a response ProxyMessage for testing."""
    return ProxyMessage(
        id=str(uuid.uuid4()),
        sequence=1,
        timestamp=datetime.now(tz=UTC),
        direction=Direction.SERVER_TO_CLIENT,
        transport=Transport.STDIO,
        raw=JSONRPCMessage(
            JSONRPCResponse(jsonrpc="2.0", id=msg_id, result=result or {})
        ),
        jsonrpc_id=msg_id,
        method=None,
        correlated_id=None,
        modified=False,
        original_raw=None,
    )


def _make_replay_result(
    original: ProxyMessage,
    response_result: dict | None = None,
    error: str | None = None,
    duration_ms: float = 42.0,
) -> ReplayResult:
    """Build a ReplayResult for testing."""
    sent = SessionMessage(message=original.raw)
    response = None
    if response_result is not None and error is None:
        response = SessionMessage(
            message=JSONRPCMessage(
                JSONRPCResponse(
                    jsonrpc="2.0", id=original.jsonrpc_id, result=response_result
                )
            )
        )
    return ReplayResult(
        original_request=original,
        sent_message=sent,
        response=response,
        error=error,
        duration_ms=duration_ms,
    )


class TestShowReplayDiff:
    """show_replay_diff displays original and replay responses."""

    async def test_both_present(self) -> None:
        app = DetailTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageDetailPanel)
            original = _make_response_proxy_message(msg_id=1, result={"tools": ["old"]})
            request = _make_proxy_message("tools/list", msg_id=1)
            replay = _make_replay_result(request, response_result={"tools": ["new"]})
            panel.show_replay_diff(original, replay)
            await pilot.pause()
            log = panel.query_one("#detail-log", RichLog)
            text = "\n".join(str(line) for line in log.lines)
            assert "ORIGINAL RESPONSE" in text
            assert "REPLAY RESPONSE" in text
            assert "old" in text
            assert "new" in text

    async def test_no_original(self) -> None:
        app = DetailTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageDetailPanel)
            request = _make_proxy_message("tools/list", msg_id=1)
            replay = _make_replay_result(request, response_result={"tools": ["new"]})
            panel.show_replay_diff(None, replay)
            await pilot.pause()
            log = panel.query_one("#detail-log", RichLog)
            text = "\n".join(str(line) for line in log.lines)
            assert "ORIGINAL RESPONSE" not in text
            assert "REPLAY RESPONSE" in text

    async def test_replay_error(self) -> None:
        app = DetailTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageDetailPanel)
            request = _make_proxy_message("tools/list", msg_id=1)
            replay = _make_replay_result(request, error="Timeout after 10s")
            panel.show_replay_diff(None, replay)
            await pilot.pause()
            log = panel.query_one("#detail-log", RichLog)
            text = "\n".join(str(line) for line in log.lines)
            assert "REPLAY RESPONSE" in text
            assert "Timeout after 10s" in text
