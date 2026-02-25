"""Tests for TUI replay controls -- keybinding, action, handler."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from mcp.shared.message import SessionMessage
from mcp.types import (
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
)
from textual.widgets import RichLog

from counteragent.core.models import Direction, Transport
from counteragent.proxy.models import ProxyMessage
from counteragent.proxy.replay import ReplayResult
from counteragent.proxy.tui.app import ProxyApp
from counteragent.proxy.tui.messages import ReplayCompleted
from counteragent.proxy.tui.widgets.message_detail import MessageDetailPanel
from counteragent.proxy.tui.widgets.message_list import MessageListPanel


def _make_proxy_message(
    method: str = "tools/list",
    seq: int = 0,
    msg_id: int = 1,
    direction: Direction = Direction.CLIENT_TO_SERVER,
    proxy_id: str | None = None,
    correlated_id: str | None = None,
) -> ProxyMessage:
    if direction == Direction.SERVER_TO_CLIENT:
        raw = JSONRPCMessage(JSONRPCResponse(jsonrpc="2.0", id=msg_id, result={}))
        return ProxyMessage(
            id=proxy_id or str(uuid.uuid4()),
            sequence=seq,
            timestamp=datetime.now(tz=UTC),
            direction=direction,
            transport=Transport.STDIO,
            raw=raw,
            jsonrpc_id=msg_id,
            method=None,
            correlated_id=correlated_id,
            modified=False,
            original_raw=None,
        )
    raw = JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=msg_id, method=method))
    return ProxyMessage(
        id=proxy_id or str(uuid.uuid4()),
        sequence=seq,
        timestamp=datetime.now(tz=UTC),
        direction=direction,
        transport=Transport.STDIO,
        raw=raw,
        jsonrpc_id=msg_id,
        method=method,
        correlated_id=correlated_id,
        modified=False,
        original_raw=None,
    )


def _make_notification(method: str = "notifications/initialized", seq: int = 0) -> ProxyMessage:
    raw = JSONRPCMessage(JSONRPCNotification(jsonrpc="2.0", method=method))
    return ProxyMessage(
        id=str(uuid.uuid4()),
        sequence=seq,
        timestamp=datetime.now(tz=UTC),
        direction=Direction.CLIENT_TO_SERVER,
        transport=Transport.STDIO,
        raw=raw,
        jsonrpc_id=None,
        method=method,
        correlated_id=None,
        modified=False,
        original_raw=None,
    )


class TestReplayKeybinding:
    """Replay keybindings are registered on ProxyApp."""

    def test_r_and_f9_bindings_exist(self) -> None:
        binding_keys = [b.key for b in ProxyApp.BINDINGS if hasattr(b, "key")]
        # Also check tuple bindings
        for b in ProxyApp.BINDINGS:
            if isinstance(b, tuple):
                binding_keys.append(b[0])
        assert "r" in binding_keys
        assert "f9" in binding_keys


class TestReplayActionGuards:
    """action_replay_message rejects invalid selections."""

    async def test_rejects_server_to_client(self) -> None:
        app = ProxyApp(
            transport=Transport.STDIO,
            server_command="echo hello",
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as pilot:
            pm = _make_proxy_message(direction=Direction.SERVER_TO_CLIENT, msg_id=1, seq=0)
            from counteragent.proxy.tui.messages import MessageReceived

            app.post_message(MessageReceived(pm))
            await pilot.pause()
            list_panel = app.query_one(MessageListPanel)
            list_panel.query_one("ListView").index = 0
            await pilot.pause()
            # Trigger replay — should be rejected (server response selected)
            app.action_replay_message()
            await pilot.pause()
            # Detail panel should NOT show replay diff headers
            detail = app.query_one(MessageDetailPanel)
            log = detail.query_one("#detail-log", RichLog)
            text = "\n".join(str(line) for line in log.lines)
            assert "REPLAY RESPONSE" not in text

    async def test_rejects_notification(self) -> None:
        app = ProxyApp(
            transport=Transport.STDIO,
            server_command="echo hello",
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as pilot:
            notif = _make_notification("notifications/initialized", seq=0)
            from counteragent.proxy.tui.messages import MessageReceived

            app.post_message(MessageReceived(notif))
            await pilot.pause()
            list_panel = app.query_one(MessageListPanel)
            list_panel.query_one("ListView").index = 0
            await pilot.pause()
            # Trigger replay — should be rejected (notification selected)
            app.action_replay_message()
            await pilot.pause()
            detail = app.query_one(MessageDetailPanel)
            log = detail.query_one("#detail-log", RichLog)
            text = "\n".join(str(line) for line in log.lines)
            assert "REPLAY RESPONSE" not in text

    async def test_rejects_no_server_command(self) -> None:
        app = ProxyApp(
            transport=Transport.STDIO,
            server_command=None,
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as pilot:
            pm = _make_proxy_message("tools/list", msg_id=1, seq=0)
            from counteragent.proxy.tui.messages import MessageReceived

            app.post_message(MessageReceived(pm))
            await pilot.pause()
            list_panel = app.query_one(MessageListPanel)
            list_panel.query_one("ListView").index = 0
            await pilot.pause()
            # Trigger replay — should be rejected (no server command)
            app.action_replay_message()
            await pilot.pause()
            detail = app.query_one(MessageDetailPanel)
            log = detail.query_one("#detail-log", RichLog)
            text = "\n".join(str(line) for line in log.lines)
            assert "REPLAY RESPONSE" not in text


class TestReplayCompletedHandler:
    """on_replay_completed updates the detail panel."""

    async def test_handler_shows_diff(self) -> None:
        app = ProxyApp(
            transport=Transport.STDIO,
            server_command="echo hello",
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as pilot:
            request = _make_proxy_message("tools/list", msg_id=1)
            original_resp = _make_proxy_message(
                direction=Direction.SERVER_TO_CLIENT, msg_id=1, seq=1
            )
            replay_response = SessionMessage(
                message=JSONRPCMessage(
                    JSONRPCResponse(jsonrpc="2.0", id=1, result={"tools": ["replayed"]})
                )
            )
            result = ReplayResult(
                original_request=request,
                sent_message=SessionMessage(message=request.raw),
                response=replay_response,
                error=None,
                duration_ms=123.4,
            )
            app.post_message(ReplayCompleted(result=result, original_response=original_resp))
            await pilot.pause()
            detail = app.query_one(MessageDetailPanel)
            log = detail.query_one("#detail-log", RichLog)
            text = "\n".join(str(line) for line in log.lines)
            assert "ORIGINAL RESPONSE" in text
            assert "REPLAY RESPONSE" in text
            assert "replayed" in text

    async def test_handler_shows_error(self) -> None:
        app = ProxyApp(
            transport=Transport.STDIO,
            server_command="echo hello",
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as pilot:
            request = _make_proxy_message("tools/list", msg_id=1)
            result = ReplayResult(
                original_request=request,
                sent_message=SessionMessage(message=request.raw),
                response=None,
                error="Timeout after 10s",
                duration_ms=10000.0,
            )
            app.post_message(ReplayCompleted(result=result, original_response=None))
            await pilot.pause()
            detail = app.query_one(MessageDetailPanel)
            log = detail.query_one("#detail-log", RichLog)
            text = "\n".join(str(line) for line in log.lines)
            assert "Timeout after 10s" in text
