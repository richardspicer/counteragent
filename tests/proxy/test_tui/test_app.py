# tests/proxy/test_tui/test_app.py
"""Tests for counteragent.proxy.tui.app — ProxyApp."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest
from textual.widgets import RichLog

from counteragent.core.models import Direction, Transport
from counteragent.proxy.models import HeldMessage, ProxyMessage
from counteragent.proxy.tui.app import ProxyApp
from counteragent.proxy.tui.messages import (
    MessageHeld,
    MessageReceived,
    PipelineError,
    PipelineStopped,
)
from counteragent.proxy.tui.widgets.message_detail import MessageDetailPanel
from counteragent.proxy.tui.widgets.message_list import MessageListPanel
from counteragent.proxy.tui.widgets.status_bar import ProxyStatusBar

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_proxy_message(method: str = "tools/list", seq: int = 0, msg_id: int = 1) -> ProxyMessage:
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


def _make_held_message(pm: ProxyMessage) -> HeldMessage:
    return HeldMessage(
        proxy_message=pm,
        release=asyncio.Event(),
        action=None,
        modified_raw=None,
    )


class MockAdapter:
    """Minimal mock adapter for TUI tests."""

    def __init__(self) -> None:
        self.read_queue: asyncio.Queue[SessionMessage | None] = asyncio.Queue()
        self.write_queue: asyncio.Queue[SessionMessage] = asyncio.Queue()

    async def read(self) -> SessionMessage:
        item = await self.read_queue.get()
        if item is None:
            raise Exception("Connection closed")
        return item

    async def write(self, message: SessionMessage) -> None:
        await self.write_queue.put(message)

    async def close(self) -> None:
        pass

    def enqueue(self, *messages: SessionMessage) -> None:
        for msg in messages:
            self.read_queue.put_nowait(msg)
        self.read_queue.put_nowait(None)


# ---------------------------------------------------------------------------
# Tests: App mounts and composes
# ---------------------------------------------------------------------------


class TestAppMount:
    """ProxyApp mounts without error and composes expected widgets."""

    async def test_app_mounts(self) -> None:
        app = ProxyApp(
            transport=Transport.STDIO,
            server_command="echo hello",
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as _pilot:
            assert app.query_one(MessageListPanel) is not None
            assert app.query_one(MessageDetailPanel) is not None
            assert app.query_one(ProxyStatusBar) is not None

    async def test_header_contains_transport(self) -> None:
        app = ProxyApp(
            transport=Transport.STDIO,
            server_command="echo hello",
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as _pilot:
            assert app.title is not None
            assert "stdio" in app.title.lower()


# ---------------------------------------------------------------------------
# Tests: Message event handling
# ---------------------------------------------------------------------------


class TestMessageEventHandling:
    """App responds to pipeline Textual messages."""

    async def test_message_received_updates_list(self) -> None:
        app = ProxyApp(
            transport=Transport.STDIO,
            server_command="echo hello",
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as pilot:
            pm = _make_proxy_message("tools/list", seq=0)
            app.post_message(MessageReceived(pm))
            await pilot.pause()
            panel = app.query_one(MessageListPanel)
            assert len(panel.messages) == 1

    async def test_message_received_updates_status_count(self) -> None:
        app = ProxyApp(
            transport=Transport.STDIO,
            server_command="echo hello",
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as pilot:
            pm1 = _make_proxy_message("tools/list", seq=0)
            pm2 = _make_proxy_message("tools/call", seq=1)
            app.post_message(MessageReceived(pm1))
            app.post_message(MessageReceived(pm2))
            await pilot.pause()
            bar = app.query_one(ProxyStatusBar)
            assert bar.message_count == 2

    async def test_message_held_updates_status(self) -> None:
        app = ProxyApp(
            transport=Transport.STDIO,
            server_command="echo hello",
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as pilot:
            pm = _make_proxy_message("tools/call", seq=0)
            held = _make_held_message(pm)
            # Manually add to intercept engine's held list for counting
            app.intercept_engine._held.append(held)
            app.post_message(MessageHeld(held))
            await pilot.pause()
            bar = app.query_one(ProxyStatusBar)
            assert bar.held_count == 1

    async def test_pipeline_error_updates_status(self) -> None:
        app = ProxyApp(
            transport=Transport.STDIO,
            server_command="echo hello",
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as pilot:
            app.post_message(PipelineError(RuntimeError("connection failed")))
            await pilot.pause()
            bar = app.query_one(ProxyStatusBar)
            assert "connection failed" in bar.connection_status.lower()

    async def test_pipeline_stopped_updates_status(self) -> None:
        app = ProxyApp(
            transport=Transport.STDIO,
            server_command="echo hello",
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as pilot:
            app.post_message(PipelineStopped())
            await pilot.pause()
            bar = app.query_one(ProxyStatusBar)
            assert "DISCONNECTED" in bar.connection_status


# ---------------------------------------------------------------------------
# Tests: Selection and detail panel
# ---------------------------------------------------------------------------


class TestSelection:
    """Selecting a message shows its detail."""

    async def test_selecting_message_shows_detail(self) -> None:
        app = ProxyApp(
            transport=Transport.STDIO,
            server_command="echo hello",
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as pilot:
            pm = _make_proxy_message("tools/call", seq=5, msg_id=42)
            app.post_message(MessageReceived(pm))
            await pilot.pause()
            # Highlight the first item in the list view
            list_panel = app.query_one(MessageListPanel)
            list_view = list_panel.query_one("ListView")
            list_view.index = 0
            await pilot.pause()
            detail = app.query_one(MessageDetailPanel)
            log = detail.query_one("#detail-log", RichLog)
            text = "\n".join(str(line) for line in log.lines)
            assert "tools/call" in text


# ---------------------------------------------------------------------------
# Tests: Key bindings
# ---------------------------------------------------------------------------


class TestKeyBindings:
    """App key bindings work."""

    async def test_q_quits(self) -> None:
        app = ProxyApp(
            transport=Transport.STDIO,
            server_command="echo hello",
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as pilot:
            await pilot.press("q")
        # After run_test() exits, app should no longer be running
        assert not app.is_running


# ---------------------------------------------------------------------------
# Tests: Pipeline worker integration
# ---------------------------------------------------------------------------


class TestPipelineWorker:
    """Pipeline runs as a background worker and updates the TUI."""

    async def test_pipeline_messages_appear_in_list(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        req = SessionMessage(
            message=JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=1, method="tools/list"))
        )
        client.enqueue(req)
        server.enqueue()

        app = ProxyApp(
            transport=Transport.STDIO,
            server_command="echo hello",
            run_pipeline_on_mount=False,
        )
        async with app.run_test() as pilot:
            app.start_pipeline_worker(client, server)
            # Give the worker time to process
            await pilot.pause(delay=0.5)
            panel = app.query_one(MessageListPanel)
            assert len(panel.messages) >= 1
