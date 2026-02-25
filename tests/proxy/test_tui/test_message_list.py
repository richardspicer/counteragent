"""Tests for counteragent.proxy.tui.widgets.message_list — MessageListPanel."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from mcp.types import JSONRPCMessage, JSONRPCRequest, JSONRPCResponse
from textual.app import App, ComposeResult

from counteragent.core.models import Direction, Transport
from counteragent.proxy.models import ProxyMessage
from counteragent.proxy.tui.widgets.message_list import MessageListPanel, MessageSelected


def _make_proxy_message(
    method: str | None = "tools/list",
    seq: int = 0,
    msg_id: int = 1,
    direction: Direction = Direction.CLIENT_TO_SERVER,
) -> ProxyMessage:
    """Build a ProxyMessage for testing."""
    if method is not None:
        raw = JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=msg_id, method=method))
    else:
        raw = JSONRPCMessage(JSONRPCResponse(jsonrpc="2.0", id=msg_id, result={}))
    return ProxyMessage(
        id=str(uuid.uuid4()),
        sequence=seq,
        timestamp=datetime.now(tz=UTC),
        direction=direction,
        transport=Transport.STDIO,
        raw=raw,
        jsonrpc_id=msg_id,
        method=method,
        correlated_id=None,
        modified=False,
        original_raw=None,
    )


class ListTestApp(App[None]):
    """Minimal app for testing MessageListPanel in isolation."""

    selected_message: ProxyMessage | None = None

    def compose(self) -> ComposeResult:
        yield MessageListPanel()

    def on_message_selected(self, event: MessageSelected) -> None:
        self.selected_message = event.proxy_message


class TestMessageListPanel:
    """MessageListPanel displays a live list of messages."""

    async def test_initial_empty(self) -> None:
        app = ListTestApp()
        async with app.run_test():
            panel = app.query_one(MessageListPanel)
            assert len(panel.messages) == 0

    async def test_add_message(self) -> None:
        app = ListTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageListPanel)
            pm = _make_proxy_message("tools/list", seq=0)
            panel.add_message(pm)
            await pilot.pause()
            assert len(panel.messages) == 1

    async def test_client_to_server_arrow(self) -> None:
        app = ListTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageListPanel)
            pm = _make_proxy_message("tools/list", seq=0, direction=Direction.CLIENT_TO_SERVER)
            panel.add_message(pm)
            await pilot.pause()
            # The rendered item should contain the right arrow
            list_view = panel.query_one("ListView")
            item = list_view.children[0]
            text = str(item.query_one("Static").render())
            assert "\u25ba" in text  # ►

    async def test_server_to_client_arrow(self) -> None:
        app = ListTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageListPanel)
            pm = _make_proxy_message(method=None, seq=0, direction=Direction.SERVER_TO_CLIENT)
            panel.add_message(pm)
            await pilot.pause()
            list_view = panel.query_one("ListView")
            item = list_view.children[0]
            text = str(item.query_one("Static").render())
            assert "\u25c4" in text  # ◄

    async def test_response_label(self) -> None:
        app = ListTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageListPanel)
            pm = _make_proxy_message(method=None, seq=0)
            panel.add_message(pm)
            await pilot.pause()
            list_view = panel.query_one("ListView")
            item = list_view.children[0]
            text = str(item.query_one("Static").render())
            assert "response" in text

    async def test_select_fires_message_selected(self) -> None:
        app = ListTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageListPanel)
            pm = _make_proxy_message("tools/list", seq=0)
            panel.add_message(pm)
            await pilot.pause()
            # Highlight the first item
            list_view = panel.query_one("ListView")
            list_view.index = 0
            await pilot.pause()
            assert app.selected_message is pm

    async def test_mark_held(self) -> None:
        app = ListTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageListPanel)
            pm = _make_proxy_message("tools/call", seq=0)
            panel.add_message(pm)
            await pilot.pause()
            panel.mark_held(pm.id)
            await pilot.pause()
            list_view = panel.query_one("ListView")
            item = list_view.children[0]
            text = str(item.query_one("Static").render())
            assert "\u23f8" in text  # ⏸
