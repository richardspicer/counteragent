"""Tests for message filtering in MessageListPanel."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from mcp.types import JSONRPCMessage, JSONRPCRequest, JSONRPCResponse
from textual.app import App, ComposeResult

from counteragent.core.models import Direction, Transport
from counteragent.proxy.models import ProxyMessage
from counteragent.proxy.tui.widgets.message_list import MessageListPanel


def _make_proxy_message(
    method: str | None = "tools/list",
    seq: int = 0,
    msg_id: int = 1,
    direction: Direction = Direction.CLIENT_TO_SERVER,
    params: dict | None = None,
) -> ProxyMessage:
    """Build a ProxyMessage for testing."""
    if method is not None:
        request_kwargs: dict = {"jsonrpc": "2.0", "id": msg_id, "method": method}
        if params is not None:
            request_kwargs["params"] = params
        raw = JSONRPCMessage(JSONRPCRequest(**request_kwargs))
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


class FilterTestApp(App[None]):
    """Minimal app for testing MessageListPanel filtering."""

    def compose(self) -> ComposeResult:
        yield MessageListPanel()


class TestMatchesFilter:
    """Unit tests for _matches_filter logic."""

    async def test_matches_filter_method(self) -> None:
        """'tools' matches ProxyMessage with method='tools/list'."""
        app = FilterTestApp()
        async with app.run_test():
            panel = app.query_one(MessageListPanel)
            pm = _make_proxy_message("tools/list")
            assert panel._matches_filter(pm, "tools") is True

    async def test_matches_filter_method_no_match(self) -> None:
        """'resources' does NOT match method='tools/list'."""
        app = FilterTestApp()
        async with app.run_test():
            panel = app.query_one(MessageListPanel)
            pm = _make_proxy_message("tools/list")
            assert panel._matches_filter(pm, "resources") is False

    async def test_matches_filter_direction_client(self) -> None:
        """'>' matches only CLIENT_TO_SERVER messages."""
        app = FilterTestApp()
        async with app.run_test():
            panel = app.query_one(MessageListPanel)
            pm_c2s = _make_proxy_message(direction=Direction.CLIENT_TO_SERVER)
            pm_s2c = _make_proxy_message(direction=Direction.SERVER_TO_CLIENT, method=None)
            assert panel._matches_filter(pm_c2s, ">") is True
            assert panel._matches_filter(pm_s2c, ">") is False

    async def test_matches_filter_direction_server(self) -> None:
        """'<' matches only SERVER_TO_CLIENT messages."""
        app = FilterTestApp()
        async with app.run_test():
            panel = app.query_one(MessageListPanel)
            pm_c2s = _make_proxy_message(direction=Direction.CLIENT_TO_SERVER)
            pm_s2c = _make_proxy_message(direction=Direction.SERVER_TO_CLIENT, method=None)
            assert panel._matches_filter(pm_s2c, "<") is True
            assert panel._matches_filter(pm_c2s, "<") is False

    async def test_matches_filter_direction_with_text(self) -> None:
        """>tools matches CLIENT_TO_SERVER with 'tools' in method."""
        app = FilterTestApp()
        async with app.run_test():
            panel = app.query_one(MessageListPanel)
            pm_match = _make_proxy_message("tools/call", direction=Direction.CLIENT_TO_SERVER)
            pm_wrong_dir = _make_proxy_message("tools/call", direction=Direction.SERVER_TO_CLIENT)
            pm_wrong_method = _make_proxy_message("ping", direction=Direction.CLIENT_TO_SERVER)
            assert panel._matches_filter(pm_match, ">tools") is True
            assert panel._matches_filter(pm_wrong_dir, ">tools") is False
            assert panel._matches_filter(pm_wrong_method, ">tools") is False

    async def test_matches_filter_empty(self) -> None:
        """Empty string matches everything."""
        app = FilterTestApp()
        async with app.run_test():
            panel = app.query_one(MessageListPanel)
            pm = _make_proxy_message("tools/list")
            assert panel._matches_filter(pm, "") is True

    async def test_matches_filter_payload(self) -> None:
        """'file_search' matches message with that string in JSON payload."""
        app = FilterTestApp()
        async with app.run_test():
            panel = app.query_one(MessageListPanel)
            pm = _make_proxy_message(
                "tools/call",
                params={"name": "file_search", "arguments": {"query": "test"}},
            )
            assert panel._matches_filter(pm, "file_search") is True

    async def test_matches_filter_case_insensitive(self) -> None:
        """Filter matching is case-insensitive."""
        app = FilterTestApp()
        async with app.run_test():
            panel = app.query_one(MessageListPanel)
            pm = _make_proxy_message("tools/list")
            assert panel._matches_filter(pm, "TOOLS") is True


class TestSetFilter:
    """Tests for set_filter visibility toggling and filter-aware add_message."""

    async def test_set_filter_hides_items(self) -> None:
        """set_filter hides non-matching items via 'hidden' class."""
        app = FilterTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageListPanel)
            pm_tools = _make_proxy_message("tools/list", seq=0)
            pm_ping = _make_proxy_message("ping", seq=1, msg_id=2)
            panel.add_message(pm_tools)
            panel.add_message(pm_ping)
            await pilot.pause()

            panel.set_filter("tools")
            await pilot.pause()

            tools_item = panel.query_one(f"#msg-{pm_tools.id}")
            ping_item = panel.query_one(f"#msg-{pm_ping.id}")
            assert not tools_item.has_class("hidden")
            assert ping_item.has_class("hidden")

    async def test_set_filter_empty_shows_all(self) -> None:
        """Clearing the filter shows all items."""
        app = FilterTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageListPanel)
            pm_tools = _make_proxy_message("tools/list", seq=0)
            pm_ping = _make_proxy_message("ping", seq=1, msg_id=2)
            panel.add_message(pm_tools)
            panel.add_message(pm_ping)
            await pilot.pause()

            panel.set_filter("tools")
            await pilot.pause()
            panel.set_filter("")
            await pilot.pause()

            tools_item = panel.query_one(f"#msg-{pm_tools.id}")
            ping_item = panel.query_one(f"#msg-{pm_ping.id}")
            assert not tools_item.has_class("hidden")
            assert not ping_item.has_class("hidden")

    async def test_add_message_respects_filter(self) -> None:
        """Adding a non-matching message while filter is active hides it."""
        app = FilterTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageListPanel)
            pm_tools = _make_proxy_message("tools/list", seq=0)
            panel.add_message(pm_tools)
            await pilot.pause()

            panel.set_filter("tools")
            await pilot.pause()

            pm_ping = _make_proxy_message("ping", seq=1, msg_id=2)
            panel.add_message(pm_ping)
            await pilot.pause()

            ping_item = panel.query_one(f"#msg-{pm_ping.id}")
            assert ping_item.has_class("hidden")

    async def test_add_message_shows_matching(self) -> None:
        """Adding a matching message while filter is active shows it."""
        app = FilterTestApp()
        async with app.run_test() as pilot:
            panel = app.query_one(MessageListPanel)
            panel.set_filter("tools")
            await pilot.pause()

            pm_tools = _make_proxy_message("tools/call", seq=0)
            panel.add_message(pm_tools)
            await pilot.pause()

            tools_item = panel.query_one(f"#msg-{pm_tools.id}")
            assert not tools_item.has_class("hidden")
