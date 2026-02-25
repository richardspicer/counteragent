# tests/proxy/test_tui/test_intercept_controls.py
"""Tests for TUI intercept controls — forward, drop, modify, save."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from mcp.types import JSONRPCMessage, JSONRPCRequest
from textual.widgets import Input, TextArea

from counteragent.core.models import Direction, Transport
from counteragent.proxy.models import (
    HeldMessage,
    InterceptAction,
    InterceptMode,
    ProxyMessage,
)
from counteragent.proxy.tui.app import ProxyApp
from counteragent.proxy.tui.messages import MessageHeld, MessageReceived
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


def _make_app(**kwargs: object) -> ProxyApp:
    defaults: dict[str, object] = {
        "transport": Transport.STDIO,
        "server_command": "echo hello",
        "run_pipeline_on_mount": False,
    }
    defaults.update(kwargs)
    return ProxyApp(**defaults)  # type: ignore[arg-type]


async def _add_and_hold(app: ProxyApp, pilot: object, pm: ProxyMessage) -> HeldMessage:
    """Post a message, hold it in the engine, select it in the list."""
    # Add message to list
    app.post_message(MessageReceived(pm))
    await pilot.pause()  # type: ignore[union-attr]

    # Hold it in the engine and notify the TUI
    held = app.intercept_engine.hold(pm)
    app.post_message(MessageHeld(held))
    await pilot.pause()  # type: ignore[union-attr]

    # Select the item in the list
    list_panel = app.query_one(MessageListPanel)
    list_view = list_panel.query_one("ListView")
    list_view.index = 0
    await pilot.pause()  # type: ignore[union-attr]

    return held


# ---------------------------------------------------------------------------
# Tests: Toggle intercept mode
# ---------------------------------------------------------------------------


class TestToggleIntercept:
    """Pressing 'i' toggles intercept mode."""

    async def test_toggle_intercept_mode(self) -> None:
        app = _make_app()
        async with app.run_test() as pilot:
            assert app.intercept_engine.mode == InterceptMode.PASSTHROUGH
            bar = app.query_one(ProxyStatusBar)
            assert bar.mode == InterceptMode.PASSTHROUGH

            await pilot.press("i")
            assert app.intercept_engine.mode == InterceptMode.INTERCEPT
            bar = app.query_one(ProxyStatusBar)
            assert bar.mode == InterceptMode.INTERCEPT

            await pilot.press("i")
            assert app.intercept_engine.mode == InterceptMode.PASSTHROUGH
            bar = app.query_one(ProxyStatusBar)
            assert bar.mode == InterceptMode.PASSTHROUGH


# ---------------------------------------------------------------------------
# Tests: Forward held message
# ---------------------------------------------------------------------------


class TestForward:
    """Pressing 'f' forwards the selected held message."""

    async def test_forward_held_message(self) -> None:
        app = _make_app(intercept=True)
        async with app.run_test() as pilot:
            pm = _make_proxy_message("tools/list", seq=0)
            held = await _add_and_hold(app, pilot, pm)

            await pilot.press("f")
            assert held.action == InterceptAction.FORWARD
            assert held.release.is_set()

            # Held indicator removed
            panel = app.query_one(MessageListPanel)
            assert pm.id not in panel._held_ids

            # Status bar updated
            bar = app.query_one(ProxyStatusBar)
            assert bar.held_count == 0


# ---------------------------------------------------------------------------
# Tests: Drop held message
# ---------------------------------------------------------------------------


class TestDrop:
    """Pressing 'd' drops the selected held message."""

    async def test_drop_held_message(self) -> None:
        app = _make_app(intercept=True)
        async with app.run_test() as pilot:
            pm = _make_proxy_message("tools/call", seq=0)
            held = await _add_and_hold(app, pilot, pm)

            await pilot.press("d")
            assert held.action == InterceptAction.DROP
            assert held.release.is_set()

            # Drop indicator shown
            panel = app.query_one(MessageListPanel)
            assert pm.id in panel._dropped_ids

            # Status bar updated
            bar = app.query_one(ProxyStatusBar)
            assert bar.held_count == 0


# ---------------------------------------------------------------------------
# Tests: Modify flow
# ---------------------------------------------------------------------------


class TestModify:
    """Modify flow: 'm' enters edit, ctrl+s confirms, escape cancels."""

    async def test_modify_enter_edit_mode(self) -> None:
        app = _make_app(intercept=True)
        async with app.run_test() as pilot:
            pm = _make_proxy_message("tools/list", seq=0)
            await _add_and_hold(app, pilot, pm)

            await pilot.press("m")
            detail = app.query_one(MessageDetailPanel)
            assert detail.is_editing
            assert app._editing

            # TextArea should be visible and contain JSON
            editor = detail.query_one("#detail-editor", TextArea)
            assert "hidden" not in editor.classes
            assert "tools/list" in editor.text

    async def test_modify_confirm(self) -> None:
        app = _make_app(intercept=True)
        async with app.run_test() as pilot:
            pm = _make_proxy_message("tools/list", seq=0, msg_id=1)
            held = await _add_and_hold(app, pilot, pm)

            # Enter edit mode
            await pilot.press("m")
            detail = app.query_one(MessageDetailPanel)

            # Modify the text in the editor — change method
            editor = detail.query_one("#detail-editor", TextArea)
            modified_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
            }
            editor.text = json.dumps(modified_payload, indent=2)
            await pilot.pause()

            # Confirm
            await pilot.press("ctrl+s")

            assert held.action == InterceptAction.MODIFY
            assert held.release.is_set()
            assert held.modified_raw is not None
            assert not detail.is_editing
            assert not app._editing

    async def test_modify_cancel(self) -> None:
        app = _make_app(intercept=True)
        async with app.run_test() as pilot:
            pm = _make_proxy_message("tools/list", seq=0)
            held = await _add_and_hold(app, pilot, pm)

            # Enter edit mode
            await pilot.press("m")
            assert app._editing

            # Cancel with escape
            await pilot.press("escape")

            # Should forward as-is
            assert held.action == InterceptAction.FORWARD
            assert held.release.is_set()
            assert not app._editing

            detail = app.query_one(MessageDetailPanel)
            assert not detail.is_editing


# ---------------------------------------------------------------------------
# Tests: No-op cases
# ---------------------------------------------------------------------------


class TestNoopCases:
    """Actions are no-ops when nothing is selected or message isn't held."""

    async def test_actions_noop_no_selection(self) -> None:
        """Press f/d/m with no messages — no crash."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.press("f")
            await pilot.press("d")
            await pilot.press("m")
            # No crash, no state changes
            assert not app._editing

    async def test_actions_noop_not_held(self) -> None:
        """Select a non-held message, press f/d/m — no action."""
        app = _make_app()
        async with app.run_test() as pilot:
            pm = _make_proxy_message("tools/list", seq=0)
            app.post_message(MessageReceived(pm))
            await pilot.pause()

            # Select the item
            list_panel = app.query_one(MessageListPanel)
            list_view = list_panel.query_one("ListView")
            list_view.index = 0
            await pilot.pause()

            # These should be no-ops (message not held)
            await pilot.press("f")
            await pilot.press("d")
            await pilot.press("m")
            assert not app._editing


# ---------------------------------------------------------------------------
# Tests: Save session
# ---------------------------------------------------------------------------


class TestSaveSession:
    """Session save via 's' key."""

    async def test_save_session_with_path(self, tmp_path: Path) -> None:
        save_path = tmp_path / "test_session.json"
        app = _make_app(session_file=save_path)
        async with app.run_test() as pilot:
            # Add a message so there's something to save
            pm = _make_proxy_message("tools/list", seq=0)
            app.post_message(MessageReceived(pm))
            await pilot.pause()

            await pilot.press("s")
            await pilot.pause()

            assert save_path.exists()
            content = json.loads(save_path.read_text(encoding="utf-8"))
            assert "messages" in content

    async def test_save_session_prompts(self) -> None:
        """Without session_file, pressing 's' mounts an Input widget."""
        app = _make_app()
        async with app.run_test() as pilot:
            await pilot.press("s")
            await pilot.pause()

            # Input widget should be mounted
            save_input = app.query_one("#save-input", Input)
            assert save_input is not None
