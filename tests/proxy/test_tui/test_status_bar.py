"""Tests for counteragent.proxy.tui.widgets.status_bar — ProxyStatusBar."""

from __future__ import annotations

from textual.app import App, ComposeResult

from counteragent.proxy.models import InterceptMode
from counteragent.proxy.tui.widgets.status_bar import ProxyStatusBar


class StatusBarTestApp(App[None]):
    """Minimal app for testing ProxyStatusBar in isolation."""

    def compose(self) -> ComposeResult:
        yield ProxyStatusBar()


class TestProxyStatusBar:
    """ProxyStatusBar displays mode, message count, and held count."""

    async def test_initial_state_passthrough(self) -> None:
        app = StatusBarTestApp()
        async with app.run_test():
            bar = app.query_one(ProxyStatusBar)
            rendered = bar.render()
            text = str(rendered)
            assert "PASSTHROUGH" in text
            assert "Messages: 0" in text

    async def test_update_message_count(self) -> None:
        app = StatusBarTestApp()
        async with app.run_test():
            bar = app.query_one(ProxyStatusBar)
            bar.message_count = 5
            rendered = bar.render()
            text = str(rendered)
            assert "Messages: 5" in text

    async def test_update_held_count(self) -> None:
        app = StatusBarTestApp()
        async with app.run_test():
            bar = app.query_one(ProxyStatusBar)
            bar.held_count = 3
            rendered = bar.render()
            text = str(rendered)
            assert "Held: 3" in text

    async def test_held_hidden_when_zero(self) -> None:
        app = StatusBarTestApp()
        async with app.run_test():
            bar = app.query_one(ProxyStatusBar)
            bar.held_count = 0
            rendered = bar.render()
            text = str(rendered)
            assert "Held:" not in text

    async def test_update_mode_intercept(self) -> None:
        app = StatusBarTestApp()
        async with app.run_test():
            bar = app.query_one(ProxyStatusBar)
            bar.mode = InterceptMode.INTERCEPT
            rendered = bar.render()
            text = str(rendered)
            assert "INTERCEPT" in text
