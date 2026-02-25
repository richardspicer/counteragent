"""Message detail panel for mcp-proxy TUI.

Displays the full JSON-RPC payload and proxy metadata for a selected
message. Supports read-only viewing via RichLog and edit mode via TextArea.
"""

from __future__ import annotations

import json

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import RichLog, TextArea

from counteragent.proxy.models import ProxyMessage
from counteragent.proxy.replay import ReplayResult


class MessageDetailPanel(Widget):
    """Right-side panel showing JSON-RPC payload and metadata.

    Displays formatted JSON of the selected message along with proxy
    metadata (sequence, direction, timestamp, correlation). Supports
    toggling into edit mode for message modification.

    Example:
        panel.show_message(proxy_message)
        panel.enter_edit_mode(proxy_message)
        text = panel.get_edited_text()
        panel.exit_edit_mode()
    """

    DEFAULT_CSS = """
    MessageDetailPanel {
        border: solid $primary;
        padding: 0 1;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._current_message: ProxyMessage | None = None
        self._editing: bool = False

    def compose(self) -> ComposeResult:
        """Compose the widget with a RichLog viewer and hidden TextArea editor."""
        yield RichLog(id="detail-log")
        yield TextArea(id="detail-editor", classes="hidden")

    @property
    def is_editing(self) -> bool:
        """Whether the panel is currently in edit mode."""
        return self._editing

    def show_message(self, proxy_message: ProxyMessage) -> None:
        """Display a ProxyMessage's payload and metadata.

        Args:
            proxy_message: The message to display.
        """
        self._current_message = proxy_message
        log = self.query_one("#detail-log", RichLog)
        log.clear()

        # Metadata header
        log.write(f"--- Message #{proxy_message.sequence} ---")
        log.write(f"Direction: {proxy_message.direction.value}")
        log.write(f"Timestamp: {proxy_message.timestamp.isoformat()}")
        if proxy_message.method:
            log.write(f"Method: {proxy_message.method}")
        if proxy_message.jsonrpc_id is not None:
            log.write(f"JSON-RPC ID: {proxy_message.jsonrpc_id}")
        if proxy_message.correlated_id:
            log.write(f"Correlated to: {proxy_message.correlated_id}")
        if proxy_message.modified:
            log.write("[Modified]")
        log.write("")

        # JSON payload
        payload = proxy_message.raw.model_dump(by_alias=True, exclude_none=True)
        formatted = json.dumps(payload, indent=2)
        log.write(formatted)

    def enter_edit_mode(self, proxy_message: ProxyMessage) -> None:
        """Switch to edit mode with the message payload in a TextArea.

        Args:
            proxy_message: The message to edit.
        """
        self._current_message = proxy_message
        self._editing = True

        payload = proxy_message.raw.model_dump(by_alias=True, exclude_none=True)
        formatted = json.dumps(payload, indent=2)

        editor = self.query_one("#detail-editor", TextArea)
        editor.text = formatted

        # Toggle visibility
        self.query_one("#detail-log", RichLog).add_class("hidden")
        editor.remove_class("hidden")
        editor.focus()

    def exit_edit_mode(self) -> None:
        """Switch back to read-only mode."""
        self._editing = False

        # Toggle visibility
        self.query_one("#detail-editor", TextArea).add_class("hidden")
        self.query_one("#detail-log", RichLog).remove_class("hidden")

    def get_edited_text(self) -> str:
        """Return the current content of the TextArea editor.

        Returns:
            The edited JSON text.
        """
        text: str = self.query_one("#detail-editor", TextArea).text
        return text

    def show_replay_diff(
        self,
        original_response: ProxyMessage | None,
        replay_result: ReplayResult,
    ) -> None:
        """Display original and replay responses for comparison.

        Args:
            original_response: The original server response (None if not correlated).
            replay_result: The replay engine result containing the new response.
        """
        if self._editing:
            self.exit_edit_mode()

        log = self.query_one("#detail-log", RichLog)
        log.clear()

        if original_response is not None:
            log.write("--- ORIGINAL RESPONSE ---")
            payload = original_response.raw.model_dump(by_alias=True, exclude_none=True)
            log.write(json.dumps(payload, indent=2))
            log.write("")

        log.write("--- REPLAY RESPONSE ---")
        if replay_result.error:
            log.write(f"ERROR: {replay_result.error}")
        elif replay_result.response is not None:
            payload = replay_result.response.message.model_dump(by_alias=True, exclude_none=True)
            log.write(json.dumps(payload, indent=2))
        else:
            log.write("(no response)")

        log.write("")
        log.write(f"Duration: {replay_result.duration_ms:.1f}ms")
