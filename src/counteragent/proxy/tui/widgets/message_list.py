"""Message list widget for mcp-proxy TUI.

Scrollable list showing the live stream of intercepted JSON-RPC messages.
Each item displays direction, sequence number, and method/type.
"""

from __future__ import annotations

import json

from textual.app import ComposeResult
from textual.binding import Binding
from textual.css.query import NoMatches
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Input, ListItem, ListView, Static

from counteragent.core.models import Direction
from counteragent.proxy.models import ProxyMessage


class MessageSelected(Message):
    """Fired when the user selects a message in the list.

    Args:
        proxy_message: The selected ProxyMessage.
    """

    def __init__(self, proxy_message: ProxyMessage) -> None:
        super().__init__()
        self.proxy_message = proxy_message


class MessageListPanel(Widget):
    """Left-side panel showing the live message stream.

    Messages are displayed as: ``{icon} #{sequence} {arrow} {method_or_type}``

    - ``\\u25ba`` (right arrow) for CLIENT_TO_SERVER
    - ``\\u25c4`` (left arrow) for SERVER_TO_CLIENT
    - ``\\u23f8`` (pause icon) prefix for held messages
    - ``\\u2715`` (cross mark) prefix for dropped messages

    Attributes:
        messages: Ordered list of all ProxyMessages added.
    """

    DEFAULT_CSS = """
    MessageListPanel {
        border: solid $primary;
    }
    """

    BINDINGS = [
        Binding("escape", "unfocus_filter", "Back to list", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.messages: list[ProxyMessage] = []
        self._held_ids: set[str] = set()
        self._dropped_ids: set[str] = set()
        self._active_filter: str = ""

    def compose(self) -> ComposeResult:
        """Compose the widget with a filter Input and ListView."""
        yield Input(placeholder="Filter (> client, < server)...", id="filter-input")
        yield ListView()

    def add_message(self, proxy_message: ProxyMessage) -> None:
        """Add a new message to the list.

        Respects the active filter — non-matching messages are added hidden.

        Args:
            proxy_message: The message to add.
        """
        self.messages.append(proxy_message)
        label = self._format_label(proxy_message)
        item = ListItem(Static(label), id=f"msg-{proxy_message.id}")
        if self._active_filter and not self._matches_filter(proxy_message, self._active_filter):
            item.add_class("hidden")
        self.query_one(ListView).append(item)

    def mark_held(self, proxy_id: str) -> None:
        """Mark a message as held (show pause icon).

        Args:
            proxy_id: The ProxyMessage.id to mark.
        """
        self._held_ids.add(proxy_id)
        self._update_item_label(proxy_id)

    def mark_forwarded(self, proxy_id: str) -> None:
        """Remove held indicator from a message.

        Args:
            proxy_id: The ProxyMessage.id to update.
        """
        self._held_ids.discard(proxy_id)
        self._update_item_label(proxy_id)

    def mark_dropped(self, proxy_id: str) -> None:
        """Show drop indicator on a message.

        Args:
            proxy_id: The ProxyMessage.id to mark as dropped.
        """
        self._held_ids.discard(proxy_id)
        self._dropped_ids.add(proxy_id)
        self._update_item_label(proxy_id)

    def get_selected_message(self) -> ProxyMessage | None:
        """Return the ProxyMessage for the currently highlighted item.

        Returns:
            The selected ProxyMessage, or None if nothing is highlighted.
        """
        list_view = self.query_one(ListView)
        if list_view.highlighted_child is None:
            return None
        item_id = list_view.highlighted_child.id
        if item_id is None:
            return None
        proxy_id = item_id.removeprefix("msg-")
        for pm in self.messages:
            if pm.id == proxy_id:
                return pm
        return None

    def _update_item_label(self, proxy_id: str) -> None:
        """Re-render the label for a message item.

        Args:
            proxy_id: The ProxyMessage.id to update.
        """
        for pm in self.messages:
            if pm.id == proxy_id:
                try:
                    item = self.query_one(f"#msg-{proxy_id}", ListItem)
                    label = self._format_label(pm)
                    item.query_one(Static).update(label)
                except NoMatches:
                    pass
                break

    def _format_label(self, pm: ProxyMessage) -> str:
        """Format a single message line for display.

        Args:
            pm: The ProxyMessage to format.

        Returns:
            Formatted label string.
        """
        if pm.id in self._dropped_ids:
            prefix = "\u2715 "
        elif pm.id in self._held_ids:
            prefix = "\u23f8 "
        else:
            prefix = ""
        arrow = "\u25ba" if pm.direction == Direction.CLIENT_TO_SERVER else "\u25c4"
        method_label = pm.method if pm.method else "response"
        return f"{prefix}{arrow} #{pm.sequence} {method_label}"

    def _matches_filter(self, pm: ProxyMessage, filter_text: str) -> bool:
        """Check if a ProxyMessage matches the filter.

        Args:
            pm: The ProxyMessage to check.
            filter_text: The filter string.

        Returns:
            True if the message matches.
        """
        if not filter_text:
            return True

        text = filter_text
        required_direction: Direction | None = None

        if text.startswith(">"):
            required_direction = Direction.CLIENT_TO_SERVER
            text = text[1:].strip()
        elif text.startswith("<"):
            required_direction = Direction.SERVER_TO_CLIENT
            text = text[1:].strip()

        if required_direction is not None and pm.direction != required_direction:
            return False

        if not text:
            return True

        text_lower = text.lower()

        if pm.method and text_lower in pm.method.lower():
            return True

        payload = pm.raw.model_dump(by_alias=True, exclude_none=True)
        serialized = json.dumps(payload).lower()
        return text_lower in serialized

    def set_filter(self, filter_text: str) -> None:
        """Apply a filter to the message list.

        Shows only messages matching the filter. Empty string shows all.

        Args:
            filter_text: The filter string to apply.
        """
        self._active_filter = filter_text
        list_view = self.query_one(ListView)
        for pm in self.messages:
            try:
                item = list_view.query_one(f"#msg-{pm.id}", ListItem)
            except NoMatches:
                continue
            if self._matches_filter(pm, filter_text):
                item.remove_class("hidden")
            else:
                item.add_class("hidden")

    def on_mount(self) -> None:
        """Focus the ListView on mount so the filter input is not auto-focused."""
        self.query_one(ListView).focus()

    def action_unfocus_filter(self) -> None:
        """Return focus from the filter input to the message list."""
        self.query_one(ListView).focus()

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        """Handle list item highlight -- fire MessageSelected.

        Args:
            event: The Textual highlighted event from ListView.
        """
        if event.item is None:
            return
        item_id = event.item.id
        if item_id is None:
            return
        # Extract proxy_id from "msg-{uuid}"
        proxy_id = item_id.removeprefix("msg-")
        for pm in self.messages:
            if pm.id == proxy_id:
                self.post_message(MessageSelected(pm))
                break
