"""Status bar widget for mcp-proxy TUI.

Displays the current intercept mode, message count, and held message
count at the bottom of the app above the key binding footer.
"""

from __future__ import annotations

from textual.reactive import reactive
from textual.widgets import Static

from counteragent.proxy.models import InterceptMode


class ProxyStatusBar(Static):
    """Bottom status bar showing mode, message count, and held count.

    Attributes:
        mode: Current intercept mode (PASSTHROUGH or INTERCEPT).
        message_count: Total number of messages captured.
        held_count: Number of messages currently held.
    """

    DEFAULT_CSS = """
    ProxyStatusBar {
        dock: bottom;
        height: 1;
        background: $surface;
        color: $text;
        padding: 0 1;
    }
    """

    mode: reactive[InterceptMode] = reactive(InterceptMode.PASSTHROUGH)
    message_count: reactive[int] = reactive(0)
    held_count: reactive[int] = reactive(0)
    connection_status: reactive[str] = reactive("")

    def render(self) -> str:
        """Render the status bar content.

        Returns:
            Formatted status string with mode, message count, held count,
            and connection status.
        """
        mode_label = f"[{self.mode.value.upper()}]"
        parts = [mode_label, f"Messages: {self.message_count}"]
        if self.held_count > 0:
            parts.append(f"Held: {self.held_count}")
        if self.connection_status:
            parts.append(self.connection_status)
        return "  ".join(parts)
