"""Custom Textual message types for pipeline-to-TUI communication.

These messages bridge the gap between the background pipeline worker
and the Textual UI thread. The pipeline fires callbacks that post
these messages via ``app.post_message()``.
"""

from __future__ import annotations

from textual.message import Message

from counteragent.proxy.models import HeldMessage, ProxyMessage
from counteragent.proxy.replay import ReplayResult


class MessageReceived(Message):
    """A new JSON-RPC message was captured by the pipeline.

    Args:
        proxy_message: The wrapped ProxyMessage with metadata.
    """

    def __init__(self, proxy_message: ProxyMessage) -> None:
        super().__init__()
        self.proxy_message = proxy_message


class MessageHeld(Message):
    """A message was held by the intercept engine for user action.

    Args:
        held_message: The HeldMessage awaiting forward/modify/drop.
    """

    def __init__(self, held_message: HeldMessage) -> None:
        super().__init__()
        self.held_message = held_message


class MessageForwarded(Message):
    """A message was forwarded to its destination.

    Args:
        proxy_message: The forwarded ProxyMessage (may be modified).
    """

    def __init__(self, proxy_message: ProxyMessage) -> None:
        super().__init__()
        self.proxy_message = proxy_message


class PipelineError(Message):
    """The pipeline encountered an error.

    Args:
        error: The exception that occurred.
    """

    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error


class PipelineStopped(Message):
    """The pipeline has stopped (adapters disconnected)."""

    def __init__(self) -> None:
        super().__init__()


class ReplayCompleted(Message):
    """Replay of a message completed with results.

    Args:
        result: The ReplayResult from the replay engine.
        original_response: The original server response for comparison
            (None if no correlated response was found).
    """

    def __init__(self, result: ReplayResult, original_response: ProxyMessage | None) -> None:
        super().__init__()
        self.result = result
        self.original_response = original_response
