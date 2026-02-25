"""Unit tests for the replay engine.

Tests use a MockReplayAdapter that simulates server responses
without spawning a real subprocess.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from mcp.shared.message import SessionMessage
from mcp.types import (
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
)

from counteragent.core.models import Direction, Transport
from counteragent.proxy.models import ProxyMessage
from counteragent.proxy.replay import ReplayResult, replay_messages

# ---------------------------------------------------------------------------
# Mock adapter for replay tests
# ---------------------------------------------------------------------------


class MockReplayAdapter:
    """Adapter that queues canned responses for replay testing.

    Responses are pre-loaded and returned in order on read().
    Write() captures what was sent for assertion.
    """

    def __init__(self) -> None:
        self.read_queue: asyncio.Queue[SessionMessage | None] = asyncio.Queue()
        self.written: list[SessionMessage] = []

    async def read(self) -> SessionMessage:
        item = await self.read_queue.get()
        if item is None:
            raise RuntimeError("MockReplayAdapter closed")
        return item

    async def write(self, message: SessionMessage) -> None:
        self.written.append(message)

    async def close(self) -> None:
        pass

    def enqueue_response(self, msg_id: int | str, result: dict | None = None) -> None:
        """Queue a JSON-RPC response with the given id."""
        resp = SessionMessage(
            message=JSONRPCMessage(
                JSONRPCResponse(
                    jsonrpc="2.0",
                    id=msg_id,
                    result=result or {},
                )
            )
        )
        self.read_queue.put_nowait(resp)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_proxy_message(
    *,
    method: str = "tools/list",
    msg_id: int | str | None = 1,
    direction: Direction = Direction.CLIENT_TO_SERVER,
    sequence: int = 0,
    is_response: bool = False,
) -> ProxyMessage:
    """Build a ProxyMessage for testing.

    Args:
        method: JSON-RPC method (for requests/notifications).
        msg_id: JSON-RPC id (None for notifications).
        direction: Message direction.
        sequence: Sequence number.
        is_response: If True, build a JSONRPCResponse instead of request.
    """
    if is_response:
        raw = JSONRPCMessage(JSONRPCResponse(jsonrpc="2.0", id=msg_id, result={}))
    elif msg_id is not None:
        raw = JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=msg_id, method=method))
    else:
        raw = JSONRPCMessage(JSONRPCNotification(jsonrpc="2.0", method=method))
    return ProxyMessage(
        id=str(uuid.uuid4()),
        sequence=sequence,
        timestamp=datetime.now(tz=UTC),
        direction=direction,
        transport=Transport.STDIO,
        raw=raw,
        jsonrpc_id=msg_id,
        method=method if not is_response else None,
        correlated_id=None,
        modified=False,
        original_raw=None,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestReplaySingleRequest:
    """Replay one request, verify ReplayResult has response and duration."""

    async def test_replay_single_request(self) -> None:
        adapter = MockReplayAdapter()
        adapter.enqueue_response(1, {"tools": []})

        msg = _make_proxy_message(method="tools/list", msg_id=1)
        results = await replay_messages([msg], adapter, timeout=5.0, auto_handshake=False)

        assert len(results) == 1
        r = results[0]
        assert isinstance(r, ReplayResult)
        assert r.original_request is msg
        assert r.response is not None
        assert r.error is None
        assert r.duration_ms > 0
        # Verify the response has the right id
        assert r.response.message.root.id == 1


class TestReplayNotificationNoResponse:
    """Notifications don't wait for a response."""

    async def test_replay_notification_no_response(self) -> None:
        adapter = MockReplayAdapter()

        msg = _make_proxy_message(method="notifications/initialized", msg_id=None)
        results = await replay_messages([msg], adapter, timeout=5.0, auto_handshake=False)

        assert len(results) == 1
        r = results[0]
        assert r.response is None
        assert r.error is None
        # Should have been sent
        assert len(adapter.written) == 1


class TestReplaySkipsServerToClient:
    """Only client-to-server messages are replayed."""

    async def test_replay_skips_server_to_client(self) -> None:
        adapter = MockReplayAdapter()
        adapter.enqueue_response(1, {"tools": []})

        c2s = _make_proxy_message(
            method="tools/list", msg_id=1, direction=Direction.CLIENT_TO_SERVER
        )
        s2c = _make_proxy_message(
            msg_id=1, direction=Direction.SERVER_TO_CLIENT, sequence=1, is_response=True
        )
        results = await replay_messages([c2s, s2c], adapter, timeout=5.0, auto_handshake=False)

        # Only the client-to-server message should be replayed
        assert len(results) == 1
        assert results[0].original_request is c2s


class TestReplayTimeout:
    """Server doesn't respond — error captured after timeout."""

    async def test_replay_timeout(self) -> None:
        adapter = MockReplayAdapter()
        # Don't enqueue any response — will timeout

        msg = _make_proxy_message(method="tools/list", msg_id=1)
        results = await replay_messages([msg], adapter, timeout=0.1, auto_handshake=False)

        assert len(results) == 1
        r = results[0]
        assert r.response is None
        assert r.error is not None
        assert "timeout" in r.error.lower()


class TestReplayAutoHandshake:
    """When messages don't start with initialize, synthetic handshake is sent."""

    async def test_replay_auto_handshake(self) -> None:
        adapter = MockReplayAdapter()
        # Response for synthetic initialize (id=0 by convention or similar)
        # We need to handle whatever id the engine assigns
        # Queue initialize response then the actual request response
        adapter.enqueue_response("__handshake__", {"protocolVersion": "2024-11-05"})
        adapter.enqueue_response(2, {"tools": []})

        msg = _make_proxy_message(method="tools/list", msg_id=2, sequence=0)
        results = await replay_messages([msg], adapter, timeout=5.0, auto_handshake=True)

        # The actual message should still produce a result
        assert len(results) == 1
        assert results[0].response is not None
        # The adapter should have received: initialize, notifications/initialized, tools/list
        assert len(adapter.written) == 3
        # First written message should be initialize
        first_method = adapter.written[0].message.root.method
        assert first_method == "initialize"
        # Second should be notifications/initialized
        second_method = adapter.written[1].message.root.method
        assert second_method == "notifications/initialized"


class TestReplayPreservesOrder:
    """Multiple requests replayed in sequence order."""

    async def test_replay_preserves_order(self) -> None:
        adapter = MockReplayAdapter()
        adapter.enqueue_response(1, {"step": "first"})
        adapter.enqueue_response(2, {"step": "second"})
        adapter.enqueue_response(3, {"step": "third"})

        msgs = [
            _make_proxy_message(method="tools/list", msg_id=1, sequence=0),
            _make_proxy_message(method="tools/call", msg_id=2, sequence=1),
            _make_proxy_message(method="tools/call", msg_id=3, sequence=2),
        ]
        results = await replay_messages(msgs, adapter, timeout=5.0, auto_handshake=False)

        assert len(results) == 3
        for i, r in enumerate(results):
            assert r.original_request is msgs[i]
            assert r.response is not None
            assert r.error is None
