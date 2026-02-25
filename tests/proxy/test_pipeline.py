"""Tests for counteragent.proxy.pipeline — run_pipeline and _forward_loop."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from mcp.shared.message import SessionMessage
from mcp.types import (
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
)

from counteragent.core.models import Direction, Transport
from counteragent.proxy.intercept import InterceptEngine
from counteragent.proxy.models import (
    HeldMessage,
    InterceptAction,
    InterceptMode,
    ProxyMessage,
)
from counteragent.proxy.pipeline import PipelineSession, run_pipeline
from counteragent.proxy.session_store import SessionStore

# ---------------------------------------------------------------------------
# Mock adapter
# ---------------------------------------------------------------------------


class MockAdapter:
    """Mock TransportAdapter backed by asyncio.Queue.

    Pre-load messages into ``read_queue`` for the pipeline to consume.
    Inspect ``write_queue`` for messages the pipeline forwarded.
    """

    def __init__(self) -> None:
        self.read_queue: asyncio.Queue[SessionMessage | None] = asyncio.Queue()
        self.write_queue: asyncio.Queue[SessionMessage] = asyncio.Queue()
        self._closed = False

    async def read(self) -> SessionMessage:
        """Return next message, or raise when None (signals close)."""
        item = await self.read_queue.get()
        if item is None:
            raise Exception("Connection closed")
        return item

    async def write(self, message: SessionMessage) -> None:
        """Store forwarded message for test inspection."""
        await self.write_queue.put(message)

    async def close(self) -> None:
        """Mark as closed."""
        self._closed = True

    def enqueue(self, *messages: SessionMessage) -> None:
        """Pre-load messages and a close sentinel."""
        for msg in messages:
            self.read_queue.put_nowait(msg)
        self.read_queue.put_nowait(None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(method: str = "tools/list", msg_id: int = 1) -> SessionMessage:
    return SessionMessage(
        message=JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=msg_id, method=method))
    )


def _make_response(msg_id: int = 1) -> SessionMessage:
    return SessionMessage(
        message=JSONRPCMessage(JSONRPCResponse(jsonrpc="2.0", id=msg_id, result={}))
    )


def _make_notification(method: str = "notifications/initialized") -> SessionMessage:
    return SessionMessage(message=JSONRPCMessage(JSONRPCNotification(jsonrpc="2.0", method=method)))


def _make_pipeline_session(**overrides: Any) -> PipelineSession:
    """Build a PipelineSession with sensible defaults."""
    defaults: dict[str, Any] = {
        "session_store": SessionStore(session_id=str(uuid.uuid4()), transport=Transport.STDIO),
        "intercept_engine": InterceptEngine(mode=InterceptMode.PASSTHROUGH),
        "transport": Transport.STDIO,
        "on_message": None,
        "on_held": None,
        "on_forwarded": None,
    }
    defaults.update(overrides)
    return PipelineSession(**defaults)


# ---------------------------------------------------------------------------
# Tests: Basic forwarding
# ---------------------------------------------------------------------------


class TestClientToServerForwarding:
    """Messages from client adapter reach server adapter."""

    async def test_single_request_forwarded(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        req = _make_request("tools/list", msg_id=1)
        client.enqueue(req)
        server.enqueue()  # server sends nothing, closes immediately

        session = _make_pipeline_session()
        await run_pipeline(client, server, session)

        forwarded = server.write_queue.get_nowait()
        assert forwarded.message.root.method == "tools/list"

    async def test_multiple_requests_forwarded_in_order(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        req1 = _make_request("tools/list", msg_id=1)
        req2 = _make_request("tools/call", msg_id=2)
        client.enqueue(req1, req2)
        server.enqueue()

        session = _make_pipeline_session()
        await run_pipeline(client, server, session)

        fwd1 = server.write_queue.get_nowait()
        fwd2 = server.write_queue.get_nowait()
        assert fwd1.message.root.method == "tools/list"
        assert fwd2.message.root.method == "tools/call"


class TestServerToClientForwarding:
    """Messages from server adapter reach client adapter."""

    async def test_response_forwarded(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        resp = _make_response(msg_id=1)
        server.enqueue(resp)
        client.enqueue()

        session = _make_pipeline_session()
        await run_pipeline(client, server, session)

        forwarded = client.write_queue.get_nowait()
        assert forwarded.message.root.id == 1


class TestBidirectionalForwarding:
    """Messages flow both directions concurrently."""

    async def test_bidirectional(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        req = _make_request("tools/list", msg_id=1)
        resp = _make_response(msg_id=1)
        client.enqueue(req)
        server.enqueue(resp)

        session = _make_pipeline_session()
        await run_pipeline(client, server, session)

        server_got = server.write_queue.get_nowait()
        client_got = client.write_queue.get_nowait()
        assert server_got.message.root.method == "tools/list"
        assert client_got.message.root.id == 1


# ---------------------------------------------------------------------------
# Tests: ProxyMessage wrapping
# ---------------------------------------------------------------------------


class TestProxyMessageWrapping:
    """Messages are wrapped as ProxyMessage with correct metadata."""

    async def test_metadata_fields(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        req = _make_request("tools/list", msg_id=1)
        client.enqueue(req)
        server.enqueue()

        session = _make_pipeline_session()
        await run_pipeline(client, server, session)

        messages = session.session_store.get_messages()
        assert len(messages) >= 1
        msg = messages[0]
        assert msg.direction == Direction.CLIENT_TO_SERVER
        assert msg.transport == Transport.STDIO
        assert msg.jsonrpc_id == 1
        assert msg.method == "tools/list"
        assert msg.modified is False
        assert msg.original_raw is None
        # UUID format
        uuid.UUID(msg.id)
        # Sequence starts at 0
        assert msg.sequence == 0

    async def test_sequence_monotonic(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        req1 = _make_request("tools/list", msg_id=1)
        req2 = _make_request("tools/call", msg_id=2)
        client.enqueue(req1, req2)
        server.enqueue()

        session = _make_pipeline_session()
        await run_pipeline(client, server, session)

        messages = session.session_store.get_messages()
        client_msgs = [m for m in messages if m.direction == Direction.CLIENT_TO_SERVER]
        assert len(client_msgs) == 2
        assert client_msgs[0].sequence < client_msgs[1].sequence


# ---------------------------------------------------------------------------
# Tests: Correlation
# ---------------------------------------------------------------------------


class TestCorrelation:
    """Request-response correlation by JSON-RPC id."""

    async def test_response_correlated_to_request(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        req = _make_request("tools/list", msg_id=42)
        resp = _make_response(msg_id=42)
        client.enqueue(req)
        server.enqueue(resp)

        session = _make_pipeline_session()
        await run_pipeline(client, server, session)

        messages = session.session_store.get_messages()
        request_msg = next(m for m in messages if m.method == "tools/list")
        response_msg = next(m for m in messages if m.method is None and m.jsonrpc_id == 42)
        assert response_msg.correlated_id == request_msg.id

    async def test_notification_not_correlated(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        notif = _make_notification("notifications/initialized")
        client.enqueue(notif)
        server.enqueue()

        session = _make_pipeline_session()
        await run_pipeline(client, server, session)

        messages = session.session_store.get_messages()
        notif_msg = next(m for m in messages if m.method == "notifications/initialized")
        assert notif_msg.correlated_id is None


# ---------------------------------------------------------------------------
# Tests: Pipeline exits cleanly on adapter disconnect
# ---------------------------------------------------------------------------


class TestCleanShutdown:
    """Pipeline exits cleanly when an adapter raises."""

    async def test_exits_when_client_disconnects(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        client.enqueue()  # immediate close
        server.enqueue()

        session = _make_pipeline_session()
        # Should not raise
        await run_pipeline(client, server, session)

    async def test_exits_when_server_disconnects(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        client.enqueue()
        server.enqueue()

        session = _make_pipeline_session()
        await run_pipeline(client, server, session)


# ---------------------------------------------------------------------------
# Tests: Intercept mode
# ---------------------------------------------------------------------------


class TestInterceptHoldAndForward:
    """Intercept mode holds messages until released with FORWARD."""

    async def test_message_held_then_forwarded(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        req = _make_request("tools/list", msg_id=1)
        client.enqueue(req)
        server.enqueue()

        engine = InterceptEngine(mode=InterceptMode.INTERCEPT)
        held_messages: list[HeldMessage] = []

        def capture_held(held: HeldMessage) -> None:
            held_messages.append(held)
            # Auto-release after capture
            engine.release(held, InterceptAction.FORWARD)

        session = _make_pipeline_session(
            intercept_engine=engine,
            on_held=capture_held,
        )
        await run_pipeline(client, server, session)

        assert len(held_messages) == 1
        forwarded = server.write_queue.get_nowait()
        assert forwarded.message.root.method == "tools/list"


class TestInterceptDrop:
    """Intercept mode drops messages when released with DROP."""

    async def test_dropped_message_not_forwarded(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        req = _make_request("tools/list", msg_id=1)
        client.enqueue(req)
        server.enqueue()

        engine = InterceptEngine(mode=InterceptMode.INTERCEPT)

        def drop_all(held: HeldMessage) -> None:
            engine.release(held, InterceptAction.DROP)

        session = _make_pipeline_session(
            intercept_engine=engine,
            on_held=drop_all,
        )
        await run_pipeline(client, server, session)

        assert server.write_queue.empty()


class TestInterceptModify:
    """Intercept mode forwards modified payload when released with MODIFY."""

    async def test_modified_message_forwarded(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        req = _make_request("tools/list", msg_id=1)
        client.enqueue(req)
        server.enqueue()

        engine = InterceptEngine(mode=InterceptMode.INTERCEPT)
        modified_raw = JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=1, method="tools/call"))

        def modify_all(held: HeldMessage) -> None:
            engine.release(held, InterceptAction.MODIFY, modified_raw=modified_raw)

        session = _make_pipeline_session(
            intercept_engine=engine,
            on_held=modify_all,
        )
        await run_pipeline(client, server, session)

        forwarded = server.write_queue.get_nowait()
        assert forwarded.message.root.method == "tools/call"

        # Verify modification tracking on the stored ProxyMessage
        messages = session.session_store.get_messages()
        modified_msg = [m for m in messages if m.method == "tools/list"][0]
        assert modified_msg.modified is True
        assert modified_msg.original_raw is not None
        assert modified_msg.raw == modified_raw


# ---------------------------------------------------------------------------
# Tests: Callbacks
# ---------------------------------------------------------------------------


class TestCallbacks:
    """Pipeline callbacks fire at correct points."""

    async def test_on_message_fires(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        req = _make_request("tools/list", msg_id=1)
        client.enqueue(req)
        server.enqueue()

        received: list[ProxyMessage] = []
        session = _make_pipeline_session(on_message=lambda m: received.append(m))
        await run_pipeline(client, server, session)

        assert len(received) >= 1
        assert received[0].method == "tools/list"

    async def test_on_forwarded_fires(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        req = _make_request("tools/list", msg_id=1)
        client.enqueue(req)
        server.enqueue()

        forwarded: list[ProxyMessage] = []
        session = _make_pipeline_session(on_forwarded=lambda m: forwarded.append(m))
        await run_pipeline(client, server, session)

        assert len(forwarded) >= 1
        assert forwarded[0].method == "tools/list"

    async def test_on_held_fires_in_intercept_mode(self) -> None:
        client = MockAdapter()
        server = MockAdapter()
        req = _make_request("tools/list", msg_id=1)
        client.enqueue(req)
        server.enqueue()

        engine = InterceptEngine(mode=InterceptMode.INTERCEPT)
        held_notifications: list[HeldMessage] = []

        def on_held(held: HeldMessage) -> None:
            held_notifications.append(held)
            engine.release(held, InterceptAction.FORWARD)

        session = _make_pipeline_session(
            intercept_engine=engine,
            on_held=on_held,
        )
        await run_pipeline(client, server, session)

        assert len(held_notifications) == 1
