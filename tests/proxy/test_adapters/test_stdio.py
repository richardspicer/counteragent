"""Tests for counteragent.proxy.adapters.stdio — StdioServerAdapter and StdioClientAdapter.

Uses mocked SDK functions (stdio_client, stdio_server) with real anyio
memory object streams. No subprocess spawning.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import patch

import anyio
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest, JSONRPCResponse

from counteragent.proxy.adapters.stdio import StdioClientAdapter, StdioServerAdapter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session_message(method: str = "tools/list", msg_id: int = 1) -> SessionMessage:
    """Build a SessionMessage wrapping a JSON-RPC request."""
    return SessionMessage(
        message=JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=msg_id, method=method))
    )


def _make_response_message(msg_id: int = 1) -> SessionMessage:
    """Build a SessionMessage wrapping a JSON-RPC response."""
    return SessionMessage(
        message=JSONRPCMessage(JSONRPCResponse(jsonrpc="2.0", id=msg_id, result={}))
    )


@asynccontextmanager
async def _mock_stdio_streams(
    inbound: list[SessionMessage | Exception] | None = None,
):
    """Create a mock that yields real anyio memory streams.

    Pre-loads ``inbound`` items into the read stream, then closes the
    send end so the reader sees end-of-stream after consuming them.

    Yields:
        (read_stream, write_stream) — same shape as stdio_client / stdio_server.
    """
    # read_stream: adapter reads FROM here (server/client → adapter)
    read_send, read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](
        max_buffer_size=16
    )
    # write_stream: adapter writes TO here (adapter → server/client)
    write_send, write_recv = anyio.create_memory_object_stream[SessionMessage](max_buffer_size=16)

    # Preload inbound items and close the send end
    if inbound:
        for item in inbound:
            read_send.send_nowait(item)
    read_send.close()

    # Expose write_recv so tests can inspect what the adapter sent
    yield read_recv, write_send  # type: ignore[misc]

    # Clean up
    write_send.close()
    read_recv.close()
    write_recv.close()


# ---------------------------------------------------------------------------
# StdioServerAdapter
# ---------------------------------------------------------------------------


class TestStdioServerAdapterRead:
    """Reading messages from the server via StdioServerAdapter."""

    async def test_read_returns_session_message(self) -> None:
        """Adapter.read() returns a SessionMessage from the SDK stream."""
        msg = _make_session_message()

        @asynccontextmanager
        async def fake_stdio_client(*args: Any, **kwargs: Any):
            async with _mock_stdio_streams(inbound=[msg]) as (r, w):
                yield r, w

        with patch("counteragent.proxy.adapters.stdio.stdio_client", fake_stdio_client):
            async with StdioServerAdapter(command="fake", args=[]) as adapter:
                result = await adapter.read()

        assert result.message == msg.message

    async def test_read_skips_exceptions(self, caplog: Any) -> None:
        """Exception items from the SDK stream are logged and skipped."""
        err = RuntimeError("parse error")
        msg = _make_session_message()

        @asynccontextmanager
        async def fake_stdio_client(*args: Any, **kwargs: Any):
            async with _mock_stdio_streams(inbound=[err, msg]) as (r, w):
                yield r, w

        with (
            patch("counteragent.proxy.adapters.stdio.stdio_client", fake_stdio_client),
            caplog.at_level(logging.WARNING),
        ):
            async with StdioServerAdapter(command="fake", args=[]) as adapter:
                result = await adapter.read()

        # Should get the valid message, having skipped the exception
        assert result.message == msg.message
        assert "parse error" in caplog.text


class TestStdioServerAdapterWrite:
    """Writing messages to the server via StdioServerAdapter."""

    async def test_write_sends_to_stream(self) -> None:
        """Adapter.write() sends the message through to the SDK stream."""
        msg = _make_session_message()
        write_recv_ref: list[Any] = []

        @asynccontextmanager
        async def fake_stdio_client(*args: Any, **kwargs: Any):
            read_send, read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](
                max_buffer_size=16
            )
            write_send, write_recv = anyio.create_memory_object_stream[SessionMessage](
                max_buffer_size=16
            )
            write_recv_ref.append(write_recv)
            yield read_recv, write_send
            read_send.close()
            read_recv.close()
            write_send.close()
            write_recv.close()

        with patch("counteragent.proxy.adapters.stdio.stdio_client", fake_stdio_client):
            async with StdioServerAdapter(command="fake", args=[]) as adapter:
                await adapter.write(msg)
                # Give writer task a chance to forward the message
                await asyncio.sleep(0.05)
                # Verify the message arrived on the receive end of the write stream
                result = write_recv_ref[0].receive_nowait()
                assert result.message == msg.message


class TestStdioServerAdapterClose:
    """Lifecycle and close behavior for StdioServerAdapter."""

    async def test_close_is_idempotent(self) -> None:
        """Calling close() multiple times does not raise."""

        @asynccontextmanager
        async def fake_stdio_client(*args: Any, **kwargs: Any):
            async with _mock_stdio_streams() as (r, w):
                yield r, w

        with patch("counteragent.proxy.adapters.stdio.stdio_client", fake_stdio_client):
            async with StdioServerAdapter(command="fake", args=[]) as adapter:
                await adapter.close()
                await adapter.close()  # should not raise

    async def test_read_on_closed_raises(self) -> None:
        """read() on a closed adapter raises RuntimeError."""

        @asynccontextmanager
        async def fake_stdio_client(*args: Any, **kwargs: Any):
            async with _mock_stdio_streams() as (r, w):
                yield r, w

        with patch("counteragent.proxy.adapters.stdio.stdio_client", fake_stdio_client):
            async with StdioServerAdapter(command="fake", args=[]) as adapter:
                await adapter.close()
                try:
                    await asyncio.wait_for(adapter.read(), timeout=0.5)
                    raise AssertionError("Expected RuntimeError")  # noqa: TRY301
                except RuntimeError:
                    pass

    async def test_write_on_closed_raises(self) -> None:
        """write() on a closed adapter raises RuntimeError."""
        msg = _make_session_message()

        @asynccontextmanager
        async def fake_stdio_client(*args: Any, **kwargs: Any):
            async with _mock_stdio_streams() as (r, w):
                yield r, w

        with patch("counteragent.proxy.adapters.stdio.stdio_client", fake_stdio_client):
            async with StdioServerAdapter(command="fake", args=[]) as adapter:
                await adapter.close()
                try:
                    await adapter.write(msg)
                    raise AssertionError("Expected RuntimeError")  # noqa: TRY301
                except RuntimeError:
                    pass

    async def test_context_manager_lifecycle(self) -> None:
        """Entering and exiting the context manager works cleanly."""

        @asynccontextmanager
        async def fake_stdio_client(*args: Any, **kwargs: Any):
            async with _mock_stdio_streams() as (r, w):
                yield r, w

        with patch("counteragent.proxy.adapters.stdio.stdio_client", fake_stdio_client):
            async with StdioServerAdapter(command="fake", args=[]) as adapter:
                assert adapter is not None
            # After exit, adapter should be closed
            assert adapter._closed


# ---------------------------------------------------------------------------
# StdioClientAdapter
# ---------------------------------------------------------------------------


class TestStdioClientAdapterRead:
    """Reading messages from the client via StdioClientAdapter."""

    async def test_read_returns_session_message(self) -> None:
        """Adapter.read() returns a SessionMessage from the SDK stream."""
        msg = _make_session_message()

        @asynccontextmanager
        async def fake_stdio_server(*args: Any, **kwargs: Any):
            async with _mock_stdio_streams(inbound=[msg]) as (r, w):
                yield r, w

        with patch("counteragent.proxy.adapters.stdio.stdio_server", fake_stdio_server):
            async with StdioClientAdapter() as adapter:
                result = await adapter.read()

        assert result.message == msg.message

    async def test_read_skips_exceptions(self, caplog: Any) -> None:
        """Exception items from the SDK stream are logged and skipped."""
        err = ValueError("bad frame")
        msg = _make_response_message()

        @asynccontextmanager
        async def fake_stdio_server(*args: Any, **kwargs: Any):
            async with _mock_stdio_streams(inbound=[err, msg]) as (r, w):
                yield r, w

        with (
            patch("counteragent.proxy.adapters.stdio.stdio_server", fake_stdio_server),
            caplog.at_level(logging.WARNING),
        ):
            async with StdioClientAdapter() as adapter:
                result = await adapter.read()

        assert result.message == msg.message
        assert "bad frame" in caplog.text


class TestStdioClientAdapterWrite:
    """Writing messages to the client via StdioClientAdapter."""

    async def test_write_sends_to_stream(self) -> None:
        """Adapter.write() sends the message through to the SDK stream."""
        msg = _make_response_message()
        write_recv_ref: list[Any] = []

        @asynccontextmanager
        async def fake_stdio_server(*args: Any, **kwargs: Any):
            read_send, read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](
                max_buffer_size=16
            )
            write_send, write_recv = anyio.create_memory_object_stream[SessionMessage](
                max_buffer_size=16
            )
            write_recv_ref.append(write_recv)
            yield read_recv, write_send
            read_send.close()
            read_recv.close()
            write_send.close()
            write_recv.close()

        with patch("counteragent.proxy.adapters.stdio.stdio_server", fake_stdio_server):
            async with StdioClientAdapter() as adapter:
                await adapter.write(msg)
                await asyncio.sleep(0.05)
                result = write_recv_ref[0].receive_nowait()
                assert result.message == msg.message


class TestStdioClientAdapterClose:
    """Lifecycle and close behavior for StdioClientAdapter."""

    async def test_close_is_idempotent(self) -> None:
        """Calling close() multiple times does not raise."""

        @asynccontextmanager
        async def fake_stdio_server(*args: Any, **kwargs: Any):
            async with _mock_stdio_streams() as (r, w):
                yield r, w

        with patch("counteragent.proxy.adapters.stdio.stdio_server", fake_stdio_server):
            async with StdioClientAdapter() as adapter:
                await adapter.close()
                await adapter.close()  # should not raise

    async def test_read_on_closed_raises(self) -> None:
        """read() on a closed adapter raises RuntimeError."""

        @asynccontextmanager
        async def fake_stdio_server(*args: Any, **kwargs: Any):
            async with _mock_stdio_streams() as (r, w):
                yield r, w

        with patch("counteragent.proxy.adapters.stdio.stdio_server", fake_stdio_server):
            async with StdioClientAdapter() as adapter:
                await adapter.close()
                try:
                    await asyncio.wait_for(adapter.read(), timeout=0.5)
                    raise AssertionError("Expected RuntimeError")  # noqa: TRY301
                except RuntimeError:
                    pass

    async def test_write_on_closed_raises(self) -> None:
        """write() on a closed adapter raises RuntimeError."""
        msg = _make_session_message()

        @asynccontextmanager
        async def fake_stdio_server(*args: Any, **kwargs: Any):
            async with _mock_stdio_streams() as (r, w):
                yield r, w

        with patch("counteragent.proxy.adapters.stdio.stdio_server", fake_stdio_server):
            async with StdioClientAdapter() as adapter:
                await adapter.close()
                try:
                    await adapter.write(msg)
                    raise AssertionError("Expected RuntimeError")  # noqa: TRY301
                except RuntimeError:
                    pass

    async def test_context_manager_lifecycle(self) -> None:
        """Entering and exiting the context manager works cleanly."""

        @asynccontextmanager
        async def fake_stdio_server(*args: Any, **kwargs: Any):
            async with _mock_stdio_streams() as (r, w):
                yield r, w

        with patch("counteragent.proxy.adapters.stdio.stdio_server", fake_stdio_server):
            async with StdioClientAdapter() as adapter:
                assert adapter is not None
            assert adapter._closed
