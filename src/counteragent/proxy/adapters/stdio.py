"""stdio transport adapters for mcp-proxy.

Provides server-facing and client-facing adapters that bridge MCP SDK
anyio streams to asyncio queues. The pipeline never sees anyio — only
these adapters touch SDK transport internals.

StdioServerAdapter wraps ``stdio_client()`` — spawns the target MCP server.
StdioClientAdapter wraps ``stdio_server()`` — the proxy IS the subprocess.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from types import TracebackType

from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage

logger = logging.getLogger(__name__)

# Sentinel pushed into the read queue when the SDK stream ends
_STREAM_CLOSED = object()


class StdioServerAdapter:
    """Server-facing adapter — proxy connects to a real MCP server via stdio.

    Wraps the MCP SDK ``stdio_client()`` context manager. Spawns the target
    server as a subprocess and bridges its anyio streams to asyncio queues
    for consumption by the pipeline.

    Args:
        command: Executable to run as the MCP server.
        args: Command-line arguments for the server.
        env: Environment variables for the subprocess (None uses SDK defaults).
        cwd: Working directory for the subprocess.

    Example:
        async with StdioServerAdapter(command="python", args=["server.py"]) as adapter:
            msg = await adapter.read()
            await adapter.write(response)
    """

    def __init__(
        self,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> None:
        self._server_params = StdioServerParameters(
            command=command,
            args=args or [],
            env=env,
            cwd=cwd,
        )
        self._read_queue: asyncio.Queue[SessionMessage | object] = asyncio.Queue()
        self._write_queue: asyncio.Queue[SessionMessage] = asyncio.Queue()
        self._closed = False
        self._reader_task: asyncio.Task[None] | None = None
        self._writer_task: asyncio.Task[None] | None = None

    async def __aenter__(self) -> StdioServerAdapter:
        """Enter the adapter context — start SDK transport and bridge tasks."""
        self._sdk_cm = stdio_client(self._server_params)
        read_stream, write_stream = await self._sdk_cm.__aenter__()
        self._reader_task = asyncio.create_task(
            self._reader_loop(read_stream),
            name="stdio-server-reader",
        )
        self._writer_task = asyncio.create_task(
            self._writer_loop(write_stream),
            name="stdio-server-writer",
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the adapter context — clean up tasks and SDK transport."""
        await self.close()
        if hasattr(self, "_sdk_cm"):
            try:
                await self._sdk_cm.__aexit__(exc_type, exc_val, exc_tb)
            except Exception:
                logger.debug("SDK context exit error (suppressed)", exc_info=True)

    async def read(self) -> SessionMessage:
        """Read the next message from the server.

        Returns:
            The next SessionMessage from the server.

        Raises:
            RuntimeError: If the adapter has been closed.
        """
        if self._closed:
            raise RuntimeError("StdioServerAdapter is closed")
        item = await self._read_queue.get()
        if item is _STREAM_CLOSED:
            raise RuntimeError("StdioServerAdapter is closed")
        return item  # type: ignore[return-value]

    async def write(self, message: SessionMessage) -> None:
        """Write a message to the server.

        Args:
            message: The SessionMessage to send to the server.

        Raises:
            RuntimeError: If the adapter has been closed.
        """
        if self._closed:
            raise RuntimeError("StdioServerAdapter is closed")
        await self._write_queue.put(message)

    async def close(self) -> None:
        """Shut down the adapter. Safe to call multiple times."""
        if self._closed:
            return
        self._closed = True
        # Signal the read queue so any waiting read() unblocks
        await self._read_queue.put(_STREAM_CLOSED)
        # Cancel bridge tasks
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader_task
        if self._writer_task and not self._writer_task.done():
            self._writer_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._writer_task

    async def _reader_loop(
        self,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
    ) -> None:
        """Bridge: pull from SDK anyio read stream, push to asyncio queue.

        Args:
            read_stream: The anyio receive stream from the SDK.
        """
        try:
            async for item in read_stream:
                if self._closed:
                    break
                if isinstance(item, Exception):
                    logger.warning("Exception from server stream: %s", item)
                    continue
                await self._read_queue.put(item)
        except Exception:
            if not self._closed:
                logger.debug("Reader loop ended", exc_info=True)
        finally:
            if not self._closed:
                await self._read_queue.put(_STREAM_CLOSED)

    async def _writer_loop(
        self,
        write_stream: MemoryObjectSendStream[SessionMessage],
    ) -> None:
        """Bridge: pull from asyncio queue, send to SDK anyio write stream.

        Args:
            write_stream: The anyio send stream from the SDK.
        """
        try:
            while not self._closed:
                message = await self._write_queue.get()
                if self._closed:
                    break
                await write_stream.send(message)
        except Exception:
            if not self._closed:
                logger.debug("Writer loop ended", exc_info=True)


class StdioClientAdapter:
    """Client-facing adapter — real MCP client connects to proxy via stdio.

    Wraps the MCP SDK ``stdio_server()`` context manager. The proxy reads
    from its own stdin and writes to stdout, acting as the MCP server from
    the client's perspective.

    Example:
        async with StdioClientAdapter() as adapter:
            msg = await adapter.read()   # message from client
            await adapter.write(response) # response to client
    """

    def __init__(self) -> None:
        self._read_queue: asyncio.Queue[SessionMessage | object] = asyncio.Queue()
        self._write_queue: asyncio.Queue[SessionMessage] = asyncio.Queue()
        self._closed = False
        self._reader_task: asyncio.Task[None] | None = None
        self._writer_task: asyncio.Task[None] | None = None

    async def __aenter__(self) -> StdioClientAdapter:
        """Enter the adapter context — start SDK transport and bridge tasks."""
        self._sdk_cm = stdio_server()
        read_stream, write_stream = await self._sdk_cm.__aenter__()
        self._reader_task = asyncio.create_task(
            self._reader_loop(read_stream),
            name="stdio-client-reader",
        )
        self._writer_task = asyncio.create_task(
            self._writer_loop(write_stream),
            name="stdio-client-writer",
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the adapter context — clean up tasks and SDK transport."""
        await self.close()
        if hasattr(self, "_sdk_cm"):
            try:
                await self._sdk_cm.__aexit__(exc_type, exc_val, exc_tb)
            except Exception:
                logger.debug("SDK context exit error (suppressed)", exc_info=True)

    async def read(self) -> SessionMessage:
        """Read the next message from the client.

        Returns:
            The next SessionMessage from the client.

        Raises:
            RuntimeError: If the adapter has been closed.
        """
        if self._closed:
            raise RuntimeError("StdioClientAdapter is closed")
        item = await self._read_queue.get()
        if item is _STREAM_CLOSED:
            raise RuntimeError("StdioClientAdapter is closed")
        return item  # type: ignore[return-value]

    async def write(self, message: SessionMessage) -> None:
        """Write a message to the client.

        Args:
            message: The SessionMessage to send to the client.

        Raises:
            RuntimeError: If the adapter has been closed.
        """
        if self._closed:
            raise RuntimeError("StdioClientAdapter is closed")
        await self._write_queue.put(message)

    async def close(self) -> None:
        """Shut down the adapter. Safe to call multiple times."""
        if self._closed:
            return
        self._closed = True
        await self._read_queue.put(_STREAM_CLOSED)
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader_task
        if self._writer_task and not self._writer_task.done():
            self._writer_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._writer_task

    async def _reader_loop(
        self,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
    ) -> None:
        """Bridge: pull from SDK anyio read stream, push to asyncio queue.

        Args:
            read_stream: The anyio receive stream from the SDK.
        """
        try:
            async for item in read_stream:
                if self._closed:
                    break
                if isinstance(item, Exception):
                    logger.warning("Exception from client stream: %s", item)
                    continue
                await self._read_queue.put(item)
        except Exception:
            if not self._closed:
                logger.debug("Reader loop ended", exc_info=True)
        finally:
            if not self._closed:
                await self._read_queue.put(_STREAM_CLOSED)

    async def _writer_loop(
        self,
        write_stream: MemoryObjectSendStream[SessionMessage],
    ) -> None:
        """Bridge: pull from asyncio queue, send to SDK anyio write stream.

        Args:
            write_stream: The anyio send stream from the SDK.
        """
        try:
            while not self._closed:
                message = await self._write_queue.get()
                if self._closed:
                    break
                await write_stream.send(message)
        except Exception:
            if not self._closed:
                logger.debug("Writer loop ended", exc_info=True)
