"""Transport adapter protocol for counteragent.

All transport adapters (stdio, SSE, streamable HTTP) implement this
protocol. The message pipeline interacts only with this interface —
it never sees transport-specific details or anyio streams.
"""

from typing import Protocol

from mcp.shared.message import SessionMessage


class TransportAdapter(Protocol):
    """Interface for transport adapters.

    Adapters translate between MCP SDK anyio streams and the asyncio-based
    pipeline. Each transport requires a matched pair: one client-facing
    (proxy acts as server) and one server-facing (proxy acts as client).

    The pipeline calls read() to receive the next message from one side
    and write() to send it to the other side. close() shuts down the
    transport connection.
    """

    async def read(self) -> SessionMessage:
        """Read the next message from this side of the connection.

        Returns:
            The next SessionMessage from the transport stream.

        Raises:
            Exception: If the connection is closed or broken.
        """
        ...

    async def write(self, message: SessionMessage) -> None:
        """Write a message to this side of the connection.

        Args:
            message: The SessionMessage to send over the transport.

        Raises:
            Exception: If the connection is closed or broken.
        """
        ...

    async def close(self) -> None:
        """Shut down this side of the connection.

        Releases any resources held by the adapter (subprocesses,
        network connections, streams). Safe to call multiple times.
        """
        ...
