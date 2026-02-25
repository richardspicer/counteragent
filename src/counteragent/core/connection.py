"""MCP server connector.

Manages connections to MCP servers via stdio, SSE, and Streamable HTTP
transports using the official MCP Python SDK (v1.26+).

The key abstraction is MCPConnection -- an async context manager that
handles the nested lifecycle of transport streams and client sessions.

Usage:
    async with MCPConnection.stdio("python", ["my_server.py"]) as conn:
        tools = await conn.session.list_tools()
        result = await conn.session.call_tool("my_tool", {"arg": "value"})

    async with MCPConnection.sse("http://localhost:8080/sse") as conn:
        tools = await conn.session.list_tools()
"""

from __future__ import annotations

import logging
import sys
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import Implementation, InitializeResult

logger = logging.getLogger("counteragent.client")


# Client info sent during MCP handshake -- identifies us to the server.
_CLIENT_INFO = Implementation(name="counteragent", version="0.1.0")


@dataclass
class MCPConnection:
    """An active, initialized connection to an MCP server.

    Wraps the MCP SDK's nested context managers (transport + session)
    into a single async context manager. The session is initialized
    and ready to use when the context is entered.

    Attributes:
        session: The initialized MCP ClientSession. Use this to call
            list_tools(), call_tool(), list_resources(), etc.
        init_result: The server's response to the initialize handshake,
            containing server info, capabilities, and protocol version.
        transport_type: Which transport was used ('stdio', 'sse',
            'streamable-http').
    """

    session: ClientSession = field(init=False)
    init_result: InitializeResult = field(init=False)
    transport_type: str = "stdio"
    _exit_stack: AsyncExitStack = field(default_factory=AsyncExitStack, init=False)
    _transport_args: dict[str, Any] = field(default_factory=dict, init=False)

    @classmethod
    def stdio(
        cls,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> MCPConnection:
        """Create a connection to a stdio-based MCP server.

        This is the most common transport for local MCP servers. The
        server is launched as a subprocess and communicates via stdin/stdout.

        Args:
            command: The executable to run (e.g., "python", "node").
            args: Arguments to pass to the command (e.g., ["my_server.py"]).
            env: Optional environment variables for the server process.
            cwd: Optional working directory for the server process.

        Returns:
            An MCPConnection (use as async context manager).

        Example:
            async with MCPConnection.stdio("python", ["server.py"]) as conn:
                tools = await conn.session.list_tools()
        """
        conn = cls(transport_type="stdio")
        conn._transport_args = {
            "command": command,
            "args": args or [],
            "env": env,
            "cwd": cwd,
        }
        return conn

    @classmethod
    def sse(cls, url: str, headers: dict[str, Any] | None = None) -> MCPConnection:
        """Create a connection to an SSE-based MCP server.

        Args:
            url: The SSE endpoint URL (e.g., "http://localhost:8080/sse").
            headers: Optional HTTP headers (e.g., for authentication).

        Returns:
            An MCPConnection (use as async context manager).

        Example:
            async with MCPConnection.sse("http://localhost:8080/sse") as conn:
                tools = await conn.session.list_tools()
        """
        conn = cls(transport_type="sse")
        conn._transport_args = {"url": url, "headers": headers}
        return conn

    @classmethod
    def streamable_http(cls, url: str, headers: dict[str, str] | None = None) -> MCPConnection:
        """Create a connection to a Streamable HTTP MCP server.

        Args:
            url: The HTTP endpoint URL.
            headers: Optional HTTP headers (e.g., for authentication).

        Returns:
            An MCPConnection (use as async context manager).

        Example:
            async with MCPConnection.streamable_http("http://localhost:8080/mcp") as conn:
                tools = await conn.session.list_tools()
        """
        conn = cls(transport_type="streamable-http")
        conn._transport_args = {"url": url, "headers": headers}
        return conn

    async def __aenter__(self) -> MCPConnection:
        """Connect to the server, initialize the session.

        Opens the transport, creates a ClientSession, and performs the
        MCP initialize handshake. The session is ready to use when this
        returns.

        Returns:
            This MCPConnection instance with session and init_result set.

        Raises:
            ConnectionError: If the server cannot be reached or the
                handshake fails.
        """
        try:
            read_stream, write_stream = await self._open_transport()

            self.session = await self._exit_stack.enter_async_context(
                ClientSession(
                    read_stream,
                    write_stream,
                    client_info=_CLIENT_INFO,
                )
            )

            self.init_result = await self.session.initialize()
            logger.info(
                "Connected to %s (protocol %s) via %s",
                self.init_result.serverInfo.name if self.init_result.serverInfo else "unknown",
                self.init_result.protocolVersion,
                self.transport_type,
            )
            return self

        except Exception as exc:
            # Clean up anything we opened if initialization fails
            await self._exit_stack.aclose()
            raise ConnectionError(f"Failed to connect via {self.transport_type}: {exc}") from exc

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Disconnect from the server, clean up all resources."""
        await self._exit_stack.aclose()

    async def _open_transport(self) -> tuple:
        """Open the appropriate transport and return (read_stream, write_stream).

        Uses AsyncExitStack to manage the transport context manager's
        lifecycle alongside the session.

        Returns:
            Tuple of (read_stream, write_stream) for ClientSession.

        Raises:
            ValueError: If transport_type is not recognized.
            ConnectionError: If the transport fails to open.
        """
        if self.transport_type == "stdio":
            server_params = StdioServerParameters(
                command=self._transport_args["command"],
                args=self._transport_args.get("args", []),
                env=self._transport_args.get("env"),
                cwd=self._transport_args.get("cwd"),
            )
            # stdio_client is an async context manager yielding (read, write)
            read_stream, write_stream = await self._exit_stack.enter_async_context(
                stdio_client(server_params, errlog=sys.stderr)
            )
            return read_stream, write_stream

        elif self.transport_type == "sse":
            read_stream, write_stream = await self._exit_stack.enter_async_context(
                sse_client(
                    url=self._transport_args["url"],
                    headers=self._transport_args.get("headers"),
                )
            )
            return read_stream, write_stream

        elif self.transport_type == "streamable-http":
            result = await self._exit_stack.enter_async_context(
                streamablehttp_client(
                    url=self._transport_args["url"],
                    headers=self._transport_args.get("headers"),
                )
            )
            # streamablehttp_client yields (read, write, get_session_id)
            read_stream, write_stream, _get_session_id = result
            return read_stream, write_stream

        else:
            raise ValueError(f"Unknown transport type: {self.transport_type}")
