"""Replay engine for mcp-proxy.

Re-sends captured client-to-server messages against a live MCP server
and captures the new responses. Operates outside the normal pipeline —
injects messages directly into a server adapter.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass, field

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCNotification, JSONRPCRequest

from counteragent.core.models import Direction
from counteragent.core.transport import TransportAdapter
from counteragent.proxy.correlation import extract_jsonrpc_id, is_notification
from counteragent.proxy.models import ProxyMessage

# Handshake request id — uses a string unlikely to collide with real ids
_HANDSHAKE_ID = "__handshake__"


@dataclass
class ReplayResult:
    """Result of replaying a single message.

    Args:
        original_request: The ProxyMessage that was replayed.
        sent_message: The SessionMessage actually sent to the server.
        response: The server's response (None for notifications or on timeout/error).
        error: Error description if replay failed.
        duration_ms: Round-trip time in milliseconds.
    """

    original_request: ProxyMessage
    sent_message: SessionMessage
    response: SessionMessage | None
    error: str | None
    duration_ms: float


@dataclass
class ReplaySessionResult:
    """Result of replaying a full session.

    Args:
        results: A ReplayResult for each replayed message.
        target_command: Server command used (stdio).
        target_url: Server URL used (SSE/HTTP).
    """

    results: list[ReplayResult] = field(default_factory=list)
    target_command: str | None = None
    target_url: str | None = None


async def replay_messages(
    messages: list[ProxyMessage],
    server_adapter: TransportAdapter,
    timeout: float = 10.0,
    auto_handshake: bool = True,
) -> list[ReplayResult]:
    """Replay a list of messages against a connected server adapter.

    Sends each client-to-server message in order, waits for the
    corresponding response by matching JSON-RPC id, and captures
    the result. Notifications (no id) are sent without waiting
    for a response.

    Args:
        messages: ProxyMessages to replay (client-to-server only).
        server_adapter: A connected server adapter.
        timeout: Seconds to wait for each response.
        auto_handshake: If True and first message is not initialize,
            send a synthetic handshake before replaying.

    Returns:
        A ReplayResult for each replayed message.
    """
    # Filter to client-to-server only
    c2s_messages = [m for m in messages if m.direction == Direction.CLIENT_TO_SERVER]

    # Auto-handshake: if first message is not initialize, send synthetic one
    needs_handshake = auto_handshake and (
        not c2s_messages or c2s_messages[0].method != "initialize"
    )
    if needs_handshake:
        await _send_handshake(server_adapter, timeout)

    results: list[ReplayResult] = []
    for msg in c2s_messages:
        result = await _replay_single(msg, server_adapter, timeout)
        results.append(result)

    return results


async def _send_handshake(
    adapter: TransportAdapter,
    timeout: float,
) -> None:
    """Send synthetic initialize + notifications/initialized.

    Args:
        adapter: The server adapter to handshake with.
        timeout: Seconds to wait for initialize response.
    """
    # Send initialize request
    init_request = SessionMessage(
        message=JSONRPCMessage(
            JSONRPCRequest(
                jsonrpc="2.0",
                id=_HANDSHAKE_ID,
                method="initialize",
                params={
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-proxy-replay", "version": "0.1.0"},
                },
            )
        )
    )
    await adapter.write(init_request)

    # Wait for initialize response (best-effort)
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(_read_response(adapter, _HANDSHAKE_ID), timeout=timeout)

    # Send notifications/initialized (no response expected)
    init_notification = SessionMessage(
        message=JSONRPCMessage(
            JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized")
        )
    )
    await adapter.write(init_notification)


async def _replay_single(
    msg: ProxyMessage,
    adapter: TransportAdapter,
    timeout: float,
) -> ReplayResult:
    """Replay a single message and capture the result.

    Args:
        msg: The ProxyMessage to replay.
        adapter: The server adapter.
        timeout: Seconds to wait for response.

    Returns:
        A ReplayResult with response or error.
    """
    session_message = SessionMessage(message=msg.raw)

    start = time.perf_counter()
    try:
        await adapter.write(session_message)
    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return ReplayResult(
            original_request=msg,
            sent_message=session_message,
            response=None,
            error=f"Write failed: {exc}",
            duration_ms=elapsed,
        )

    # Notifications: fire-and-forget
    if is_notification(msg.raw):
        elapsed = (time.perf_counter() - start) * 1000
        return ReplayResult(
            original_request=msg,
            sent_message=session_message,
            response=None,
            error=None,
            duration_ms=elapsed,
        )

    # Request: wait for matching response
    try:
        response = await asyncio.wait_for(_read_response(adapter, msg.jsonrpc_id), timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000
        return ReplayResult(
            original_request=msg,
            sent_message=session_message,
            response=response,
            error=None,
            duration_ms=elapsed,
        )
    except TimeoutError:
        elapsed = (time.perf_counter() - start) * 1000
        return ReplayResult(
            original_request=msg,
            sent_message=session_message,
            response=None,
            error=f"Timeout after {timeout}s",
            duration_ms=elapsed,
        )
    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return ReplayResult(
            original_request=msg,
            sent_message=session_message,
            response=None,
            error=f"Read failed: {exc}",
            duration_ms=elapsed,
        )


async def _read_response(
    adapter: TransportAdapter,
    expected_id: str | int | None,
) -> SessionMessage:
    """Read from adapter until we get a response matching expected_id.

    Args:
        adapter: The server adapter to read from.
        expected_id: The JSON-RPC id to match.

    Returns:
        The matching SessionMessage.
    """
    while True:
        response = await adapter.read()
        resp_id = extract_jsonrpc_id(response.message)
        if resp_id == expected_id:
            return response
        # Non-matching messages (e.g. server notifications) are skipped
