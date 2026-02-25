"""Core message pipeline for mcp-proxy.

Routes traffic between client and server transport adapters. Two
concurrent forward loops relay messages bidirectionally, wrapping
each in a ProxyMessage envelope, capturing to the session store,
and checking the intercept engine.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from mcp.shared.message import SessionMessage

from counteragent.core.models import Direction, Transport

logger = logging.getLogger(__name__)
from counteragent.core.transport import TransportAdapter
from counteragent.proxy.correlation import (
    extract_jsonrpc_id,
    extract_method,
    is_request,
    is_response,
)
from counteragent.proxy.intercept import InterceptEngine
from counteragent.proxy.models import (
    HeldMessage,
    InterceptAction,
    ProxyMessage,
)
from counteragent.proxy.session_store import SessionStore


@dataclass
class PipelineSession:
    """Dependencies and callbacks for a pipeline run.

    Args:
        session_store: Captures all proxied messages.
        intercept_engine: Controls hold/release behavior.
        transport: The transport type for this session.
        on_message: Called when a message is received (before intercept).
        on_held: Called when a message is held by the intercept engine.
        on_forwarded: Called after a message is forwarded to its destination.
    """

    session_store: SessionStore
    intercept_engine: InterceptEngine
    transport: Transport
    on_message: Callable[[ProxyMessage], None] | None = None
    on_held: Callable[[HeldMessage], None] | None = None
    on_forwarded: Callable[[ProxyMessage], None] | None = None


async def run_pipeline(
    client_adapter: TransportAdapter,
    server_adapter: TransportAdapter,
    session: PipelineSession,
) -> None:
    """Run the bidirectional message pipeline.

    Launches two concurrent forward loops: client-to-server and
    server-to-client. Exits when either adapter disconnects.

    Args:
        client_adapter: The client-facing transport adapter.
        server_adapter: The server-facing transport adapter.
        session: Pipeline dependencies and callbacks.
    """
    seq = itertools.count()
    correlation_map: dict[str | int, str] = {}

    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(
                _forward_loop(
                    source=client_adapter,
                    destination=server_adapter,
                    direction=Direction.CLIENT_TO_SERVER,
                    session=session,
                    seq=seq,
                    correlation_map=correlation_map,
                )
            )
            tg.create_task(
                _forward_loop(
                    source=server_adapter,
                    destination=client_adapter,
                    direction=Direction.SERVER_TO_CLIENT,
                    session=session,
                    seq=seq,
                    correlation_map=correlation_map,
                )
            )
    except* Exception as eg:  # noqa: S110
        # One or both forward loops raised (adapter closed).
        # This is normal shutdown — both loops stop when either side disconnects.
        for exc in eg.exceptions:
            logger.debug("Pipeline forward loop exited: %s", exc)


async def _forward_loop(
    source: TransportAdapter,
    destination: TransportAdapter,
    direction: Direction,
    session: PipelineSession,
    seq: itertools.count[int],
    correlation_map: dict[str | int, str],
) -> None:
    """Forward messages from source to destination.

    Args:
        source: Adapter to read from.
        destination: Adapter to write to.
        direction: CLIENT_TO_SERVER or SERVER_TO_CLIENT.
        session: Pipeline dependencies and callbacks.
        seq: Shared monotonic sequence counter.
        correlation_map: Shared JSON-RPC id to ProxyMessage.id mapping.
    """
    while True:
        session_message = await source.read()
        proxy_msg = _wrap_message(session_message, direction, session.transport, seq)

        # Correlate responses to requests
        if is_request(session_message.message) and proxy_msg.jsonrpc_id is not None:
            correlation_map[proxy_msg.jsonrpc_id] = proxy_msg.id
        elif is_response(session_message.message) and proxy_msg.jsonrpc_id is not None:
            correlated = correlation_map.pop(proxy_msg.jsonrpc_id, None)
            if correlated is not None:
                proxy_msg.correlated_id = correlated

        # Capture
        session.session_store.append(proxy_msg)

        # Notify
        if session.on_message is not None:
            session.on_message(proxy_msg)

        # Intercept check
        if session.intercept_engine.should_hold(proxy_msg):
            held = session.intercept_engine.hold(proxy_msg)
            if session.on_held is not None:
                session.on_held(held)
            await held.release.wait()

            if held.action == InterceptAction.DROP:
                continue

            if held.action == InterceptAction.MODIFY and held.modified_raw is not None:
                proxy_msg.original_raw = proxy_msg.raw
                proxy_msg.raw = held.modified_raw
                proxy_msg.modified = True
                session_message = SessionMessage(message=held.modified_raw)

        # Forward
        await destination.write(session_message)

        # Notify forwarded
        if session.on_forwarded is not None:
            session.on_forwarded(proxy_msg)


def _wrap_message(
    session_message: SessionMessage,
    direction: Direction,
    transport: Transport,
    seq: itertools.count[int],
) -> ProxyMessage:
    """Wrap a SessionMessage in a ProxyMessage envelope.

    Args:
        session_message: The raw SDK message.
        direction: CLIENT_TO_SERVER or SERVER_TO_CLIENT.
        transport: The transport type.
        seq: Shared monotonic sequence counter.

    Returns:
        A ProxyMessage with UUID, sequence, timestamp, and extracted fields.
    """
    raw = session_message.message
    return ProxyMessage(
        id=str(uuid.uuid4()),
        sequence=next(seq),
        timestamp=datetime.now(tz=UTC),
        direction=direction,
        transport=transport,
        raw=raw,
        jsonrpc_id=extract_jsonrpc_id(raw),
        method=extract_method(raw),
        correlated_id=None,
        modified=False,
        original_raw=None,
    )
