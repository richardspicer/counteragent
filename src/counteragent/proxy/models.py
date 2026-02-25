"""Core data models for mcp-proxy.

Defines the envelope types that wrap every intercepted JSON-RPC message,
session containers for capture/export, and intercept engine state.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from mcp.types import JSONRPCMessage
from pydantic import BaseModel

from counteragent.core.models import Direction, Transport  # noqa: F401


class InterceptMode(StrEnum):
    """Operating mode for the intercept engine.

    Attributes:
        PASSTHROUGH: Messages flow through without being held for inspection.
        INTERCEPT: Messages are held for user inspection before forwarding.
    """

    PASSTHROUGH = "passthrough"
    INTERCEPT = "intercept"


class InterceptAction(StrEnum):
    """User action on a held message.

    Attributes:
        FORWARD: Forward the message to its destination unchanged.
        MODIFY: Forward the message with user modifications applied.
        DROP: Discard the message without forwarding.
    """

    FORWARD = "forward"
    MODIFY = "modify"
    DROP = "drop"


@dataclass
class ProxyMessage:
    """A single intercepted MCP JSON-RPC message with proxy metadata.

    Args:
        id: Unique proxy-assigned ID (UUID string).
        sequence: Monotonic sequence number within the session.
        timestamp: When the proxy received this message.
        direction: CLIENT_TO_SERVER or SERVER_TO_CLIENT.
        transport: The transport type (STDIO, SSE, STREAMABLE_HTTP).
        raw: The actual JSON-RPC message (MCP SDK type).
        jsonrpc_id: JSON-RPC id field (None for notifications).
        method: JSON-RPC method (None for responses).
        correlated_id: Proxy ID of the request this response correlates to.
        modified: True if the user modified this message before forwarding.
        original_raw: Pre-modification snapshot (populated when modified=True).
    """

    id: str
    sequence: int
    timestamp: datetime
    direction: Direction
    transport: Transport
    raw: JSONRPCMessage
    jsonrpc_id: str | int | None
    method: str | None
    correlated_id: str | None
    modified: bool
    original_raw: JSONRPCMessage | None


@dataclass
class HeldMessage:
    """A message held by the intercept engine, awaiting user action.

    Args:
        proxy_message: The intercepted message.
        release: Event set when the user acts (forward/modify/drop).
        action: The user's chosen action (populated before setting release).
        modified_raw: If action is MODIFY, the edited JSON-RPC message.
    """

    proxy_message: ProxyMessage
    release: asyncio.Event
    action: InterceptAction | None
    modified_raw: JSONRPCMessage | None


@dataclass
class InterceptState:
    """Current state of the intercept engine.

    Args:
        mode: PASSTHROUGH (forward all) or INTERCEPT (hold all).
        held_messages: Messages currently waiting for user action.
    """

    mode: InterceptMode
    held_messages: list[HeldMessage] = field(default_factory=list)


class ProxySession(BaseModel):
    """A captured proxy session — the unit of evidence.

    Serialized to JSON for session export and replay. Uses Pydantic
    for reliable serialization/deserialization.

    Args:
        id: Session UUID string.
        started_at: When the session started.
        ended_at: When the session ended (None if still active).
        transport: The transport type used for this session.
        server_command: For stdio: the command that launched the server.
        server_url: For SSE/HTTP: the server endpoint URL.
        messages: Ordered sequence of serialized proxy messages.
        metadata: Arbitrary session metadata (target name, notes, etc.).
    """

    id: str
    started_at: datetime
    ended_at: datetime | None
    transport: Transport
    server_command: str | None
    server_url: str | None
    messages: list[dict[str, Any]]
    metadata: dict[str, Any]
