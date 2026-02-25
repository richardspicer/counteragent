"""Tests for counteragent.proxy.models."""

import asyncio
import uuid
from datetime import UTC, datetime

from mcp.types import JSONRPCMessage, JSONRPCRequest

from counteragent.core.models import Direction, Transport
from counteragent.proxy.models import (
    HeldMessage,
    InterceptAction,
    InterceptMode,
    InterceptState,
    ProxyMessage,
    ProxySession,
)


class TestDirection:
    def test_values(self) -> None:
        assert Direction.CLIENT_TO_SERVER == "client_to_server"
        assert Direction.SERVER_TO_CLIENT == "server_to_client"

    def test_string_serialization(self) -> None:
        assert str(Direction.CLIENT_TO_SERVER) == "client_to_server"
        assert Direction.CLIENT_TO_SERVER.value == "client_to_server"

    def test_members_count(self) -> None:
        assert len(Direction) == 2


class TestTransport:
    def test_values(self) -> None:
        assert Transport.STDIO == "stdio"
        assert Transport.SSE == "sse"
        assert Transport.STREAMABLE_HTTP == "streamable_http"

    def test_members_count(self) -> None:
        assert len(Transport) == 3


class TestInterceptMode:
    def test_values(self) -> None:
        assert InterceptMode.PASSTHROUGH == "passthrough"
        assert InterceptMode.INTERCEPT == "intercept"

    def test_members_count(self) -> None:
        assert len(InterceptMode) == 2


class TestInterceptAction:
    def test_values(self) -> None:
        assert InterceptAction.FORWARD == "forward"
        assert InterceptAction.MODIFY == "modify"
        assert InterceptAction.DROP == "drop"

    def test_members_count(self) -> None:
        assert len(InterceptAction) == 3


def _make_request(method: str = "tools/list", msg_id: int = 1) -> JSONRPCMessage:
    """Helper to build a JSONRPCMessage wrapping a request."""
    return JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=msg_id, method=method))


class TestProxyMessage:
    def test_creation(self) -> None:
        raw = _make_request()
        msg = ProxyMessage(
            id=str(uuid.uuid4()),
            sequence=1,
            timestamp=datetime.now(tz=UTC),
            direction=Direction.CLIENT_TO_SERVER,
            transport=Transport.STDIO,
            raw=raw,
            jsonrpc_id=1,
            method="tools/list",
            correlated_id=None,
            modified=False,
            original_raw=None,
        )
        assert msg.sequence == 1
        assert msg.direction == Direction.CLIENT_TO_SERVER
        assert msg.transport == Transport.STDIO
        assert msg.jsonrpc_id == 1
        assert msg.method == "tools/list"
        assert msg.modified is False
        assert msg.original_raw is None

    def test_modified_preserves_original(self) -> None:
        original = _make_request("tools/call", msg_id=2)
        modified = _make_request("tools/call", msg_id=2)
        msg = ProxyMessage(
            id=str(uuid.uuid4()),
            sequence=2,
            timestamp=datetime.now(tz=UTC),
            direction=Direction.CLIENT_TO_SERVER,
            transport=Transport.STDIO,
            raw=modified,
            jsonrpc_id=2,
            method="tools/call",
            correlated_id=None,
            modified=True,
            original_raw=original,
        )
        assert msg.modified is True
        assert msg.original_raw is not None
        assert msg.original_raw is original


class TestHeldMessage:
    def test_creation(self) -> None:
        raw = _make_request()
        proxy_msg = ProxyMessage(
            id="test-id",
            sequence=1,
            timestamp=datetime.now(tz=UTC),
            direction=Direction.CLIENT_TO_SERVER,
            transport=Transport.STDIO,
            raw=raw,
            jsonrpc_id=1,
            method="tools/list",
            correlated_id=None,
            modified=False,
            original_raw=None,
        )
        held = HeldMessage(
            proxy_message=proxy_msg,
            release=asyncio.Event(),
            action=None,
            modified_raw=None,
        )
        assert held.proxy_message is proxy_msg
        assert held.action is None
        assert held.modified_raw is None
        assert not held.release.is_set()

    async def test_event_signaling(self) -> None:
        raw = _make_request()
        proxy_msg = ProxyMessage(
            id="test-id",
            sequence=1,
            timestamp=datetime.now(tz=UTC),
            direction=Direction.CLIENT_TO_SERVER,
            transport=Transport.STDIO,
            raw=raw,
            jsonrpc_id=1,
            method="tools/list",
            correlated_id=None,
            modified=False,
            original_raw=None,
        )
        held = HeldMessage(
            proxy_message=proxy_msg,
            release=asyncio.Event(),
            action=None,
            modified_raw=None,
        )
        assert not held.release.is_set()
        held.action = InterceptAction.FORWARD
        held.release.set()
        assert held.release.is_set()
        assert held.action == InterceptAction.FORWARD


class TestInterceptState:
    def test_default_passthrough(self) -> None:
        state = InterceptState(mode=InterceptMode.PASSTHROUGH)
        assert state.mode == InterceptMode.PASSTHROUGH
        assert state.held_messages == []

    def test_with_held_messages(self) -> None:
        raw = _make_request()
        proxy_msg = ProxyMessage(
            id="test-id",
            sequence=1,
            timestamp=datetime.now(tz=UTC),
            direction=Direction.CLIENT_TO_SERVER,
            transport=Transport.STDIO,
            raw=raw,
            jsonrpc_id=1,
            method="tools/list",
            correlated_id=None,
            modified=False,
            original_raw=None,
        )
        held = HeldMessage(
            proxy_message=proxy_msg,
            release=asyncio.Event(),
            action=None,
            modified_raw=None,
        )
        state = InterceptState(
            mode=InterceptMode.INTERCEPT,
            held_messages=[held],
        )
        assert state.mode == InterceptMode.INTERCEPT
        assert len(state.held_messages) == 1


class TestProxySession:
    def test_creation(self) -> None:
        session = ProxySession(
            id="session-123",
            started_at=datetime.now(tz=UTC),
            ended_at=None,
            transport=Transport.STDIO,
            server_command="python server.py",
            server_url=None,
            messages=[],
            metadata={},
        )
        assert session.id == "session-123"
        assert session.ended_at is None
        assert session.server_command == "python server.py"
        assert session.messages == []

    def test_serialization_roundtrip(self) -> None:
        now = datetime.now(tz=UTC)
        session = ProxySession(
            id="session-456",
            started_at=now,
            ended_at=now,
            transport=Transport.SSE,
            server_command=None,
            server_url="http://localhost:8080/sse",
            messages=[],
            metadata={"target": "test-server", "notes": "integration test"},
        )
        json_str = session.model_dump_json()
        restored = ProxySession.model_validate_json(json_str)
        assert restored.id == session.id
        assert restored.started_at == session.started_at
        assert restored.ended_at == session.ended_at
        assert restored.transport == Transport.SSE
        assert restored.server_url == "http://localhost:8080/sse"
        assert restored.metadata == {"target": "test-server", "notes": "integration test"}
