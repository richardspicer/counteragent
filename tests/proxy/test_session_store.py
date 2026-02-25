"""Tests for counteragent.proxy.session_store — SessionStore."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from mcp.types import (
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
)

from counteragent.core.models import Direction, Transport
from counteragent.proxy.models import ProxyMessage
from counteragent.proxy.session_store import SessionStore


def _make_proxy_message(
    method: str = "tools/list",
    msg_id: int = 1,
    direction: Direction = Direction.CLIENT_TO_SERVER,
    sequence: int = 1,
    proxy_id: str | None = None,
) -> ProxyMessage:
    """Build a ProxyMessage wrapping a JSON-RPC request."""
    raw = JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=msg_id, method=method))
    return ProxyMessage(
        id=proxy_id or str(uuid.uuid4()),
        sequence=sequence,
        timestamp=datetime.now(tz=UTC),
        direction=direction,
        transport=Transport.STDIO,
        raw=raw,
        jsonrpc_id=msg_id,
        method=method,
        correlated_id=None,
        modified=False,
        original_raw=None,
    )


def _make_notification_message(
    method: str = "notifications/initialized",
    direction: Direction = Direction.CLIENT_TO_SERVER,
    sequence: int = 1,
) -> ProxyMessage:
    """Build a ProxyMessage wrapping a JSON-RPC notification."""
    raw = JSONRPCMessage(JSONRPCNotification(jsonrpc="2.0", method=method))
    return ProxyMessage(
        id=str(uuid.uuid4()),
        sequence=sequence,
        timestamp=datetime.now(tz=UTC),
        direction=direction,
        transport=Transport.STDIO,
        raw=raw,
        jsonrpc_id=None,
        method=method,
        correlated_id=None,
        modified=False,
        original_raw=None,
    )


def _make_response_message(
    msg_id: int = 1,
    direction: Direction = Direction.SERVER_TO_CLIENT,
    sequence: int = 2,
    correlated_id: str | None = None,
) -> ProxyMessage:
    """Build a ProxyMessage wrapping a JSON-RPC response."""
    raw = JSONRPCMessage(JSONRPCResponse(jsonrpc="2.0", id=msg_id, result={}))
    return ProxyMessage(
        id=str(uuid.uuid4()),
        sequence=sequence,
        timestamp=datetime.now(tz=UTC),
        direction=direction,
        transport=Transport.STDIO,
        raw=raw,
        jsonrpc_id=msg_id,
        method=None,
        correlated_id=correlated_id,
        modified=False,
        original_raw=None,
    )


class TestAppendAndRetrieve:
    """SessionStore.append() and get_messages()."""

    def test_append_and_get_messages(self) -> None:
        store = SessionStore(session_id="s1", transport=Transport.STDIO)
        msg1 = _make_proxy_message(sequence=1)
        msg2 = _make_proxy_message(sequence=2, msg_id=2)
        store.append(msg1)
        store.append(msg2)
        messages = store.get_messages()
        assert len(messages) == 2
        assert messages[0] is msg1
        assert messages[1] is msg2

    def test_get_messages_returns_copy(self) -> None:
        store = SessionStore(session_id="s1", transport=Transport.STDIO)
        msg = _make_proxy_message()
        store.append(msg)
        messages = store.get_messages()
        messages.clear()
        assert len(store.get_messages()) == 1


class TestGetById:
    """SessionStore.get_by_id() lookup."""

    def test_get_by_id_found(self) -> None:
        store = SessionStore(session_id="s1", transport=Transport.STDIO)
        msg = _make_proxy_message(proxy_id="known-id")
        store.append(msg)
        result = store.get_by_id("known-id")
        assert result is msg

    def test_get_by_id_not_found(self) -> None:
        store = SessionStore(session_id="s1", transport=Transport.STDIO)
        result = store.get_by_id("nonexistent")
        assert result is None


class TestSerialization:
    """SessionStore.to_proxy_session() and round-trip."""

    def test_to_proxy_session_basic(self) -> None:
        store = SessionStore(
            session_id="s1",
            transport=Transport.STDIO,
            server_command="python server.py",
        )
        msg = _make_proxy_message(proxy_id="msg-1", method="initialize", msg_id=1)
        store.append(msg)
        session = store.to_proxy_session()
        assert session.id == "s1"
        assert session.transport == Transport.STDIO
        assert session.server_command == "python server.py"
        assert len(session.messages) == 1
        m = session.messages[0]
        assert m["proxy_id"] == "msg-1"
        assert m["direction"] == "client_to_server"
        assert m["method"] == "initialize"

    def test_to_proxy_session_empty(self) -> None:
        store = SessionStore(session_id="s1", transport=Transport.STDIO)
        session = store.to_proxy_session()
        assert session.messages == []

    def test_roundtrip_json(self) -> None:
        store = SessionStore(
            session_id="s1",
            transport=Transport.STDIO,
            server_command="python server.py",
            metadata={"note": "test"},
        )
        msg = _make_proxy_message(proxy_id="msg-1", method="initialize", msg_id=1)
        store.append(msg)
        session = store.to_proxy_session()
        json_str = session.model_dump_json(indent=2)
        parsed = json.loads(json_str)
        assert parsed["id"] == "s1"
        assert len(parsed["messages"]) == 1
        assert parsed["messages"][0]["proxy_id"] == "msg-1"
        assert parsed["metadata"] == {"note": "test"}


class TestSaveLoad:
    """SessionStore.save() and SessionStore.load() to filesystem."""

    def test_save_and_load(self, tmp_path: Path) -> None:
        store = SessionStore(
            session_id="s1",
            transport=Transport.STDIO,
            server_command="python server.py",
            metadata={"note": "save-load test"},
        )
        req = _make_proxy_message(proxy_id="req-1", method="tools/list", msg_id=1)
        resp = _make_response_message(msg_id=1, correlated_id="req-1")
        notif = _make_notification_message(method="notifications/initialized")
        store.append(req)
        store.append(resp)
        store.append(notif)

        file_path = tmp_path / "session.json"
        store.save(file_path)
        assert file_path.exists()

        loaded = SessionStore.load(file_path)
        assert loaded.session_id == "s1"
        messages = loaded.get_messages()
        assert len(messages) == 3
        assert messages[0].id == "req-1"
        assert messages[0].method == "tools/list"
        assert messages[0].jsonrpc_id == 1
        assert messages[1].correlated_id == "req-1"
        assert messages[2].jsonrpc_id is None
        assert messages[2].method == "notifications/initialized"

    def test_save_creates_parent_dirs(self, tmp_path: Path) -> None:
        store = SessionStore(session_id="s1", transport=Transport.STDIO)
        file_path = tmp_path / "subdir" / "session.json"
        store.save(file_path)
        assert file_path.exists()
