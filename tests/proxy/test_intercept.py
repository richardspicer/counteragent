"""Tests for counteragent.proxy.intercept — InterceptEngine."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from mcp.types import JSONRPCMessage, JSONRPCRequest

from counteragent.core.models import Direction, Transport
from counteragent.proxy.intercept import InterceptEngine
from counteragent.proxy.models import (
    HeldMessage,
    InterceptAction,
    InterceptMode,
    ProxyMessage,
)


def _make_proxy_message(
    method: str = "tools/list",
    msg_id: int = 1,
    direction: Direction = Direction.CLIENT_TO_SERVER,
    sequence: int = 1,
) -> ProxyMessage:
    """Build a ProxyMessage wrapping a JSON-RPC request."""
    raw = JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=msg_id, method=method))
    return ProxyMessage(
        id=str(uuid.uuid4()),
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


class TestShouldHold:
    """InterceptEngine.should_hold() based on mode."""

    def test_passthrough_returns_false(self) -> None:
        engine = InterceptEngine(mode=InterceptMode.PASSTHROUGH)
        msg = _make_proxy_message()
        assert engine.should_hold(msg) is False

    def test_intercept_returns_true(self) -> None:
        engine = InterceptEngine(mode=InterceptMode.INTERCEPT)
        msg = _make_proxy_message()
        assert engine.should_hold(msg) is True


class TestHold:
    """InterceptEngine.hold() creates HeldMessage."""

    def test_hold_creates_held_message(self) -> None:
        engine = InterceptEngine(mode=InterceptMode.INTERCEPT)
        msg = _make_proxy_message()
        held = engine.hold(msg)
        assert isinstance(held, HeldMessage)
        assert held.proxy_message is msg
        assert held.action is None
        assert held.modified_raw is None
        assert not held.release.is_set()

    def test_hold_adds_to_held_list(self) -> None:
        engine = InterceptEngine(mode=InterceptMode.INTERCEPT)
        msg1 = _make_proxy_message(sequence=1)
        msg2 = _make_proxy_message(sequence=2)
        engine.hold(msg1)
        engine.hold(msg2)
        assert len(engine.get_held()) == 2


class TestRelease:
    """InterceptEngine.release() sets action and fires event."""

    def test_release_forward(self) -> None:
        engine = InterceptEngine(mode=InterceptMode.INTERCEPT)
        msg = _make_proxy_message()
        held = engine.hold(msg)
        engine.release(held, InterceptAction.FORWARD)
        assert held.action == InterceptAction.FORWARD
        assert held.release.is_set()
        assert held.modified_raw is None
        assert len(engine.get_held()) == 0

    def test_release_drop(self) -> None:
        engine = InterceptEngine(mode=InterceptMode.INTERCEPT)
        msg = _make_proxy_message()
        held = engine.hold(msg)
        engine.release(held, InterceptAction.DROP)
        assert held.action == InterceptAction.DROP
        assert held.release.is_set()
        assert len(engine.get_held()) == 0

    def test_release_modify(self) -> None:
        engine = InterceptEngine(mode=InterceptMode.INTERCEPT)
        msg = _make_proxy_message()
        held = engine.hold(msg)
        modified_raw = JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=99, method="tools/call"))
        engine.release(held, InterceptAction.MODIFY, modified_raw=modified_raw)
        assert held.action == InterceptAction.MODIFY
        assert held.modified_raw is modified_raw
        assert held.release.is_set()
        assert len(engine.get_held()) == 0


class TestSetMode:
    """InterceptEngine.set_mode() toggles and auto-releases."""

    def test_switch_to_passthrough_releases_all_held(self) -> None:
        engine = InterceptEngine(mode=InterceptMode.INTERCEPT)
        msg1 = _make_proxy_message(sequence=1)
        msg2 = _make_proxy_message(sequence=2)
        held1 = engine.hold(msg1)
        held2 = engine.hold(msg2)
        engine.set_mode(InterceptMode.PASSTHROUGH)
        assert engine.mode == InterceptMode.PASSTHROUGH
        assert held1.release.is_set()
        assert held1.action == InterceptAction.FORWARD
        assert held2.release.is_set()
        assert held2.action == InterceptAction.FORWARD
        assert len(engine.get_held()) == 0

    def test_switch_to_intercept(self) -> None:
        engine = InterceptEngine(mode=InterceptMode.PASSTHROUGH)
        engine.set_mode(InterceptMode.INTERCEPT)
        assert engine.mode == InterceptMode.INTERCEPT


class TestGetState:
    """InterceptEngine.get_state() returns snapshot."""

    def test_empty_state(self) -> None:
        engine = InterceptEngine(mode=InterceptMode.PASSTHROUGH)
        state = engine.get_state()
        assert state.mode == InterceptMode.PASSTHROUGH
        assert state.held_messages == []

    def test_state_with_held_messages(self) -> None:
        engine = InterceptEngine(mode=InterceptMode.INTERCEPT)
        msg = _make_proxy_message()
        engine.hold(msg)
        state = engine.get_state()
        assert state.mode == InterceptMode.INTERCEPT
        assert len(state.held_messages) == 1
