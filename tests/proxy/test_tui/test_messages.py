"""Tests for counteragent.proxy.tui.messages — custom Textual message types."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest

from counteragent.core.models import Direction, Transport
from counteragent.proxy.models import HeldMessage, ProxyMessage
from counteragent.proxy.replay import ReplayResult
from counteragent.proxy.tui.messages import (
    MessageForwarded,
    MessageHeld,
    MessageReceived,
    PipelineError,
    PipelineStopped,
    ReplayCompleted,
)


def _make_proxy_message(method: str = "tools/list", seq: int = 0) -> ProxyMessage:
    """Build a ProxyMessage for testing."""
    return ProxyMessage(
        id=str(uuid.uuid4()),
        sequence=seq,
        timestamp=datetime.now(tz=UTC),
        direction=Direction.CLIENT_TO_SERVER,
        transport=Transport.STDIO,
        raw=JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=1, method=method)),
        jsonrpc_id=1,
        method=method,
        correlated_id=None,
        modified=False,
        original_raw=None,
    )


class TestMessageReceived:
    """MessageReceived wraps a ProxyMessage."""

    def test_stores_proxy_message(self) -> None:
        pm = _make_proxy_message()
        msg = MessageReceived(pm)
        assert msg.proxy_message is pm


class TestMessageHeld:
    """MessageHeld wraps a HeldMessage."""

    def test_stores_held_message(self) -> None:
        pm = _make_proxy_message()
        held = HeldMessage(
            proxy_message=pm,
            release=asyncio.Event(),
            action=None,
            modified_raw=None,
        )
        msg = MessageHeld(held)
        assert msg.held_message is held


class TestMessageForwarded:
    """MessageForwarded wraps a ProxyMessage."""

    def test_stores_proxy_message(self) -> None:
        pm = _make_proxy_message()
        msg = MessageForwarded(pm)
        assert msg.proxy_message is pm


class TestPipelineError:
    """PipelineError wraps an exception."""

    def test_stores_error(self) -> None:
        err = RuntimeError("boom")
        msg = PipelineError(err)
        assert msg.error is err


class TestPipelineStopped:
    """PipelineStopped carries no data."""

    def test_instantiates(self) -> None:
        msg = PipelineStopped()
        assert isinstance(msg, PipelineStopped)


class TestReplayCompleted:
    """ReplayCompleted wraps a ReplayResult and optional original response."""

    def test_stores_result_and_original(self) -> None:
        pm = _make_proxy_message()
        sent = SessionMessage(message=pm.raw)
        result = ReplayResult(
            original_request=pm,
            sent_message=sent,
            response=None,
            error=None,
            duration_ms=42.0,
        )
        original_resp = _make_proxy_message("tools/list", seq=1)
        msg = ReplayCompleted(result=result, original_response=original_resp)
        assert msg.result is result
        assert msg.original_response is original_resp

    def test_stores_result_without_original(self) -> None:
        pm = _make_proxy_message()
        sent = SessionMessage(message=pm.raw)
        result = ReplayResult(
            original_request=pm,
            sent_message=sent,
            response=None,
            error="timeout",
            duration_ms=10000.0,
        )
        msg = ReplayCompleted(result=result, original_response=None)
        assert msg.result is result
        assert msg.original_response is None
