"""Tests for counteragent.proxy.correlation."""

from mcp.types import (
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
)

from counteragent.proxy.correlation import (
    extract_jsonrpc_id,
    extract_method,
    is_notification,
    is_request,
    is_response,
)


def _request(method: str = "tools/list", msg_id: int = 1) -> JSONRPCMessage:
    return JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=msg_id, method=method))


def _response(msg_id: int = 1) -> JSONRPCMessage:
    return JSONRPCMessage(JSONRPCResponse(jsonrpc="2.0", id=msg_id, result={}))


def _error(msg_id: int = 1) -> JSONRPCMessage:
    return JSONRPCMessage(
        JSONRPCError(
            jsonrpc="2.0",
            id=msg_id,
            error={"code": -32600, "message": "Invalid Request"},
        )
    )


def _notification(method: str = "notifications/progress") -> JSONRPCMessage:
    return JSONRPCMessage(JSONRPCNotification(jsonrpc="2.0", method=method))


class TestExtractJsonrpcId:
    def test_request_id(self) -> None:
        assert extract_jsonrpc_id(_request(msg_id=42)) == 42

    def test_response_id(self) -> None:
        assert extract_jsonrpc_id(_response(msg_id=7)) == 7

    def test_error_id(self) -> None:
        assert extract_jsonrpc_id(_error(msg_id=99)) == 99

    def test_notification_has_no_id(self) -> None:
        assert extract_jsonrpc_id(_notification()) is None

    def test_string_id(self) -> None:
        msg = JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id="abc-123", method="test"))
        assert extract_jsonrpc_id(msg) == "abc-123"


class TestExtractMethod:
    def test_request_method(self) -> None:
        assert extract_method(_request("tools/call")) == "tools/call"

    def test_notification_method(self) -> None:
        assert extract_method(_notification("notifications/cancelled")) == "notifications/cancelled"

    def test_response_has_no_method(self) -> None:
        assert extract_method(_response()) is None

    def test_error_has_no_method(self) -> None:
        assert extract_method(_error()) is None


class TestMessageClassification:
    def test_request(self) -> None:
        msg = _request()
        assert is_request(msg) is True
        assert is_response(msg) is False
        assert is_notification(msg) is False

    def test_response(self) -> None:
        msg = _response()
        assert is_request(msg) is False
        assert is_response(msg) is True
        assert is_notification(msg) is False

    def test_error_is_response(self) -> None:
        msg = _error()
        assert is_request(msg) is False
        assert is_response(msg) is True
        assert is_notification(msg) is False

    def test_notification(self) -> None:
        msg = _notification()
        assert is_request(msg) is False
        assert is_response(msg) is False
        assert is_notification(msg) is True
