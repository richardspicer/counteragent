"""JSON-RPC field extraction and message classification utilities.

Insulates the rest of the codebase from the MCP SDK's JSONRPCMessage
internal structure. The pipeline, session store, and correlation logic
use these helpers instead of reaching into raw message internals.
"""

from typing import cast

from mcp.types import (
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
)


def extract_jsonrpc_id(message: JSONRPCMessage) -> str | int | None:
    """Extract the JSON-RPC id field from a message.

    Args:
        message: A JSONRPCMessage (RootModel wrapping a request, response,
            notification, or error).

    Returns:
        The id value (str or int) for requests, responses, and errors.
        None for notifications (which have no id field).
    """
    root = message.root
    if isinstance(root, JSONRPCRequest):
        return cast(str | int, root.id)
    if isinstance(root, (JSONRPCResponse, JSONRPCError)):
        return cast(str | int, root.id)
    return None


def extract_method(message: JSONRPCMessage) -> str | None:
    """Extract the JSON-RPC method field from a message.

    Args:
        message: A JSONRPCMessage (RootModel wrapping a request, response,
            notification, or error).

    Returns:
        The method string for requests and notifications.
        None for responses and errors (which have no method field).
    """
    root = message.root
    if isinstance(root, JSONRPCRequest):
        return cast(str, root.method)
    if isinstance(root, JSONRPCNotification):
        return cast(str, root.method)
    return None


def is_request(message: JSONRPCMessage) -> bool:
    """Check if the message is a JSON-RPC request (has id and method).

    Args:
        message: A JSONRPCMessage to classify.

    Returns:
        True if the message is a request.
    """
    return isinstance(message.root, JSONRPCRequest)


def is_response(message: JSONRPCMessage) -> bool:
    """Check if the message is a JSON-RPC response or error (has id, no method).

    Args:
        message: A JSONRPCMessage to classify.

    Returns:
        True if the message is a response or error.
    """
    return isinstance(message.root, JSONRPCResponse | JSONRPCError)


def is_notification(message: JSONRPCMessage) -> bool:
    """Check if the message is a JSON-RPC notification (has method, no id).

    Args:
        message: A JSONRPCMessage to classify.

    Returns:
        True if the message is a notification.
    """
    return isinstance(message.root, JSONRPCNotification)
