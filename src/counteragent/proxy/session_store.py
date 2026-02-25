"""In-memory session capture for mcp-proxy.

Stores all ProxyMessage objects in a session, with save/load to JSON
via the ProxySession Pydantic model.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.types import JSONRPCMessage

from counteragent.core.models import Direction, Transport
from counteragent.proxy.models import ProxyMessage, ProxySession


class SessionStore:
    """In-memory capture of all proxied messages in a session.

    Args:
        session_id: Unique session identifier (UUID string).
        transport: Transport type for this session.
        server_command: For stdio sessions, the server launch command.
        server_url: For SSE/HTTP sessions, the server endpoint URL.
        metadata: Arbitrary session metadata.

    Example:
        >>> store = SessionStore(session_id="abc", transport=Transport.STDIO)
        >>> store.append(proxy_msg)
        >>> store.save(Path("session.json"))
    """

    def __init__(
        self,
        session_id: str,
        transport: Transport,
        server_command: str | None = None,
        server_url: str | None = None,
        metadata: dict[str, Any] | None = None,
        started_at: datetime | None = None,
    ) -> None:
        self.session_id = session_id
        self.transport = transport
        self.server_command = server_command
        self.server_url = server_url
        self.metadata = metadata or {}
        self.started_at = started_at or datetime.now(tz=UTC)
        self._messages: list[ProxyMessage] = []
        self._index: dict[str, ProxyMessage] = {}

    def append(self, message: ProxyMessage) -> None:
        """Add a message to the session capture.

        Args:
            message: The proxy message to store.
        """
        self._messages.append(message)
        self._index[message.id] = message

    def get_messages(self) -> list[ProxyMessage]:
        """Return all captured messages in order.

        Returns:
            A copy of the message list.
        """
        return list(self._messages)

    def get_by_id(self, proxy_id: str) -> ProxyMessage | None:
        """Look up a message by its proxy-assigned ID.

        Args:
            proxy_id: The ProxyMessage.id to search for.

        Returns:
            The matching ProxyMessage, or None if not found.
        """
        return self._index.get(proxy_id)

    def to_proxy_session(self) -> ProxySession:
        """Convert to a ProxySession Pydantic model for serialization.

        Returns:
            A ProxySession containing all captured messages.
        """
        serialized_messages: list[dict[str, Any]] = []
        for msg in self._messages:
            entry: dict[str, Any] = {
                "proxy_id": msg.id,
                "sequence": msg.sequence,
                "timestamp": msg.timestamp.isoformat(),
                "direction": msg.direction.value,
                "transport": msg.transport.value,
                "jsonrpc_id": msg.jsonrpc_id,
                "method": msg.method,
                "correlated_id": msg.correlated_id,
                "modified": msg.modified,
                "payload": msg.raw.model_dump(by_alias=True, exclude_none=True),
            }
            if msg.original_raw is not None:
                entry["original_payload"] = msg.original_raw.model_dump(
                    by_alias=True, exclude_none=True
                )
            serialized_messages.append(entry)

        return ProxySession(
            id=self.session_id,
            started_at=self.started_at,
            ended_at=None,
            transport=self.transport,
            server_command=self.server_command,
            server_url=self.server_url,
            messages=serialized_messages,
            metadata=self.metadata,
        )

    def save(self, path: Path) -> None:
        """Save the session to a JSON file.

        Args:
            path: File path to write. Parent directories are created
                if they do not exist.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        session = self.to_proxy_session()
        path.write_text(session.model_dump_json(indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> SessionStore:
        """Load a session from a JSON file.

        Args:
            path: File path to read.

        Returns:
            A SessionStore reconstructed from the saved session.
        """
        json_text = path.read_text(encoding="utf-8")
        session = ProxySession.model_validate_json(json_text)
        store = cls(
            session_id=session.id,
            transport=session.transport,
            server_command=session.server_command,
            server_url=session.server_url,
            metadata=session.metadata,
            started_at=session.started_at,
        )
        for entry in session.messages:
            raw = JSONRPCMessage.model_validate(entry["payload"])
            original_raw = None
            if "original_payload" in entry:
                original_raw = JSONRPCMessage.model_validate(entry["original_payload"])
            msg = ProxyMessage(
                id=entry["proxy_id"],
                sequence=entry["sequence"],
                timestamp=datetime.fromisoformat(entry["timestamp"]),
                direction=Direction(entry["direction"]),
                transport=Transport(entry["transport"]),
                raw=raw,
                jsonrpc_id=entry.get("jsonrpc_id"),
                method=entry.get("method"),
                correlated_id=entry.get("correlated_id"),
                modified=entry.get("modified", False),
                original_raw=original_raw,
            )
            store.append(msg)
        return store
