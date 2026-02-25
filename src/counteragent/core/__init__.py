"""Shared core modules -- models, transport, and utilities."""

from counteragent.core.connection import MCPConnection
from counteragent.core.discovery import enumerate_server
from counteragent.core.models import Finding, ScanContext, Severity

__all__ = ["Finding", "MCPConnection", "ScanContext", "Severity", "enumerate_server"]
