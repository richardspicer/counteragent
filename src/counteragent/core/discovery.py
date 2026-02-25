"""Server capability discovery and enumeration.

Connects to an MCP server and enumerates all tools, resources, and
prompts it exposes. Packages results into a ScanContext that scanner
modules consume.

Usage:
    async with MCPConnection.stdio("python", ["server.py"]) as conn:
        context = await enumerate_server(conn)
        print(f"Found {len(context.tools)} tools")
"""

from __future__ import annotations

import logging
from typing import Any

from counteragent.core.connection import MCPConnection
from counteragent.core.models import ScanContext

logger = logging.getLogger("counteragent.discovery")


def _tool_to_dict(tool: Any) -> dict[str, Any]:
    """Convert an MCP Tool object to a plain dict for ScanContext.

    Keeps the data serializable and decoupled from SDK types so
    scanner modules don't need to import the SDK directly.

    Args:
        tool: An mcp.types.Tool instance.

    Returns:
        Dict with tool name, description, input schema, and metadata.
    """
    return {
        "name": tool.name,
        "title": tool.title,
        "description": tool.description or "",
        "inputSchema": tool.inputSchema or {},
        "outputSchema": tool.outputSchema,
        "annotations": tool.annotations.model_dump() if tool.annotations else None,
    }


def _resource_to_dict(resource: Any) -> dict[str, Any]:
    """Convert an MCP Resource object to a plain dict.

    Args:
        resource: An mcp.types.Resource instance.

    Returns:
        Dict with resource URI, name, description, and MIME type.
    """
    return {
        "uri": str(resource.uri),
        "name": resource.name,
        "title": resource.title,
        "description": resource.description or "",
        "mimeType": resource.mimeType,
    }


def _prompt_to_dict(prompt: Any) -> dict[str, Any]:
    """Convert an MCP Prompt object to a plain dict.

    Args:
        prompt: An mcp.types.Prompt instance.

    Returns:
        Dict with prompt name, description, and arguments.
    """
    return {
        "name": prompt.name,
        "title": prompt.title,
        "description": prompt.description or "",
        "arguments": [
            {"name": a.name, "description": a.description or "", "required": a.required}
            for a in (prompt.arguments or [])
        ],
    }


async def enumerate_server(conn: MCPConnection) -> ScanContext:
    """Enumerate all capabilities of a connected MCP server.

    Queries the server for tools, resources, and prompts, and packages
    everything into a ScanContext for scanner modules. Capabilities that
    the server doesn't support are silently skipped.

    Args:
        conn: An active MCPConnection (already entered as context manager).

    Returns:
        ScanContext populated with server metadata and all discovered
        tools, resources, and prompts.

    Example:
        async with MCPConnection.stdio("python", ["server.py"]) as conn:
            ctx = await enumerate_server(conn)
            for tool in ctx.tools:
                print(f"  {tool['name']}: {tool['description']}")
    """
    session = conn.session
    capabilities = conn.init_result.capabilities
    server_info = conn.init_result.serverInfo

    # Build server_info dict
    info_dict: dict[str, Any] = {
        "name": server_info.name if server_info else "unknown",
        "version": server_info.version if server_info else "unknown",
        "protocolVersion": conn.init_result.protocolVersion,
        "instructions": conn.init_result.instructions,
    }

    # Enumerate tools (if server supports them)
    tools: list[dict[str, Any]] = []
    if capabilities and capabilities.tools:
        try:
            tools_result = await session.list_tools()
            tools = [_tool_to_dict(t) for t in tools_result.tools]
            logger.info("Discovered %d tools", len(tools))
        except Exception:
            logger.warning("Failed to enumerate tools", exc_info=True)

    # Enumerate resources (if server supports them)
    resources: list[dict[str, Any]] = []
    if capabilities and capabilities.resources:
        try:
            resources_result = await session.list_resources()
            resources = [_resource_to_dict(r) for r in resources_result.resources]
            logger.info("Discovered %d resources", len(resources))
        except Exception:
            logger.warning("Failed to enumerate resources", exc_info=True)

    # Enumerate prompts (if server supports them)
    prompts: list[dict[str, Any]] = []
    if capabilities and capabilities.prompts:
        try:
            prompts_result = await session.list_prompts()
            prompts = [_prompt_to_dict(p) for p in prompts_result.prompts]
            logger.info("Discovered %d prompts", len(prompts))
        except Exception:
            logger.warning("Failed to enumerate prompts", exc_info=True)

    # Extract connection URL for HTTP-based transports (auth scanner needs this)
    connection_url: str | None = None
    if conn.transport_type in ("sse", "streamable-http"):
        connection_url = conn._transport_args.get("url")

    return ScanContext(
        server_info=info_dict,
        tools=tools,
        resources=resources,
        prompts=prompts,
        transport_type=conn.transport_type,
        connection_url=connection_url,
        session=session,
    )
