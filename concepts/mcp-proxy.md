# mcp-proxy

> Interactive MCP traffic interceptor — "Burp Suite for MCP."

## Purpose

mcp-proxy is a man-in-the-middle proxy that sits between an MCP client (Claude Desktop, Cursor, etc.) and an MCP server, allowing interception, inspection, modification, and replay of live JSON-RPC traffic. No existing tool provides this for MCP. Burp Suite sees HTTP but doesn't understand MCP JSON-RPC semantics or stdio transport. When bounty hunting against a real MCP server, you need to see what the client sends, what the server returns, and modify payloads on the fly — mcp-proxy provides that workflow.

## Program Context

Phase 1.5 in the CounterAgent program. mcp-audit (Phase 1) handles automated scanning — predefined checks against OWASP MCP Top 10. mcp-proxy handles the manual testing that automated scanners can't do: exploring complex multi-step JSON-RPC flows, testing logic bugs, and crafting targeted payloads interactively.

The two tools form a feedback loop:
- mcp-audit findings feed into mcp-proxy sessions ("scan found a possible injection in tool X, now manually explore it")
- Manual discoveries in mcp-proxy feed new scanner modules back into mcp-audit
- Both produce evidence for bounty submissions and detection engineering

## Core Capabilities

- Proxy all three MCP transports: stdio, SSE, and Streamable HTTP.
- Log all JSON-RPC messages with timestamps, direction, and tool/method metadata.
- Intercept mode: pause on each message, allow inspection and modification before forwarding.
- Replay mode: re-send captured tool calls with modified arguments against the live server.
- Filter and search message history by tool name, JSON-RPC method, or content pattern.
- Export sessions as structured JSON for evidence capture and reproducibility.

## Key Design Decisions

- **Standalone repo** (`richardspicer/mcp-proxy`), not a mode inside mcp-audit. Fundamentally different UX: interactive long-running proxy vs. automated scan-and-report. Different use pattern — mcp-audit runs and exits, mcp-proxy stays running while you test.
- **Python CLI with TUI** (Textual). Terminal tool for researchers, not a GUI. Keeps the dependency footprint small and the tool composable.
- **Proxy core is a pass-through** that hooks into the message stream. Not a full MCP client — it doesn't interpret tool semantics, just intercepts and forwards JSON-RPC messages with optional modification.
- **Shares no code with mcp-audit at the package level.** The MCP client in mcp-audit is a scanning-oriented wrapper around the SDK. mcp-proxy operates at a lower level — intercepting raw JSON-RPC, not calling tools through the SDK. If shared utilities emerge, they get extracted later, not prematurely.
- **Session-based** — each proxy session is a discrete unit that can be saved, loaded, and replayed.
- **Cross-platform** — must run on Windows, macOS, and Linux. No platform-specific shell commands in source or test fixtures.

## Open Questions

- **Transport multiplexing:** Should mcp-proxy support proxying multiple concurrent client-server pairs, or one pair per instance? Multiple pairs adds complexity but matches real-world setups where Claude Desktop connects to several servers. Leaning toward single-pair for v1.
- **TLS interception for SSE/Streamable HTTP:** Burp handles this with its CA cert. Does mcp-proxy need the same, or is it sufficient to proxy the unencrypted side of local development servers? Most MCP servers in testing are localhost.
- **Breakpoint conditions:** Should intercept mode support conditional breakpoints (e.g., "only pause on tool calls to `execute_query`"), or is global pause sufficient for v1?
- **Dependency on MCP SDK:** Should mcp-proxy use the `mcp` SDK for transport handling, or implement raw JSON-RPC proxying to avoid SDK assumptions about message flow? Raw gives more control for interception but more work.

## Artifacts

- Captured MCP session transcripts (JSON) with full message history, timestamps, and metadata.
- Modified-payload replay logs showing before/after request-response pairs.
- Logic flaw evidence chains: "client sent X, I modified to Y, server returned Z" — structured for bounty submissions.

## Relation to Other Tools

- **mcp-audit** handles automated scanning. mcp-proxy does NOT run predefined checks or produce OWASP-mapped findings. It's the manual exploration tool.
- **agent-inject** (Phase 2) tests agent-level trust exploitation. mcp-proxy operates at the protocol level — it doesn't care what the agent does with tool responses, only what the server sends and receives.
- **Burp Suite** handles HTTP. mcp-proxy handles MCP JSON-RPC, including stdio transport which has no HTTP layer at all.

---

*This is a concept doc, not an architecture doc. It captures intent and constraints. The full Architecture doc gets written when development begins.*
