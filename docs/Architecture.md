# CounterAgent Architecture

## Overview

CounterAgent is a unified monorepo consolidating MCP security tools into one Python package with a shared CLI. It provides automated security scanning (audit) and interactive traffic interception (proxy) for MCP servers.

---

## Package Layout

```
src/counteragent/
├── __init__.py               # Package version
├── __main__.py               # python -m counteragent support
├── cli.py                    # Root Typer app — mounts audit, proxy, inject, chain
├── core/                     # Shared models, connection, transport
│   ├── __init__.py
│   ├── models.py             # Data models (Finding, ScanContext, Severity, Transport, Direction)
│   ├── connection.py         # MCP connection management
│   ├── discovery.py          # Server enumeration, capability discovery
│   ├── evidence.py           # Evidence collection and reporting
│   ├── owasp.py              # OWASP MCP Top 10 category definitions
│   └── transport.py          # Transport abstractions (stdio, SSE, Streamable HTTP)
├── audit/                    # MCP server security scanner
│   ├── cli.py                # audit subcommand CLI (scan, list-checks, enumerate, report)
│   ├── orchestrator.py       # ScanResult + run_scan() entry point
│   ├── scanner/              # Scanner modules (one per OWASP category)
│   │   ├── base.py           # BaseScanner ABC + re-exports from core.models
│   │   ├── registry.py       # Scanner registry and lookup
│   │   ├── injection.py      # MCP05 — Command Injection
│   │   ├── auth.py           # MCP07 — Authentication/Authorization
│   │   ├── token_exposure.py # MCP01 — Token Mismanagement
│   │   ├── permissions.py    # MCP02 — Privilege Escalation
│   │   ├── tool_poisoning.py # MCP03 — Tool Poisoning
│   │   ├── supply_chain.py   # MCP04 — Supply Chain & Integrity
│   │   ├── prompt_injection.py # MCP06 — Indirect Prompt Injection
│   │   ├── audit_telemetry.py  # MCP08 — Audit & Telemetry
│   │   ├── shadow_servers.py # MCP09 — Shadow MCP Servers
│   │   └── context_sharing.py # MCP10 — Context Over-Sharing
│   ├── payloads/             # Injection payload generators
│   ├── reporting/            # JSON report output (HTML/SARIF planned)
│   ├── mcp_client/           # Re-export shims → core.connection, core.discovery
│   └── utils/                # Scan-specific utilities
├── proxy/                    # MCP traffic interceptor
│   ├── cli.py                # proxy subcommand CLI (start, replay, export, inspect)
│   ├── models.py             # ProxyMessage, ProxySession, HeldMessage, InterceptAction
│   ├── pipeline.py           # Message pipeline (bidirectional forwarding loops)
│   ├── intercept.py          # InterceptEngine (hold/release/breakpoint logic)
│   ├── session_store.py      # SessionStore (capture, save/load, export)
│   ├── replay.py             # ReplayEngine (re-send captured messages)
│   ├── correlation.py        # Request-response correlation by JSON-RPC id
│   ├── exporting/            # Session export formats
│   ├── adapters/             # Transport adapters
│   │   ├── __init__.py       # TransportAdapter protocol
│   │   └── stdio.py          # StdioServerAdapter, StdioClientAdapter
│   └── tui/                  # Textual TUI
│       ├── app.py            # ProxyApp — main Textual application
│       ├── messages.py       # Custom Textual messages (MessageReceived, etc.)
│       └── widgets/          # TUI widgets
│           ├── message_list.py    # Message list panel
│           ├── message_detail.py  # Message detail/edit panel
│           └── status_bar.py      # Proxy status bar
├── inject/                   # Tool poisoning & prompt injection [Phase 2]
│   └── cli.py                # inject subcommand CLI (placeholder)
└── chain/                    # Multi-agent attack chains [Phase 3]
    └── cli.py                # chain subcommand CLI (placeholder)
```

---

## Shared Core (`core/`)

The core module provides types and utilities shared across all submodules:

- **`models.py`** — `Severity` enum, `Finding` dataclass, `ScanContext`, `Transport` enum, `Direction` enum
- **`connection.py`** — `MCPConnection` class for establishing MCP client connections
- **`discovery.py`** — `enumerate_server()` for capability discovery
- **`transport.py`** — Transport type abstractions
- **`evidence.py`** — Evidence collection for reporting
- **`owasp.py`** — OWASP MCP Top 10 category definitions and metadata

---

## Audit Module

**Data flow:** CLI → `run_scan()` (orchestrator) → `enumerate_server()` (discovery) → scanner registry → each scanner's `scan()` → aggregate `ScanResult` → JSON report

**Key abstractions:**

- **`BaseScanner`** ABC in `scanner/base.py` — every scanner extends this and implements `async scan(context: ScanContext) -> list[Finding]`
- Scanner registry maintains a static mapping of scanner modules
- Import convention: shared types from `counteragent.audit.scanner.base` (re-exports from core)
- `mcp_client/` contains backward-compatibility shims pointing to `core.connection` and `core.discovery`

10 scanner modules, one per OWASP MCP Top 10 category. See `docs/owasp_mapping.md` for detailed coverage.

---

## Proxy Module

**Design principle:** SDK for transport, raw for messages. Uses MCP SDK transport functions for connection setup but operates on raw `JSONRPCMessage` objects.

**Data flow:** CLI → TUI App (Textual Worker) → Pipeline → Transport Adapters → Target Server

```
┌──────────────┐         ┌──────────────────────────────────────┐         ┌──────────────┐
│  MCP Client  │         │           counteragent proxy         │         │  MCP Server   │
│  (Claude,    │  stdio  │  ┌────────┐  ┌─────────┐  ┌──────┐ │  stdio  │  (target      │
│   Cursor,    │◄───────►│  │Client  │  │Message  │  │Server│ │◄───────►│   server)     │
│   etc.)      │  SSE    │  │Adapter │◄►│Pipeline │◄►│Adapt.│ │  SSE    │               │
│              │  HTTP   │  └────────┘  └─────────┘  └──────┘ │  HTTP   │               │
└──────────────┘         │       ▲      ▲    │    ▲            │         └──────────────┘
                         │       │      │    ▼    │            │
                         │       │  ┌─────────┐   │            │
                         │       │  │Intercept│   │            │
                         │       │  │Engine   │   │            │
                         │       │  └─────────┘   │            │
                         │       │      │    ▲    │            │
                         │       │      ▼    │    │            │
                         │  ┌────────┐ ┌─────────┐ ┌────────┐ │
                         │  │Session │ │ Replay  │ │Textual │ │
                         │  │Store   │ │ Engine  │ │  TUI   │ │
                         │  └────────┘ └─────────┘ └────────┘ │
                         └──────────────────────────────────────┘
```

**Key abstractions:**

- **`TransportAdapter`** protocol — `read()`, `write()`, `close()`
- **`InterceptEngine`** — hold/release messages via `asyncio.Event`, FORWARD/MODIFY/DROP actions
- **`SessionStore`** — ordered `ProxyMessage` sequence, save/load JSON
- **`ProxyMessage`** — envelope wrapping JSON-RPC message with metadata (direction, timestamp, sequence, correlation)
- asyncio primary, anyio only at SDK boundary inside transport adapters

---

## CLI Hierarchy

Root `cli.py` creates a Typer app and mounts subcommands:

- `counteragent audit ...` → `audit/cli.py` (scan, list-checks, enumerate, report)
- `counteragent proxy ...` → `proxy/cli.py` (start, replay, export, inspect)
- `counteragent inject ...` → `inject/cli.py` (placeholder)
- `counteragent chain ...` → `chain/cli.py` (placeholder)

---

## Test Layout

```
tests/
├── audit/                    # Audit module tests
│   ├── test_scanner/         # Per-scanner unit tests
│   ├── test_mcp_client/      # MCP client tests
│   ├── test_orchestrator.py
│   └── test_cli.py
├── proxy/                    # Proxy module tests
│   ├── test_tui/             # TUI app and widget tests
│   ├── test_pipeline.py
│   ├── test_intercept.py
│   ├── test_session_store.py
│   ├── test_replay.py
│   └── test_cli.py
├── core/                     # Core module tests
└── conftest.py               # Shared fixtures
fixtures/vulnerable_servers/  # Intentionally vulnerable MCP servers for integration testing
```

---

## Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Language | Python >=3.11 | Async-native, rich ecosystem for security tooling |
| MCP SDK | mcp v1.x | Official SDK, stable API |
| CLI | Typer | Declarative CLI with auto-generated help |
| TUI | Textual 8.x | Async-native terminal UI framework |
| Async | asyncio (stdlib), anyio at SDK boundary | Standard library async, anyio for MCP SDK compatibility |
| Serialization | Pydantic | Type-safe data models with validation |
| Testing | pytest + pytest-asyncio | Async test support, fixture-based |
| Linting | ruff | Fast, unified linter and formatter |
| Type checking | mypy | Static type verification |
| Packaging | hatchling + uv | Modern Python packaging with fast dependency resolution |
