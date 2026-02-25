# CounterAgent

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)

**Open source offensive security suite for testing attack chains targeting autonomous AI agents.**

> **Status:** mcp-audit is the first released tool. mcp-proxy, agent-inject, and agent-chain are planned.

Covers MCP server vulnerabilities, tool poisoning, prompt injection via tools, and agent-to-agent exploitation. Maps findings to [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) and [OWASP Top 10 for Agentic AI](https://genai.owasp.org/).

> Research program by [Richard Spicer](https://richardspicer.io) · [GitHub](https://github.com/richardspicer)

CounterAgent is the **protocol & system** arm of the Agentic AI Security ecosystem. The **[Volery](https://github.com/richardspicer/volery)** program (IPI-Canary, CXP-Canary, Drongo) is the sister program handling content & supply chain security.

---

## Quick Start

### Install

```bash
git clone https://github.com/richardspicer/counteragent.git
cd counteragent
uv sync --group dev
```

### Usage

```bash
# See all available tools
counteragent --help

# MCP server security scanning (Phase B)
counteragent audit --help

# MCP traffic interception (Phase C)
counteragent proxy --help
```

> **Note:** This is the unified monorepo. Individual tool source code is being migrated from standalone repos. See [Roadmap](Roadmap.md) for current status.

---

## Tools

The program produces four tools in phases, each building on the last:

| Tool | Phase | Focus | Status |
|------|-------|-------|--------|
| [**mcp-audit**](https://github.com/richardspicer/mcp-audit) | 1 | MCP server security scanner — automated checks against OWASP MCP Top 10 | 🚧 Active |
| **mcp-proxy** | 1.5 | Interactive MCP traffic interceptor — inspect, modify, and replay JSON-RPC messages | 🚧 Active |
| **agent-inject** | 2 | Tool poisoning & prompt injection framework — test how agents handle malicious tool outputs | 📋 Planned |
| **agent-chain** | 3 | Multi-agent attack chain exploitation — full attack paths across agent architectures | 📋 Planned |

---

Existing AI red teaming tools (Garak, PyRIT, Promptfoo) focus on LLM-level testing — prompt injection, output analysis, jailbreaks. CounterAgent targets the layer above: MCP servers, tool trust boundaries, and agent delegation chains. mcp-audit handles automated scanning; mcp-proxy provides the manual testing workflow (intercept, modify, replay) for deeper exploration of findings.

---

## Phase 1: mcp-audit (Active)

Automated security scanner for MCP server implementations. Connects to a server, enumerates its capabilities, runs modular security checks, and produces reports with findings mapped to OWASP MCP Top 10.

```bash
# Scan a local MCP server
counteragent audit scan --transport stdio --command "python my_server.py"

# See available checks
counteragent audit list-checks
```

**Current status:** 10 scanner modules covering all OWASP MCP Top 10 categories, 378 tests passing.

---

## Phase 1.5: mcp-proxy (Active)

Interactive MCP traffic interceptor — "Burp Suite for MCP." Sits between an MCP client and server, intercepting, modifying, and replaying live JSON-RPC traffic for manual security testing.

- Proxy all MCP transports (stdio, SSE, Streamable HTTP)
- Intercept mode: pause, inspect, modify messages before forwarding
- Replay mode: re-send captured tool calls with modified arguments
- TUI interface (Textual) for terminal-based researchers
- Session export (JSON) for evidence capture

mcp-audit findings feed directly into mcp-proxy sessions — "scan found a possible injection in tool X, now manually explore it."

---

## Phase 2: agent-inject (Planned)

Framework for testing how AI agents handle malicious tool outputs, poisoned tool descriptions, and prompt injection payloads delivered through tool integrations.

- Tool description poisoning — embedded instructions in MCP tool metadata
- Output injection payloads — tool responses containing prompt injection
- Cross-tool escalation — one tool's output manipulates use of another tool
- Effectiveness scoring across agent configurations

---

## Phase 3: agent-chain (Planned)

Map and demonstrate full multi-step attack chains exploiting interactions between agents, tools, and data sources in real-world agentic architectures.

- Agent-to-agent exploitation and confused deputy attacks
- Data pipeline poisoning (RAG, vector databases)
- Autonomous action abuse and lateral movement
- Attack chain visualization and blast radius analysis

---

## Framework Mapping

All findings map to established frameworks:

| Framework | Usage |
|-----------|-------|
| OWASP MCP Top 10 | Primary vulnerability taxonomy (Phase 1) |
| OWASP Top 10 for Agentic AI | Attack pattern classification (Phases 2-3) |
| OWASP Top 10 for LLM Applications 2025 | Cross-reference for LLM-specific findings |
| MITRE ATLAS | Adversarial ML technique mapping |
| NIST AI RMF | Risk management context |

---

## Legal

All tools are intended for authorized security testing only. Only test systems you own, control, or have explicit permission to test. Responsible disclosure for all vulnerabilities discovered.

## License

All CounterAgent tools are released under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0).

## Documentation

| Document | Purpose |
|----------|---------|
| [Roadmap](Roadmap.md) | Phased development plan, OWASP mapping, deliverables, success metrics |
| [concepts/](concepts/) | Concept docs for tools (agent-inject, agent-chain) |
| [CONTRIBUTING](CONTRIBUTING.md) | Development setup, branch workflow, code standards |
| [SECURITY](SECURITY.md) | Vulnerability reporting and responsible disclosure |

## AI Disclosure

This project uses a human-led, AI-augmented workflow. See [AI-STATEMENT.md](AI-STATEMENT.md).
