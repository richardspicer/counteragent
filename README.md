# CounterAgent

**Open source offensive security suite for testing attack chains targeting autonomous AI agents.**

> **Status:** mcp-audit is the first released tool. mcp-proxy, agent-inject, and agent-chain are planned.

Covers MCP server vulnerabilities, tool poisoning, prompt injection via tools, and agent-to-agent exploitation. Maps findings to [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) and [OWASP Top 10 for Agentic AI](https://genai.owasp.org/).

> Research program by [Richard Spicer](https://richardspicer.io) · [GitHub](https://github.com/richardspicer)

CounterAgent is the **protocol & system** arm of the Agentic AI Security ecosystem. The **[Volery](https://github.com/richardspicer/volery)** program (IPI-Canary, CXP-Canary, Drongo) is the sister program handling content & supply chain security.

---

## Tools

The program produces four tools in phases, each building on the last:

| Tool | Phase | Focus | Status |
|------|-------|-------|--------|
| [**mcp-audit**](https://github.com/richardspicer/mcp-audit) | 1 | MCP server security scanner — automated checks against OWASP MCP Top 10 | 🚧 Active |
| **mcp-proxy** | 1.5 | Interactive MCP traffic interceptor — inspect, modify, and replay JSON-RPC messages | 📋 Planned |
| **agent-inject** | 2 | Tool poisoning & prompt injection framework — test how agents handle malicious tool outputs | 📋 Planned |
| **agent-chain** | 3 | Multi-agent attack chain exploitation — full attack paths across agent architectures | 📋 Planned |

---

Existing AI red teaming tools (Garak, PyRIT, Promptfoo) focus on LLM-level testing — prompt injection, output analysis, jailbreaks. CounterAgent targets the layer above: MCP servers, tool trust boundaries, and agent delegation chains. mcp-audit handles automated scanning; mcp-proxy provides the manual testing workflow (intercept, modify, replay) for deeper exploration of findings.

---

## Phase 1: mcp-audit (Active)

Automated security scanner for MCP server implementations. Connects to a server, enumerates its capabilities, runs modular security checks, and produces reports with findings mapped to OWASP MCP Top 10.

```bash
# Scan a local MCP server
mcp-audit scan --transport stdio --command "python my_server.py"

# See available checks
mcp-audit list-checks
```

**Current status:** MCP client (stdio/SSE/Streamable HTTP), injection scanner (MCP05), scan orchestrator, JSON reporting, 17 tests passing. See the [mcp-audit repo](https://github.com/richardspicer/mcp-audit) for details.

---

## Phase 1.5: mcp-proxy (Planned)

<<<<<<< Updated upstream
Interactive MCP traffic interceptor — "Burp Suite for MCP." Sits between an MCP client and server, intercepting, modifying, and replaying live JSON-RPC traffic for manual security testing.

- Proxy all MCP transports (stdio, SSE, Streamable HTTP)
- Intercept mode: pause, inspect, modify messages before forwarding
- Replay mode: re-send captured tool calls with modified arguments
- TUI interface (Textual) for terminal-based researchers
- Session export (JSON) for evidence capture

mcp-audit finds potential issues automatically; mcp-proxy lets you manually explore them.
=======
Interactive man-in-the-middle proxy for MCP traffic — the Burp Suite equivalent for JSON-RPC. Sits between an MCP client and server, allowing inspection, modification, and replay of live traffic to find logic bugs that automated scanning misses.

- Proxy stdio, SSE, and Streamable HTTP MCP transports
- Intercept mode: pause, inspect, modify, and forward individual messages
- Replay mode: re-send captured tool calls with modified arguments
- Session export as JSON for evidence capture
- TUI interface for interactive research workflows

mcp-audit findings feed directly into mcp-proxy sessions — "scan found a possible injection in tool X, now manually explore it."
>>>>>>> Stashed changes

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
| [Architecture](Architecture.md) | mcp-audit architecture, data models, module structure, extension points |
| [concepts/](concepts/) | Concept docs for planned tools (mcp-proxy, agent-inject, agent-chain) |

## AI Disclosure

This project uses a human-led, AI-augmented workflow. See [AI-STATEMENT.md](AI-STATEMENT.md).
