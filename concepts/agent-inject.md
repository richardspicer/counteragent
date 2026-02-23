# agent-inject

> Tool poisoning and prompt injection framework for testing agent trust boundaries.

## Purpose

Phase 1 tests MCP servers. agent-inject tests what happens when an agent *trusts* the output from those servers. A tool that passes basic security checks but returns carefully crafted output designed to manipulate agent behavior is the threat model. No existing tool packages this as a repeatable, measurable testing framework. Current approaches are ad-hoc — researchers craft individual payloads and manually observe results. agent-inject makes tool poisoning and output injection systematic, scored, and reproducible.

## Program Context

Phase 2 in the CounterAgent program. Builds directly on Phase 1 findings — vulnerabilities discovered by mcp-audit and mcp-proxy become the delivery mechanisms for agent-inject payloads. Where Phase 1 asks "is this server vulnerable?", Phase 2 asks "what can an attacker achieve through a vulnerable server?"

Feeds forward into Phase 3 (agent-chain) — successful single-tool injection techniques become building blocks for multi-step attack chains.

## Core Capabilities

- Serve configurable payloads through purpose-built malicious MCP servers.
- Template payloads by technique (tool description poisoning, output injection, cross-tool escalation) and by target (Claude, ChatGPT, Copilot, open-source agents).
- Measure injection effectiveness with automated scoring — did the agent follow the injected instruction, partially comply, or reject it?
- Score memory persistence — how long injected behaviors survive across conversation turns and sessions in agents with memory features (persistence half-life metrics).
- Run injection campaigns against isolated agent setups with structured result capture.
- Generate reports mapping successful techniques to agent configurations and OWASP categories.
- **Advisory-informed scenarios** — reference real MCP CVEs from GitHub Advisory Database to design realistic attack scenarios grounded in actual vulnerability patterns rather than theoretical constructs.

## Key Design Decisions

- **Standalone repo** (`richardspicer/agent-inject`). Different threat model and target surface from mcp-audit.
- **Malicious MCP servers as the delivery mechanism.** Payloads are served through MCP tool descriptions, tool outputs, and resource content — not injected through HTTP or other side channels. This matches the real-world attack vector.
- **Effectiveness scoring is core, not optional.** "It worked once" isn't research. Scoring must be automated, repeatable, and produce comparable results across agent configurations.
- **Memory persistence scoring folded in** rather than built as a separate tool. Persistence is an axis of injection effectiveness, not a standalone capability.
- **Ethics statement and responsible use policy ship with the tool.** This is offensive tooling — framing as defensive security testing (analogous to Metasploit, Burp Suite) is mandatory.
- **Cross-platform** — must run on Windows, macOS, and Linux. No platform-specific shell commands in source or test fixtures.

## Open Questions

- **Scoring methodology:** How to measure "injection success" consistently across different agent architectures? Binary (followed/didn't) vs. graded (full compliance, partial, refusal with leak, clean refusal)? Graded is more informative but harder to automate.
- **Agent interaction interface:** Does agent-inject control the agent directly (API calls to Claude, GPT, etc.) or does it only serve payloads and rely on external agent setups? Direct control is more repeatable but couples the tool to specific APIs. Leaning toward both — provide malicious servers that any agent can connect to, plus built-in test harnesses for major APIs.
- **Payload organization:** By technique (description poisoning, output injection, cross-tool) or by objective (exfiltration, privilege escalation, behavior modification)? Or both with cross-referencing?
- **Memory persistence testing:** Requires agents with persistent memory features. Which agents support this currently, and how to standardize the test methodology across different memory implementations?
- **CVE data consumption:** Should agent-inject read from mcp-audit's local CVE cache (JSON file) or query GitHub Advisory Database independently? Shared cache avoids duplication but creates a dependency on mcp-audit being installed. Independent queries add redundancy but keep tools decoupled. Decision deferred until development begins — see `counteragent/docs/github-advisory-integration.md`.

## Artifacts

- Injection campaign reports — technique × target matrix with success rates and evidence.
- Payload library — organized, documented, and tagged by technique, target, and OWASP category.
- Memory persistence decay curves — how injection effectiveness degrades over turns/sessions.
- Ready-to-deploy malicious MCP servers for reproducing specific attack scenarios.
- Responsible disclosure packages for novel bypasses discovered during testing.

## Relation to Other Tools

- **mcp-audit** tests server-side vulnerabilities. agent-inject tests client-side (agent) trust exploitation. mcp-audit might find that a server has no auth — agent-inject tests what an attacker can *do* through that open server.
- **mcp-proxy** operates at the protocol level. agent-inject operates at the semantic level — it cares about what the agent *does* with tool responses, not the wire format.
- **agent-chain** (Phase 3) composes agent-inject techniques into multi-step attack paths. agent-inject tests single-tool or single-interaction injection. agent-chain tests how injections cascade across agent architectures.
- **IPI-Canary** (Volery program) is the content-layer counterpart — it detects indirect prompt injection via document ingestion. agent-inject tests injection via tool outputs. Together they validate detection capabilities across different delivery mechanisms.

---

*This is a concept doc, not an architecture doc. It captures intent and constraints. The full Architecture doc gets written when development begins.*
