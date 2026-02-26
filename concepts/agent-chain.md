# agent-chain

> Multi-agent attack chain exploitation toolkit — full attack paths across agent architectures.

## Purpose

Phases 1 and 2 test individual components — a single MCP server, a single agent's trust in tool output. Phase 3 tests the *system*: how vulnerabilities compose when multiple agents collaborate, delegate tasks, and share context. A command injection in one tool, combined with excessive permissions on a delegated agent, combined with a RAG pipeline that trusts agent-written content, creates an attack chain far more dangerous than any individual flaw. No existing tool models or tests these composed attack paths. agent-chain makes multi-step agentic exploitation systematic, repeatable, and visible.

## Program Context

Phase 3 in the CounterAgent program. Consumes findings and techniques from both prior phases:
- mcp-audit (Phase 1) identifies server-level entry points
- agent-inject (Phase 2) provides single-step exploitation techniques
- agent-chain composes these into end-to-end attack paths and measures blast radius

This is the capstone tool — it demonstrates why individual vulnerabilities matter by showing what happens when they're chained together in realistic architectures.

## Core Capabilities

- Define multi-step attack chains declaratively — specify entry point, exploitation steps, and target outcome as structured sequences.
- Simulate agent architectures without requiring live production systems — model trust relationships, delegation patterns, and data flows.
- Ship pre-built chain templates for common architectures: RAG pipelines, multi-agent task delegation, MCP tool ecosystems, and hybrid setups.
- Reference real CVEs as chain entry points — pull known MCP vulnerabilities from GitHub Advisory Database to ground chain templates in actual exploitable conditions rather than hypothetical flaws.
- Measure blast radius — given a successful chain, quantify what the attacker can reach (data, systems, actions, persistence).
- Map exfiltration channels post-compromise — enumerate available paths (HTTP to allowlisted domains, DNS, tool-mediated file writes, rendering-based visual exfil) as part of blast radius analysis.
- Visualize attack chains — render the path from entry to impact for reports and presentations.
- Generate defensive playbooks from findings — each successful chain produces specific detection and mitigation recommendations.
- Generate detection rules (Sigma/Wazuh) from observed attack patterns.

## Key Design Decisions

- **Monorepo module** (`src/counteragent/chain/`). CLI: `counteragent chain`. Shares core models, transport, and evidence formats with audit, proxy, and inject modules.
- **Declarative chain definitions.** Attack chains are specified as data (YAML or similar), not imperative scripts. This makes them shareable, reproducible, and diffable.
- **Simulation-first, live-second.** The primary mode models agent architectures and traces attack paths through the model. Live execution against real agent setups is a secondary mode requiring explicit opt-in and isolation. This keeps the tool safe by default.
- **Exfil channel mapping is a blast radius module**, not a standalone tool. It answers "what can the attacker do after gaining access?" as part of the chain analysis.
- **Detection rule generation is a first-class output.** Every successful attack chain should produce at least one detection rule. This closes the loop back to the North Star: "If I can break it, I should be able to detect it."
- **Cross-platform** — must run on Windows, macOS, and Linux. No platform-specific shell commands in source or test fixtures.

## Open Questions

- **Architecture modeling format:** How to represent agent architectures (trust relationships, delegation patterns, data flows) in a way that's both expressive enough for real-world systems and simple enough to author? Graph-based? YAML declarations? Need to study how enterprise teams actually document their agent architectures.
- **Live execution safety:** When running chains against real agent setups, how to bound the blast radius of the test itself? Docker isolation is necessary but may not be sufficient for chains that involve network calls or cloud APIs. Need a "dry run" mode that traces the path without executing destructive steps.
- **Chain composability:** Should chains be built from reusable steps (like Metasploit modules) or defined as monolithic sequences? Reusable steps enable community contributions but add abstraction complexity.
- **Scope boundary with agent-inject:** Where does "single-step injection with multi-tool side effects" (agent-inject) end and "multi-step chain across agents" (agent-chain) begin? Needs a clear decision rule — likely: if it requires multiple agents or delegation hops, it's agent-chain.
- **Conference-ready output:** Phase 3 writeup targets Black Hat / DEF CON AI Village. What evidence format and visualization style is expected for conference submissions in this space?
- **Real CVE grounding:** Should chain templates reference specific CVE IDs as entry points (e.g., "start with CVE-2025-6514 mcp-remote command injection"), or use abstract vulnerability classes? Specific CVEs are more credible for conference submissions and bounty evidence, but chain templates become dated as CVEs are patched. Likely both — abstract classes for reusable templates, specific CVEs for demonstration chains. Advisory data from GitHub Advisory Database via `docs/github-advisory-integration.md`.

## Artifacts

- Attack chain definitions (declarative, shareable format).
- Chain execution reports — step-by-step trace with evidence at each stage.
- Blast radius analysis — what the attacker reached, through which path, with what permissions.
- Exfil channel inventory — available post-compromise channels with feasibility ratings.
- Attack chain visualizations — renderable diagrams for reports and presentations.
- Defensive playbooks — per-chain mitigation and detection recommendations.
- Detection rules (Sigma, Wazuh) generated from observed attack patterns.
- Research paper / conference submission material.

## Relation to Other Tools

- **mcp-audit** finds individual server vulnerabilities. agent-chain uses those as entry points in composed attack paths.
- **agent-inject** tests single-step agent exploitation. agent-chain tests what happens when injection techniques are chained across agents, tools, and data sources.
- **mcp-proxy** operates at the protocol level. agent-chain operates at the architecture level — it models how agents interact, not how individual messages flow.
- **Drongo** (Volery program) handles RAG retrieval poisoning. agent-chain may incorporate RAG poisoning as a step in broader chains but does not implement the retrieval optimization itself.

---

*This is a concept doc, not an architecture doc. It captures intent and constraints. The full Architecture doc gets written when development begins.*
