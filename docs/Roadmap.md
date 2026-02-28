## Vision
An offensive security suite for Agentic AI — a complete research program and toolkit for testing attack chains targeting autonomous AI agents, with proof-of-exploitation and practical defensive guidance.

---
## Ecosystem Context

CounterAgent is the **protocol & system** arm of the Agentic AI Security ecosystem under [richardspicer.io](https://richardspicer.io). It tests MCP servers, tool trust boundaries, and agent delegation chains.

The **[CounterSignal](https://github.com/richardspicer/countersignal)** program (IPI, CXP, RXP) is the sister program handling **content & supply chain** — indirect prompt injection detection, coding assistant context poisoning, and RAG retrieval poisoning.

---
## The Problem
- AI agents are being deployed with access to tools, data, and systems — often with excessive trust
- MCP adoption is exploding (Claude, ChatGPT, Cursor, Gemini, VS Code) but security tooling hasn't kept pace
- 43% of tested MCP implementations contain command injection flaws
- Only 6% of organizations have an advanced AI security framework
- There is almost no open source offensive tooling purpose-built for agentic AI security testing
- Current tools (Garak, PyRIT) focus on LLM output analysis, not agent action exploitation

### Competitive Landscape

| Tool | Approach | CounterAgent Differentiator |
|------|----------|---------------------------|
| Garak (NVIDIA) | LLM vulnerability scanning, output analysis | Tests agent infrastructure, not just models |
| PyRIT (Microsoft) | Multi-turn red teaming | Maps to OWASP MCP Top 10, tests MCP protocol |
| Invariant MCP-Scan | CLI scanner for tool description attacks | Full OWASP MCP Top 10 coverage, not just tool descriptions |
| ScanMCP.com | Cloud-based scanner + dashboard | Open source, local execution, SARIF for CI/CD |
| Equixly CLI | Commercial MCP security testing | Free and community-extensible |
| MCP Guardian (EQTY Lab) | Runtime security proxy | Complementary — guardian is runtime, counteragent audit is pre-deployment |
| Levo MCP Security | Enterprise platform | Open source alternative |
| Docker MCP Toolkit | Secure distribution (containerized) | Complementary — Docker solves deployment, counteragent audit audits code |

## The Solution
Four tools, building progressively: audit MCP servers → manually explore findings → test agent trust boundaries → chain vulnerabilities into full attack paths.

---
## Phase 1: MCP Security Auditor (v1.0) — `counteragent audit`

> **Status:** Migrated into the counteragent monorepo as `src/counteragent/audit/`. CLI: `counteragent audit ...`

### Scope
- Automated scanner auditing MCP server implementations against the OWASP MCP Top 10
- Connect to servers via stdio, SSE, and Streamable HTTP transports
- Enumerate server capabilities (tools, resources, prompts)
- Test for each OWASP MCP Top 10 vulnerability category
- Generate machine-readable (SARIF, JSON) and human-readable (HTML) reports

### OWASP MCP Top 10:2025 — Target Coverage

| # | Vulnerability | Scanner Coverage | Priority |
|---|--------------|-----------------|----------|
| MCP01 | Token Mismanagement & Secret Exposure | Automated — scan for hardcoded creds, long-lived tokens in config/logs | High |
| MCP02 | Privilege Escalation via Scope Creep | Automated — enumerate permissions, flag excessive tool access | High |
| MCP03 | Tool Poisoning | Semi-automated — detect suspicious tool descriptions, metadata anomalies | High |
| MCP04 | Supply Chain Attacks & Dependency Tampering | Automated — dependency audit, signature verification checks | Medium |
| MCP05 | Command Injection & Execution | Automated — injection payload testing against tool inputs | Critical |
| MCP06 | Prompt Injection via Contextual Payloads | Semi-automated — test tool outputs for injection patterns | High |
| MCP07 | Insufficient Authentication & Authorization | Automated — probe auth requirements, test unauthorized access | Critical |
| MCP08 | Lack of Audit and Telemetry | Configuration audit — check logging capabilities and coverage | Medium |
| MCP09 | Shadow MCP Servers | Detection heuristics — identify undocumented/rogue server instances | Medium |
| MCP10 | Context Injection & Over-Sharing | Semi-automated — test for context leakage between sessions/agents | High |

### Deliverables
- MCP client library (stdio, SSE, Streamable HTTP transports)
- Server capability enumeration
- Modular scanner with one module per OWASP MCP Top 10 category
- Payload library for injection and SSRF testing
- Schema-derived adversarial payloads — auto-generate CWE-mapped payloads from tool JSON schemas (`src/counteragent/audit/payloads/schema_derived.py`)
- Fingerprinting in `enumerate` — framework signatures, auth detection, known CVE matching (`src/counteragent/core/discovery.py`)
- SARIF, JSON, and HTML report generation
- CVSS-aligned severity scoring
- CLI: scan, report, list-checks
- CLI: update-cves — refresh local CVE database from GitHub Advisory Database REST API (planned, post-10/10 scanner completion)
- Intentionally vulnerable MCP server fixtures for validation
- Test harness for scanner accuracy

### Key Design Decisions
- **SARIF output** — enables integration with GitHub Advanced Security, VS Code, and CI/CD pipelines
- **Intentionally vulnerable test servers** — ship fixtures exhibiting each OWASP category for validation and training
- **CVSS-aligned severity scoring** — real-world severity, not arbitrary labels
- **Modular scanner architecture** — each check is self-contained, community contributors can add checks independently
- **No mystery cruft** — clean pyproject.toml, no daemons, no background services
- **GitHub Advisory Database as CVE source** — preferred over NVD for MCP CVE freshness (advisories published before NVD ingestion), GHSA-only coverage, structured version/patch data, and no auth required. Design note: `docs/github-advisory-integration.md`

### Phase 1 Writeup
**Title:** "Auditing MCP Servers Against the OWASP Top 10: Findings from Scanning [N] Public Implementations"
**Publish to:** richardspicer.io + cross-post to Medium
**CVE/Bug Bounty:** Responsible disclosure for any novel vulnerabilities. Even one CVE dramatically elevates credibility.

---
## Phase 1.5: Interactive MCP Traffic Interceptor — `counteragent proxy`

> **Status:** Migrated into the counteragent monorepo as `src/counteragent/proxy/`. CLI: `counteragent proxy ...`. Architecture docs in [`docs/Architecture.md`](docs/Architecture.md).

### Concept
`counteragent audit` is an automated scanner — it runs predefined checks and produces a report. But when bounty hunting against a real MCP server, you need to see what the client is sending, what the server returns, and modify payloads on the fly. `counteragent proxy` provides the Burp Suite equivalent for MCP traffic: a man-in-the-middle proxy that understands JSON-RPC semantics across all three MCP transports.

### Why Proxy Is a Separate Module from Audit
- Fundamentally different UX: interactive proxy with inspect/modify/replay vs. automated scan-and-report
- Different use pattern: `counteragent audit` runs, produces a report, done. `counteragent proxy` stays running while you manually test
- Audit findings feed into proxy sessions — "scan found a possible injection in tool X, now manually explore it"

### Core Capabilities
- Proxy stdio, SSE, and Streamable HTTP MCP transports
- Log all JSON-RPC messages with timestamps and direction
- Intercept mode: pause on each message, allow modification before forwarding
- Replay mode: re-send captured tool calls with modified arguments
- Filter/search by tool name, method, or content pattern
- Export session as JSON for evidence capture

### Implementation Approach
Lightweight Python CLI with TUI (Textual or similar). Not a full GUI — this is a terminal tool for researchers. The proxy core is a pass-through that can hook into the message stream.

### Deliverables
- Proxy core supporting all three MCP transports
- Intercept and replay modes
- TUI for interactive research workflows
- Session export (JSON) for bounty evidence
- CLI: proxy, replay, export

### Phase 1.5 Writeup
**Title:** "Manual MCP Security Testing: Finding Logic Bugs That Scanners Miss"
**Target:** richardspicer.io + bounty submission evidence

---
## Phase 2: Tool Poisoning & Prompt Injection Framework (v2.0) — `counteragent inject`

> **Planned:** Will be added as `src/counteragent/inject/` module. CLI: `counteragent inject ...`

### Concept
Phase 1 tests the MCP *servers*. Phase 2 tests what happens when an agent *trusts* the output from those servers. A tool that passes basic security checks but returns carefully crafted output designed to manipulate agent behavior.

### Real-World Precedent
- Supabase Cursor agent breach — SQL instructions in support tickets executed by AI agent
- AgentFlayer attacks (Black Hat 2025) — zero-click exploitation via rogue prompts
- Adversarial tool descriptions hijacking agent behavior across ChatGPT, Gemini, Copilot

### Capabilities
- **Tool description poisoning** — embedded instructions in MCP tool metadata
- **Output injection payloads** — tool responses containing prompt injection targeting the calling agent
- **Cross-tool escalation** — one tool's output manipulates agent into misusing a different tool
- **Payload library** — organized by target (Claude, ChatGPT, Copilot, open-source) and technique
- **Advisory-informed payload design** — reference real MCP CVEs from GitHub Advisory Database to ground payload templates in actual vulnerability patterns
- **Effectiveness scoring** — automated measurement of injection success rates

### Deliverables
- Malicious MCP server that serves configurable payloads
- Payload templating system
- Effectiveness detection and scoring engine
- Memory persistence scoring — persistence half-life metrics for injected behaviors across turns and sessions in agents with memory features
- CLI for running injection campaigns against test targets
- Report generation
- Ready-to-deploy malicious MCP servers for testing
- Ethics statement and responsible use policy

### Cross-Tool Integration ([Mutual Dissent](https://github.com/q-uestionable-AI/mutual-dissent))
The inject module's multi-vendor payload testing (Anthropic, OpenAI, Gemini,
Grok) overlaps with Mutual Dissent's provider routing and transcript capture.
Rather than building parallel API integration, inject should consume Mutual
Dissent's provider abstraction for cross-model effectiveness testing. Mutual
Dissent's per-panelist context injection (scaffolded as a Phase 3 prerequisite)
enables injecting tool-poisoning payloads into specific panelists and observing
propagation through reflection rounds. Effectiveness scoring maps to Mutual
Dissent's `--ground-truth` mechanism.

### Phase 2 Writeup
**Title:** "Tool Poisoning in the Wild: How Malicious MCP Servers Can Hijack AI Agents"
**Framing:** Defensive security testing tooling (Metasploit/Burp Suite positioning)

---
## Phase 3: Agent Chain Exploitation (v3.0) — `counteragent chain`

> **Planned:** Will be added as `src/counteragent/chain/` module. CLI: `counteragent chain ...`

### Concept
Phases 1 and 2 test individual components. Phase 3 tests the *system* — how vulnerabilities compose when multiple agents collaborate, delegate tasks, and share context.

### Research Areas
**Agent-to-Agent Exploitation:**
- Compromising one agent to manipulate others in multi-agent systems
- Exploiting trust relationships between agents
- Cascading privilege escalation across delegation chains
- "Confused deputy" attacks on privileged agents
- Referencing real CVEs as chain entry points via GitHub Advisory Database integration

**Data Pipeline Poisoning:**
- Injecting malicious content into RAG knowledge bases
- Poisoning vector databases to influence agent decisions
- Manipulating agent memory/context windows

**Autonomous Action Abuse:**
- Tricking agents into unintended actions (file writes, API calls, code execution)
- Exploiting agent access to external systems
- Lateral movement from a single compromised tool

### Deliverables
- Attack chain builder — declarative multi-step exploitation sequences
- Agent interaction simulator — model architectures without live production systems
- Chain templates — pre-built chains for common architectures (RAG, multi-agent, MCP tools)
- Blast radius analysis — measure impact of successful chains
- Exfil channel mapping — post-compromise channel enumeration (HTTP to allowlisted domains, DNS, tool-mediated writes, rendering-based visual exfil) as part of blast radius analysis
- Attack chain visualization
- Defensive playbook generated from findings
- Detection rule generation

### Cross-Tool Integration ([Mutual Dissent](https://github.com/q-uestionable-AI/mutual-dissent))
The chain module plans a "multi-agent simulation environment" and "data pipeline
poisoning" capabilities. Mutual Dissent's orchestrator with per-panelist context
injection provides the multi-model observation platform for these experiments —
specifically, testing whether RAG-poisoned models propagate tainted content to
clean models through reflection rounds. Building a separate simulation
environment would duplicate Mutual Dissent's provider routing, fan-out, and
transcript infrastructure. Blast radius analysis and exfil channel mapping
can consume Mutual Dissent transcripts with experiment metadata for cross-tool
correlation.

### Phase 3 Writeup
**Title:** "Anatomy of an Agentic AI Attack Chain: From Tool Poisoning to Lateral Movement"
**Target:** Security architects, CISOs, AI platform teams
**Conference submission:** Black Hat, DEF CON AI Village, BSides, OWASP AppSec

---
## Pre-Release Security Review (before each tool release)

### Static Analysis (SAST)
- `bandit` — Python security linter
- `semgrep` — custom rules for project patterns
- Run in CI on every PR

### CI Testing Matrix
- Cross-platform: `ubuntu-latest` + `windows-latest`
- Python versions: `["3.11", "3.13", "3.14"]` — floor, near-ceiling, and forward-compatibility
- `requires-python = ">=3.11"` means the floor must always be tested

### Dependency Scanning
- `pip-audit` — check against PyPI advisory database
- GitHub Dependabot for ongoing monitoring

### Manual Review Focus
| Area | Check |
|------|-------|
| Path operations | Output paths constrained, no traversal |
| URL validation | Target URLs validated, blocking where appropriate |
| Input handling | All user inputs sanitized |
| Error handling | No sensitive data in error messages |

### Exit Criteria
- Zero high/critical findings from SAST
- No known CVEs in dependencies
- SECURITY.md documents trust boundaries and limitations

---
## Cross-Phase: Ongoing Activities

### Vulnerability Research & Disclosure
- Continuously test public MCP server implementations
- Monitor MCP spec changes for new attack surface
- Responsible disclosure pipeline — document, report, wait for fix, then publish
- Track and catalog CVEs related to agentic AI — monthly review via GitHub Advisory Database REST API with NVD and OWASP cross-reference (see `docs/github-advisory-integration.md`)

### Community & Visibility
- richardspicer.io blog — phase writeups + shorter posts on individual findings
- GitHub — well-documented repos, contribution guides, issue templates
- OWASP engagement — contribute findings back to MCP Top 10 and Agentic AI Top 10
- LinkedIn — quality posts on key findings

### Framework Mapping

| Framework | Usage |
|-----------|-------|
| OWASP MCP Top 10 | Primary vulnerability taxonomy for Phase 1 |
| OWASP Top 10 for Agentic AI | Attack pattern classification for Phases 2-3 |
| OWASP Top 10 for LLM Applications 2025 | Cross-reference for LLM-specific findings |
| MITRE ATLAS | Adversarial ML technique mapping |
| NIST AI RMF | Risk management context |
| NIST Cybersecurity Framework Profile for AI (NISTIR 8596) | Defensive recommendation alignment |

---
## Success Metrics

### Phase 1 Success
- counteragent audit scans a live MCP server and produces a SARIF report
- At least 5 OWASP MCP Top 10 categories have working scanner modules
- Tool validates against intentionally vulnerable fixtures

### Phase 1.5 Success
- `counteragent proxy` intercepts and displays live MCP traffic across all three transports
- Intercept mode allows modification of in-flight JSON-RPC messages
- Replay mode re-sends captured tool calls with modified arguments
- Session export produces JSON evidence suitable for bounty submissions

### Phase 2 Success
- The inject module delivers payloads that successfully manipulate agent behavior
- Effectiveness scoring produces measurable results across 3+ agent configurations
- Responsible disclosure for any novel bypasses

### Phase 3 Success
- At least 3 documented novel attack chains
- Defensive playbook generated from findings
- Conference CFP submission (stretch goal)

### Portfolio Success
- 50+ GitHub stars on counteragent within 3 months
- At least one responsible disclosure accepted
- Project referenced in job applications and interviews

---
## Reference Links
- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
- OWASP Top 10 for Agentic AI: https://genai.owasp.org/
- MCP Specification: https://modelcontextprotocol.io/
- MCP Python SDK: https://github.com/modelcontextprotocol/python-sdk
- FastMCP: https://gofastmcp.com/
- MITRE ATLAS: https://atlas.mitre.org/
- Garak: https://github.com/NVIDIA/garak
- PyRIT: https://github.com/Azure/PyRIT
