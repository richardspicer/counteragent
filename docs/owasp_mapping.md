# OWASP MCP Top 10 — Scanner Mapping

How `counteragent audit` maps to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) vulnerability taxonomy.

**OWASP MCP Top 10 Status:** Phase 3 Beta Release (as of early 2026)
**License:** CC BY-NC-SA 4.0
**Last reviewed:** 2026-02-22

---

## Coverage Overview

| OWASP ID | Vulnerability | Scanner Module | Status | Priority |
|----------|--------------|----------------|--------|----------|
| MCP01 | Token Mismanagement & Secret Exposure | `token_exposure.py` | ✅ Built (PR #23) | — |
| MCP02 | Privilege Escalation via Scope Creep | `permissions.py` | ✅ Built (PR #12) | — |
| MCP03 | Tool Poisoning | `tool_poisoning.py` | ✅ Built (PR #13) | — |
| MCP04 | Software Supply Chain Attacks | `supply_chain.py` | ✅ Built | Medium |
| MCP05 | Command Injection & Execution | `injection.py` | ✅ Built | — |
| MCP06 | Prompt Injection via Contextual Payloads | `prompt_injection.py` | ✅ Built (PR #14) | — |
| MCP07 | Insufficient Authentication & Authorization | `auth.py` | ✅ Built (PR #11) | — |
| MCP08 | Lack of Audit and Telemetry | `audit_telemetry.py` | ✅ Built (PR #15) | — |
| MCP09 | Shadow MCP Servers | `shadow_servers.py` | ✅ Built | Low |
| MCP10 | Context Injection & Over-Sharing | `context_sharing.py` | ✅ Built (PR #19) | — |

### Testability Split

Some categories are directly testable by an automated scanner. Others require agent-level
testing or manual assessment and are partially covered in Phase 1 with deeper coverage in later phases.

**Directly testable by counteragent audit:** MCP01, MCP02, MCP05, MCP06, MCP07, MCP08
**Partially testable (static analysis only):** MCP03, MCP04, MCP10
**Better suited for agent-inject / manual assessment:** MCP09

---

## Per-Category Detail

### MCP01: Token Mismanagement & Secret Exposure ✅ Built

**Scanner module:** `audit/scanner/token_exposure.py`

Hard-coded credentials, long-lived tokens, and secrets stored in model memory or protocol
logs. MCP systems enable long-lived sessions and context persistence, making the
model/protocol layer itself an unintentional secret repository.

**Current implementation:**

- **MCP01-001: Sensitive parameter names** — enumerate all tool schemas and flag parameters
  named `token`, `api_key`, `secret`, `password`, `credential`, `auth`, or similar.
- **MCP01-002: Secret patterns in tool responses** — call tools with benign inputs, scan
  responses for patterns matching API keys, JWTs, or bearer tokens. Regex targets: `eyJ`
  (JWT), `sk-` (OpenAI), `ghp_` (GitHub), `AKIA` (AWS), `xoxb-` (Slack), and others.
- **MCP01-003: Secrets in error responses** — trigger error paths and scan error messages
  for leaked credentials.
- **MCP01-004: Environment variable leakage** — check for leaked secrets in tool output or
  error messages.

Scanner type: Hybrid (static schema analysis + active tool calls).

**Related CVEs:** CVE-2025-6514 (mcp-remote — token in OAuth URL flow)

---

### MCP02: Privilege Escalation via Scope Creep ✅ Built

**Scanner module:** `audit/scanner/permissions.py`

Loosely defined permissions that expand over time, granting agents excessive capabilities.
Especially dangerous because agents act autonomously — an over-privileged agent can trigger
deployments or access sensitive data without human review.

**Current implementation:**

- **MCP02-001: Excessive tool count** — flag servers exposing more than 15 tools (surface
  area indicator).
- **MCP02-002: Dangerous capability analysis** — categorize tools by risk. Flag tools that
  perform shell execution, file writes, network requests, database operations, or
  credential management.
- **MCP02-003: Unconstrained parameters** — tools with string parameters that accept
  unbounded input without enumeration or pattern restrictions, especially for file paths,
  URLs, and commands.
- **MCP02-004: High write/execute ratio** — flag servers where write/execute tools
  significantly outnumber read-only tools.

Scanner type: Static analysis only (does NOT invoke tools).

**Cross-reference:** MCP01 + MCP02 = exponential impact. A stolen token with excessive
scopes can access far more resources than intended (Microsoft Azure Security Guide).

---

### MCP03: Tool Poisoning ✅ Built

**Scanner module:** `audit/scanner/tool_poisoning.py`

An adversary compromises tools, plugins, or their outputs to manipulate model behavior.
Sub-techniques include rug pulls (malicious updates to trusted tools), schema poisoning
(corrupting interface definitions), and tool shadowing (introducing fake or duplicate tools).

**Current implementation:**

- **MCP03-001: Embedded instructions** — scan descriptions for suspicious patterns: embedded
  instructions, `<IMPORTANT>` tags, social-engineering phrases, hidden directives.
  20 instruction regex patterns including MPMA preference manipulation.
- **MCP03-002: Hidden Unicode** — scan names and descriptions for zero-width characters,
  directional overrides, invisible formatters that could conceal malicious content.
- **MCP03-003: Homoglyph detection** — check tool names for Cyrillic, Greek, and other
  script characters that visually resemble ASCII (tool name spoofing).
- **MCP03-004: Description length anomaly** — flag descriptions over 500 characters that may
  hide embedded instructions in verbose text.
- **MCP03-005: Duplicate/shadowed tools** — Levenshtein similarity detection (threshold: 80%)
  across all tool names. Exact duplicates flagged as CRITICAL.

Scanner type: Static analysis only (does NOT invoke tools).

**Phase 2 coverage:** Dynamic tool poisoning testing moves to `agent-inject` where full
agent behavior can be observed.

**Related CVEs:** GPT-4.1 jailbreak via tool description poisoning (April 2025), Invariant
Labs WhatsApp exfiltration via malicious MCP server.

---

### MCP04: Software Supply Chain Attacks & Dependency Tampering

**Scanner module:** `audit/scanner/supply_chain.py` — Planned

Compromised dependencies altering agent behavior or introducing execution-level backdoors.
Includes trojanized plugins, registry compromise, dependency confusion via name collision,
and build pipeline tampering.

**Planned implementation:**

- **MCP04-001: Unidentified server** — check if the server reports a name and version during
  MCP initialization. Missing identity prevents vulnerability tracking, CVE matching, and
  provenance verification. Flag generic names ("unknown", "server", "mcp-server").
- **MCP04-002: Known vulnerable server version** — cross-reference server name and version
  against a static database of known MCP CVEs. Severity mapped from CVE CVSS score.
  Uses `packaging.version.Version` for semver comparison. Database ships with the scanner
  and is updated manually; planned `update-cves` CLI command will automate refresh via
  GitHub Advisory Database REST API.
- **MCP04-003: Outdated MCP protocol version** — check `protocolVersion` against the current
  stable MCP protocol version. Older versions may lack security features.
- **MCP04-004: Tool namespace confusion** — compare tool names against a registry of
  well-known tools mapped to expected server identities. Flag tools whose names match
  well-known tools but come from a different server identity — indicates potential dependency
  confusion or impersonation attack.

Scanner type: Hybrid (static metadata analysis + active checks).

**CVE data source:** GitHub Advisory Database (preferred over NVD for MCP-specific
advisories). See `counteragent/docs/github-advisory-integration.md` for the cross-tool
advisory integration strategy.

**Related attack patterns:** Koi Security npm Postmark impersonation (malicious MCP package
BCC'd emails to attacker), dual reverse shell MCP packages (install-time + runtime triggers).

**Attack chain role:** MCP04 delivers MCP03, which enables MCP05 (supply chain → tool
poisoning → command injection).

---

### MCP05: Command Injection & Execution ✅ Built

**Scanner module:** `audit/scanner/injection.py`

AI agent constructs and executes system commands using untrusted input without proper
validation. Analogous to classic injection (XSS, SQLi) but the interpreter is the model and
the payload is natural language.

**Current implementation:**

- 11 payloads (7 Unix + 4 Windows) covering `;`, `|`, `&&`, `||`, command substitution,
  newline injection.
- Canary-based detection (`MCP_AUDIT_CANARY_7f3a9b2e`).
- False-positive guard (rejects findings where full payload is reflected verbatim).
- Breaks after first confirmed injection per parameter.

**Planned enhancements based on CVE patterns:**

- `exec`/`execFile` detection payloads targeting Node.js servers using `child_process.exec`
  with `shell: true`.
- URL-based injection payloads mirroring CVE-2025-6514 (OAuth URL parameter injection).
- Windows PowerShell `$(...)` subexpression evaluation payloads.
- Pipe command payloads for data exfiltration chains.
- Timing-based detection for blind injection (`sleep`/`timeout` payloads).

**Related CVEs:**

| CVE | Component | CVSS | Root Cause |
|-----|-----------|------|------------|
| CVE-2025-6514 | mcp-remote | 9.6 | OS command injection via crafted OAuth `authorization_endpoint` URL |
| CVE-2025-49596 | MCP Inspector | 9.4 | Unauthenticated stdio command execution via proxy |
| CVE-2025-53967 | figma-developer-mcp | Critical | `child_process.exec` with unsanitized URL input |
| CVE-2025-5277 | aws-mcp-server | — | Command injection via crafted prompts to `cli_executor.py` |

---

### MCP06: Prompt Injection via Contextual Payloads ✅ Built

**Scanner module:** `audit/scanner/prompt_injection.py`

Untrusted content containing hidden instructions that influence agent behavior. In MCP
systems, agents merge retrieved context with instruction templates before invoking tools.
If retrieved context is not treated as untrusted data, attackers can embed imperative
instructions.

**Current implementation:**

- **MCP06-001: Injection patterns in tool responses** — calls each tool with benign inputs,
  scans returned content for 20+ injection patterns: XML instruction tags, override
  directives, role reassignment, exfiltration directives, concealment language, behavioral
  overrides, system prompt extraction attempts.
- **MCP06-002: Hidden Unicode in responses** — zero-width characters, directional overrides,
  invisible formatters that could conceal injected instructions.
- **MCP06-003: Suspicious URLs in responses** — URL detection with allowlist filtering.
  External URLs in tool responses may be exfiltration targets when combined with injection
  directives.
- **MCP06-004: Cross-tool manipulation** — detects when a tool's response references other
  tools by name combined with behavioral directive language (e.g., "now call tool_X").
- **MCP06-005: Anomalous response length** — flag responses over 2000 characters that may
  hide injected instructions within verbose output.

Scanner type: Active (calls tools with benign inputs, analyzes responses).

**Phase 2 coverage:** Full prompt injection effectiveness testing (success rate measurement
across agent configurations) moves to `agent-inject`.

---

### MCP07: Insufficient Authentication & Authorization ✅ Built

**Scanner module:** `audit/scanner/auth.py`

MCP servers that fail to properly verify identities or enforce access controls.
CVE-2025-49596 is the poster child: MCP Inspector proxy accepted arbitrary stdio commands
without authentication and bound to `0.0.0.0` by default. 560+ exposed instances were
found on Shodan.

**Current implementation:**

- **MCP07-001: Unauthenticated enumeration** — connected without credentials and discovered
  tools/resources/prompts. Escalates to HIGH if sensitive tools (shell, database, credential
  management) are exposed. Uses keyword-based tool sensitivity classification.
- **MCP07-002: Unauthenticated tool invocation** — calls the first available tool without
  credentials. Escalates to CRITICAL if the tool handles sensitive operations.
- **MCP07-003: Transport encryption** — checks HTTP-based transports for TLS. Flags
  unencrypted HTTP connections that expose tokens and tool arguments.
- **MCP07-004: Well-known port detection** — flags servers on known MCP ports (6274, 6277,
  3001) without authentication. These ports are targeted by automated scanners.

Scanner type: Active (connects without auth, attempts tool calls, analyzes transport).

**Cross-reference:** MCP07 is foundational. Proper auth validates tokens (MCP01), enforces
least privilege (MCP02), and prevents cross-tenant leakage (MCP10). (Microsoft Azure
Security Guide)

**Related CVEs:** CVE-2025-49596 (MCP Inspector — no auth, 0.0.0.0 binding, CSRF via
browser)

**Planned enhancements:**

- CORS configuration audit — check for `Access-Control-Allow-Origin: *`
- Origin validation — send requests with spoofed origin headers
- Session management — check if server issues/expires session tokens
- Binding detection — detect if server binds to `0.0.0.0` vs `127.0.0.1`

---

### MCP08: Lack of Audit and Telemetry ✅ Built

**Scanner module:** `audit/scanner/audit_telemetry.py`

Without comprehensive logging and alerting, unauthorized actions go undetected. MCP08 makes
all other risks harder to detect (Microsoft Azure Security Guide).

**Current implementation:**

- **MCP08-001: Missing server identification** — checks if the server provides a name and
  version in its initialization response. Without identification, asset management and
  vulnerability tracking are impaired.
- **MCP08-002: Error information disclosure** — calls tools with error-triggering inputs
  (type mismatches, boundary values) and scans error responses for stack traces, file paths,
  SQL queries, database errors, and internal implementation details.
- **MCP08-003: No logging capability** — checks if the server advertises MCP logging
  capability or exposes logging-related resources.
- **MCP08-004: Sensitive data in errors** — scans error responses for auth tokens, email
  addresses, IP addresses, private keys, and API key patterns.
- **MCP08-005: Missing protocol version** — checks if the server reports `protocolVersion`
  in initialization.

Scanner type: Hybrid (static metadata checks + active error triggering).

---

### MCP09: Shadow MCP Servers

**Scanner module:** `audit/scanner/shadow_servers.py` — Planned

Unapproved MCP server deployments operating outside formal security governance. The MCP
equivalent of Shadow IT.

**Planned testing approach:**

- **Network scanning mode** — scan for common MCP ports and endpoints.
- **Default configuration detection** — flag default settings: no auth, binding to `0.0.0.0`,
  default ports.
- **Server fingerprinting** — identify MCP server implementations by initialization
  responses.

**Note:** Low priority for Phase 1. This is more of a network scanning concern than a
per-server audit. May be better suited to a standalone utility or integration with existing
network scanners.

**Fingerprinting reference:** Recorded Future Nuclei template for CVE-2025-49596 detection:
- Vulnerable: `GET /sse?transportType=stdio&command=echo&args=TEST` → 200 OK with `/message?sessionId=`
- Patched: 401 Unauthorized with "Authentication required"

---

### MCP10: Context Injection & Over-Sharing ✅ Built

**Scanner module:** `audit/scanner/context_sharing.py`

Context windows that are shared, persistent, or insufficiently scoped, causing information
leakage between sessions, agents, or users.

**Current implementation:**

- **MCP10-001: Excessive context in tool responses** — flags tools where response/input ratio
  exceeds 50x with 500+ char responses.
- **MCP10-002: Session data in tool responses** — detects session_id, request_id, trace_id,
  worker_id patterns in tool responses.
- **MCP10-003: Error context leakage** — triggers errors and checks for leaked session data
  and credentials.
- **MCP10-004: Resource over-exposure** — static check for resources without
  user/session/tenant scoping in URI/name/description.
- **MCP10-005: Sensitive data in resources** — reads resources and scans for passwords,
  API keys, PII, connection strings (escalates to HIGH for credentials).

Scanner type: Hybrid (static analysis of resources + active tool calls).

**Planned enhancements:**

- Session isolation test — connect with two sessions, check for data leakage between them.
- Context persistence check — disconnect and reconnect, check if server retains previous
  context.

---

## Attack Chain Relationships

Categories don't exist in isolation. The OWASP MCP Top 10 categories compose into attack
chains (informed by the Microsoft Azure Security Guide for MCP):

```
MCP04 (Supply Chain) → delivers → MCP03 (Tool Poisoning) → enables → MCP05 (Command Injection)

MCP01 (Token Leak) + MCP02 (Excessive Scope) = Exponential impact

MCP07 (Weak Auth) = Foundational — validates tokens (MCP01),
                     enforces least privilege (MCP02),
                     prevents cross-tenant leakage (MCP10)

MCP08 (No Telemetry) = All other risks become harder to detect

MCP09 (Shadow Servers) = Bypass all centralized security policies
```

These chains inform testing priority. MCP07 (auth) is the foundation — if auth is broken,
MCP01, MCP02, and MCP10 weaknesses become directly exploitable.

---

## CVE Reference

Known CVEs mapped to OWASP MCP Top 10 categories:

| CVE | CVSS | Component | OWASP Category | Summary |
|-----|------|-----------|----------------|---------|
| CVE-2025-6514 | 9.6 | mcp-remote v0.0.5–v0.1.15 | MCP05, MCP01 | OS command injection via crafted OAuth URL |
| CVE-2025-49596 | 9.4 | MCP Inspector < 0.14.1 | MCP07, MCP05 | Unauthenticated RCE via stdio proxy |
| CVE-2025-53967 | Critical | figma-developer-mcp | MCP05 | `child_process.exec` injection via unsanitized URL |
| CVE-2025-5277 | — | aws-mcp-server | MCP05 | Command injection via crafted prompts |
| CVE-2025-53110 | 7.3 | Anthropic Filesystem MCP | MCP02 | Directory containment bypass via prefix tricks |
| CVE-2025-53109 | 8.4 | Anthropic Filesystem MCP | MCP02, MCP05 | Symlink bypass enabling arbitrary file access and code execution |

---

## References

- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [OWASP Top 10 for Agentic AI](https://owasp.org/www-project-top-10-for-agentic-ai/)
- [Microsoft Azure: MCP Security Guidance](https://learn.microsoft.com/en-us/azure/ai-services/agents/concepts/model-context-protocol-security)
- [MITRE ATLAS](https://atlas.mitre.org/) — adversarial ML technique mapping
- [NIST AI RMF](https://www.nist.gov/artificial-intelligence/risk-management-framework) — risk management context
