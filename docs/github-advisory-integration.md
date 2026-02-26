# GitHub Advisory Database Integration Strategy

> Cross-tool design note for the CounterAgent program. Lives in `counteragent/docs/`.

## Decision

Use the **GitHub Advisory Database REST API** as the primary CVE/advisory feed for CounterAgent tools, replacing the originally planned NVD API (nvdlib) approach.

## Why GitHub Advisory Database Over NVD

| Factor | GitHub Advisory DB | NVD (nvd.nist.gov) |
|--------|-------------------|---------------------|
| **MCP CVE freshness** | Published first — MCP advisories appear here before NVD ingests them | Delayed — NVD processing backlog is well-documented |
| **Coverage** | Superset — includes GHSA-only advisories that may never get CVE IDs | CVEs only |
| **Structured version data** | Affected version ranges + patched versions per ecosystem (npm, pip) | Often missing or less structured |
| **Authentication** | None required for public advisories | API key required for reasonable rate limits |
| **Query interface** | REST API with keyword search, ecosystem filter, severity filter | REST API with keyword search (nvdlib wrapper) |
| **Rate limits** | Generous for unauthenticated (60 req/hr), higher with PAT | 5 req/30s without key, 50 req/30s with key |
| **Ecosystem tagging** | Native — advisories tagged by npm, pip, etc. | CPE-based — more complex to query by ecosystem |

## API Reference

**Endpoint:** `GET https://api.github.com/advisories`

**Key parameters:**
- `keyword` — free text search (e.g., "MCP", "Model Context Protocol")
- `ecosystem` — filter by package ecosystem (npm, pip, etc.)
- `severity` — filter by severity level
- `type` — "reviewed" (GitHub-reviewed) or "malware"
- `updated` — filter by last updated date (ISO 8601)
- `per_page` — results per page (max 100)

**Response includes:** GHSA ID, CVE ID (if assigned), summary, description, severity, CVSS score, affected package versions, patched versions, references, published/updated dates.

**Docs:** https://docs.github.com/en/rest/security-advisories/global-advisories

**No authentication required** for read-only access to public advisories. A GitHub PAT increases rate limits but is not mandatory.

## Tools That Benefit

### mcp-audit (Phase 1) — Primary Consumer
- **MCP04-002 (Known Vulnerable Server Version):** Static CVE dict ships with the scanner. `update-cves` CLI command refreshes from GitHub Advisory DB.
- **Enumerate fingerprinting:** Planned enhancement to match scanned servers against known CVEs during `mcp-audit enumerate`.
- **Implementation:** First tool to build the integration. Query logic lives in mcp-audit initially.

### inject (Phase 2) — Attack Pattern Reference
- **Payload design:** Real CVE data informs realistic attack scenarios. Knowing which MCP servers have command injection flaws (the dominant pattern) guides payload templates.
- **Campaign targeting:** When building injection campaigns, reference actual vulnerable server versions as realistic test targets.
- **Implementation:** Read from the same advisory data format. May share a JSON cache file or query independently.

### chain (Phase 3) — Chain Entry Points
- **Chain templates:** Pre-built attack chains can reference real CVEs as entry points (e.g., "start with CVE-2025-6514 mcp-remote command injection, escalate to...").
- **Blast radius analysis:** Cross-reference target architecture against known CVEs to estimate realistic attack surface.
- **Implementation:** Consume advisory data as input to chain definitions.

### Program-Level — Ongoing Vulnerability Research
- **CVE tracking:** The CounterAgent Roadmap's "Track and catalog CVEs related to agentic AI" activity maps directly to periodic GitHub Advisory DB queries.
- **Research Log enrichment:** Monthly CVE review process pulls from this feed, results go in the Research Log.
- **OWASP mapping updates:** New CVEs inform updates to `docs/owasp_mapping.md` in mcp-audit.

## Tools That Don't Need It

- **mcp-proxy** — Protocol-level interception. Doesn't assess server identity.
- **IPI-Canary** — Document-based prompt injection. Different attack surface entirely.
- **CXP-Canary** — Coding assistant context files. Not MCP server CVEs.
- **Drongo** — RAG retrieval optimization. No CVE relevance.

## Implementation Plan

### Phase 1: Static Dict (ships with mcp-audit supply_chain scanner)
- Hand-curated CVE entries in module code
- No external dependencies, no API calls
- Reviewed and updated manually (monthly cadence + ad-hoc when CVEs appear)

### Phase 2: `mcp-audit update-cves` CLI Command
- Query GitHub Advisory DB REST API for MCP-related advisories
- Parse and merge into local JSON cache file
- CLI: `mcp-audit update-cves [--since YYYY-MM-DD]`
- Dependencies: httpx (already used by MCP SDK) or stdlib urllib
- No authentication required — document PAT option for higher rate limits
- **Build after 10/10 scanner completion**

### Phase 3: Cross-Tool Advisory Cache (when inject module development starts)
- Evaluate whether to extract advisory fetching into a shared utility
- Decision criteria: Is the same data used by 2+ tools? Is the query pattern identical?
- Avoid premature abstraction — replicate the pattern first, extract when the duplication is real
- Shared format: JSON file with standardized schema that any tool can read

## Monthly CVE Review Process

Recurring Kanban item (already planned):

1. Query GitHub Advisory Database: `https://github.com/advisories?query=MCP`
2. Search NVD: keyword "MCP" and "Model Context Protocol"
3. Check OWASP MCP Top 10 exploit tracker for newly cited CVEs
4. For each new CVE:
   - Add to mcp-audit static CVE dict (fix/ branch)
   - Log in Research Log with OWASP mapping
   - If significant, create Findings/ doc
5. Quarterly cadence is the safety net; ad-hoc updates when CVEs appear in security feeds

## Interesting Find

Microsoft published a **GitHub Advisory MCP Server** (`microsoft/github-advisory-mcp`) that queries a local clone of the advisory database via MCP tools. This validates the GitHub Advisory Database as the right source for MCP vulnerability data — Microsoft's own security team chose it over NVD for this use case.

---

*Created: 2026-02-22. Update when Phase 2 implementation begins.*
