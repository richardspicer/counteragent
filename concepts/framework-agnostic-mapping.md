# Concept: Framework-Agnostic Vulnerability Mapping

**Status:** Approved
**Date:** 2026-02-25
**Scope:** Cross-cutting refactor — affects core, audit, and future modules

---

## Problem

CounterAgent currently hardcodes OWASP MCP Top 10 identifiers (`MCP01`–`MCP10`) into scanner class attributes, Finding construction, rule IDs, CLI output, and documentation. When OWASP updates or renumbers the MCP Top 10 (currently in Phase 3 beta), every scanner module, test assertion, and doc reference must change.

Additionally, multiple relevant frameworks now exist:

- **OWASP MCP Top 10** (2025-beta) — protocol-level MCP vulnerabilities
- **OWASP Top 10 for Agentic Applications** (2026, ASI01–ASI10) — autonomous agent behavior risks
- **MITRE ATLAS** — adversarial ML technique taxonomy
- **CWE** — weakness enumeration (already partially used in injection scanner)
- **NIST CAISI** — AI agent security guidance (RFI open, standards forthcoming)
- **NIST Cyber AI Profile** (NISTIR 8596) — CSF 2.0 mapped to AI concerns

Phase 2 (agent-inject) and Phase 3 (agent-chain) will produce findings that map to the Agentic Top 10 rather than the MCP Top 10. The current architecture can't express that.

## Design

### Stable Internal Taxonomy

Each scanner gets a `category` string that is CounterAgent's own identifier. This never changes regardless of external framework updates.

```python
class InjectionScanner(BaseScanner):
    name = "injection"
    category = "command_injection"    # stable — replaces owasp_id = "MCP05"
    description = "Tests for command injection via MCP tools"
```

Category values are short, descriptive, snake_case strings: `command_injection`, `auth`, `token_exposure`, `permissions`, `tool_poisoning`, `prompt_injection`, `audit_telemetry`, `supply_chain`, `shadow_servers`, `context_sharing`. Future phases add new categories as needed (e.g., `goal_hijack`, `agent_delegation_abuse`).

### Framework Mapping Data File

A YAML file in `src/counteragent/core/data/frameworks.yaml` maps categories to external frameworks, versioned:

```yaml
frameworks:
  owasp_mcp_top10:
    version: "2025-beta"
    url: "https://owasp.org/www-project-mcp-top-10/"
    mappings:
      command_injection: "MCP05"
      auth: "MCP07"
      token_exposure: "MCP01"
      permissions: "MCP02"
      tool_poisoning: "MCP03"
      supply_chain: "MCP04"
      prompt_injection: "MCP06"
      audit_telemetry: "MCP08"
      shadow_servers: "MCP09"
      context_sharing: "MCP10"

  owasp_agentic_top10:
    version: "2026"
    url: "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
    mappings:
      prompt_injection: "ASI01"
      tool_poisoning: "ASI02"
      command_injection: "ASI02"
      supply_chain: "ASI04"
      context_sharing: "ASI06"
      # Not all categories map — that's fine

  mitre_atlas:
    version: "4.0"
    url: "https://atlas.mitre.org/"
    mappings:
      command_injection: "AML.T0040"
      prompt_injection: "AML.T0051"

  cwe:
    version: "4.15"
    mappings:
      command_injection: ["CWE-78", "CWE-88", "CWE-22"]
      token_exposure: ["CWE-798", "CWE-312"]
      permissions: ["CWE-269", "CWE-732"]
```

When OWASP publishes MCP Top 10 v2, add a new section or update the existing one. Zero code changes.

### Framework Resolver

A `FrameworkResolver` class in `core/frameworks.py` loads the YAML at startup and provides lookups:

```python
class FrameworkResolver:
    def resolve(self, category: str) -> dict[str, str | list[str]]:
        """Return all framework IDs for a category."""
        # {"owasp_mcp_top10": "MCP05", "cwe": ["CWE-78", "CWE-88"], ...}

    def resolve_one(self, category: str, framework: str) -> str | None:
        """Return a single framework ID."""

    def list_frameworks(self) -> list[str]:
        """Return available framework names."""
```

### Finding Model Changes

```python
@dataclass
class Finding:
    category: str                                    # "command_injection" — stable internal ID
    rule_id: str                                     # "CA-INJ-CWE88-flag_injection" — stable
    framework_ids: dict[str, str | list[str]]        # populated by orchestrator, not scanner
    # ... existing fields (title, description, severity, evidence, remediation, etc.)
```

Scanners return findings with `category` set and `framework_ids` empty. The orchestrator calls `resolver.resolve(finding.category)` to populate `framework_ids` before writing reports.

### Rule ID Format

Current: `MCP05-CWE88-flag_injection` (embeds framework ID).

New: `CA-INJ-CWE88-flag_injection` where:
- `CA` — CounterAgent namespace
- `INJ` — stable category abbreviation
- `CWE88` — weakness type
- `flag_injection` — technique

Category abbreviations:

| Category | Abbreviation |
|----------|-------------|
| command_injection | INJ |
| auth | AUTH |
| token_exposure | TOK |
| permissions | PERM |
| tool_poisoning | TPOIS |
| prompt_injection | PINJ |
| audit_telemetry | AUDIT |
| supply_chain | SCHAIN |
| shadow_servers | SHADOW |
| context_sharing | CTX |

### CLI Changes

`counteragent audit list-checks` currently shows an OWASP ID column. After this change:

- Default: shows primary framework column (OWASP MCP Top 10 for audit scanners)
- `--framework owasp-mcp` — OWASP MCP Top 10 IDs
- `--framework owasp-agentic` — Agentic Top 10 IDs
- `--framework all` — all mapped framework IDs

### Report Changes

JSON reports get a `framework_mappings` section per finding:

```json
{
  "category": "command_injection",
  "rule_id": "CA-INJ-CWE88-flag_injection",
  "framework_ids": {
    "owasp_mcp_top10": "MCP05",
    "owasp_agentic_top10": "ASI02",
    "cwe": ["CWE-78", "CWE-88"],
    "mitre_atlas": "AML.T0040"
  },
  "title": "Argument injection in 'git_status' parameter 'repo_path'",
  ...
}
```

## Migration

### What Changes

| Component | Current | New |
|-----------|---------|-----|
| `BaseScanner.owasp_id` | `"MCP05"` | `category = "command_injection"` |
| `Finding.owasp_id` | `"MCP05"` | `category = "command_injection"` + `framework_ids: dict` |
| `Finding.rule_id` | `"MCP05-CWE88-..."` | `"CA-INJ-CWE88-..."` |
| `core/owasp.py` | empty stub | deleted — replaced by `core/frameworks.py` + `core/data/frameworks.yaml` |
| Scanner modules (10) | hardcoded `owasp_id` | `category` attribute |
| Finding construction (all scanners) | `owasp_id="MCP05"` | `category="command_injection"` |
| `rule_id` construction (all scanners) | `f"MCP05-{cwe}-..."` | `f"CA-INJ-{cwe}-..."` |
| Orchestrator | passes findings through | calls `resolver.resolve()` to populate `framework_ids` |
| `list-checks` CLI | hardcoded OWASP column | resolver-driven, supports `--framework` flag |
| JSON reports | `owasp_id` field | `category` + `framework_ids` dict |
| Tests | assert on `owasp_id` | assert on `category` |
| `owasp_mapping.md` | hardcoded MCP IDs | generated from YAML or references YAML as source of truth |

### What Doesn't Change

- Scanner logic (detection, payloads, evidence collection)
- Finding severity levels
- CLI invocation (`counteragent audit scan`)
- Report structure (adds fields, doesn't remove)

### Backward Compatibility

For the transition period, JSON reports include both `owasp_id` (deprecated) and `category` + `framework_ids` (new). The `owasp_id` field is populated from `framework_ids["owasp_mcp_top10"]` for backward compatibility and removed in a future version.

## Timing

Post-Phase E (after monorepo migration completes). This is a refactor that touches all 10 scanner modules and their tests — doing it during migration would create merge conflicts. Phase 2 (agent-inject) should start with this pattern already in place.

Sequence: Phase E (deprecate old repos) → Framework Decoupling → Phase 2 (agent-inject).

## Not In Scope

- Auto-updating framework mappings from OWASP/NIST APIs (future)
- Generating `owasp_mapping.md` from the YAML (nice-to-have, not blocking)
- SARIF output format (separate effort, would consume `framework_ids`)
