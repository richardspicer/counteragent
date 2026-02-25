# counteragent

Unified AI agent red team platform. Monorepo consolidating mcp-audit, mcp-proxy, and future tools (agent-inject, agent-chain) into one Python package with a shared CLI. Maps findings to OWASP MCP Top 10 and OWASP Top 10 for Agentic AI.

## Project Layout

```
src/counteragent/
├── __init__.py               # Package version
├── __main__.py               # python -m counteragent support
├── cli.py                    # Root Typer app — mounts scan, proxy, inject, chain
├── core/                     # Shared models, connection, transport
│   ├── models.py             # Data models (Finding, ScanContext, etc.)
│   ├── connection.py         # MCP connection management
│   ├── discovery.py          # Server enumeration, capability discovery
│   ├── evidence.py           # Evidence collection and reporting
│   ├── owasp.py              # OWASP MCP Top 10 category definitions
│   └── transport.py          # Transport abstractions (stdio, SSE, Streamable HTTP)
├── scan/                     # MCP server security scanner (from mcp-audit)
│   ├── cli.py                # scan subcommand CLI (run, list-checks, enumerate, report)
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
├── proxy/                    # MCP traffic interceptor (from mcp-proxy)
│   └── cli.py                # proxy subcommand CLI
├── inject/                   # Tool poisoning & prompt injection [Phase 2]
│   └── cli.py                # inject subcommand CLI
└── chain/                    # Multi-agent attack chains [Phase 3]
    └── cli.py                # chain subcommand CLI
tests/                        # Test suite mirroring src/ structure
fixtures/vulnerable_servers/  # Intentionally vulnerable MCP servers for testing
```

## Code Standards

- **Python:** >=3.11
- **Docstrings:** Google-style on all public functions and classes
- **Async:** MCP SDK is async-native. Use `async/await` for MCP interactions
- **Type hints:** Required on all function signatures
- **Line length:** 100 chars (ruff)
- **Imports:** Sorted by ruff (isort rules)

## CLI Usage

```bash
# Top-level help
counteragent --help

# Scan commands (Phase B — mcp-audit migration)
counteragent scan --help
counteragent scan run
counteragent scan list-checks

# Proxy commands (Phase C — mcp-proxy migration)
counteragent proxy --help
counteragent proxy start

# Future phases
counteragent inject --help
counteragent chain --help
```

Smoke tests after changes:
```bash
counteragent --help
counteragent scan list-checks
counteragent scan run --help
counteragent scan enumerate --help
counteragent proxy start --help
```

## Testing

- Framework: pytest + pytest-asyncio (asyncio_mode = "auto")
- Test files mirror source structure under `tests/`
- Integration tests connect to fixture servers via MCP transports
- **All tests must pass before committing**

Run tests:
```bash
uv run pytest -q
```

## Scan Architecture

The scan subcommand (migrated from mcp-audit) has 10 scanner modules, one per OWASP MCP Top 10 category. Each scanner extends `BaseScanner` from `scan/scanner/base.py` and implements an async `scan(context: ScanContext) -> list[Finding]` method.

**Import conventions:**
- Shared types (`Severity`, `Finding`, `ScanContext`) live in `core/models.py`
- `MCPConnection` lives in `core/connection.py`, `enumerate_server` in `core/discovery.py`
- Scanner modules import from `counteragent.scan.scanner.base` (which re-exports from core)
- `scan/mcp_client/` contains re-export shims for backward compatibility

**Flow:** CLI → `run_scan()` (orchestrator) → `enumerate_server()` → scanner registry → each scanner's `scan()` → aggregate `ScanResult` → JSON report

**Integration tests** launch real fixture servers from `fixtures/vulnerable_servers/` via stdio transport. The injection integration tests are inherently slow (~5 min each) because they send many payloads per tool.

## Git Workflow

**Never commit directly to main.** Branch protection enforced.

```bash
git checkout main && git pull
git checkout -b feature/description
# ... work ...
uv run pytest -q
counteragent --help
git add .
git commit -F .commitmsg
git push -u origin feature/description
```

### Shell Quoting (CRITICAL)

CMD corrupts `git commit -m "message with spaces"`. Always use:
```bash
echo "feat: description here" > .commitmsg
git commit -F .commitmsg
del .commitmsg
```

### End of Session

Commit to branch, `git stash -m "description"`, or `git restore .` — never leave uncommitted changes.

## Pre-commit Hooks

Hooks run automatically on `git commit`:
- trailing-whitespace, end-of-file-fixer, check-yaml, check-toml
- check-added-large-files, check-merge-conflict
- **no-commit-to-branch** (blocks direct commits to main)
- **ruff-check** (lint + auto-fix) + **ruff-format**
- **gitleaks** (secrets detection)
- **mypy** (type checking)

If pre-commit fails, fix issues and re-stage before committing.

## Dependencies

Managed via `uv` with PEP 735 dependency groups. Sync with:
```bash
uv sync --group dev
```

**Without `--group dev`, dev dependencies get stripped.**

## Build

- `src/` layout with `hatchling` backend
- Entry point: `counteragent = "counteragent.cli:app"`
- Packaging: `uv` with PEP 735 dependency groups

## Claude Code Guardrails

### Verification Scope
- Run only the tests for new/changed code, not the full suite
- Smoke test the CLI after changes (`counteragent --help`)
- Full suite verification is the developer's responsibility before merging

### Timeout Policy
- If any test run exceeds 60 seconds, stop and identify the stuck test
- Do not set longer timeouts and wait — diagnose instead

### Process Hygiene
- Before running tests, kill any orphaned python/node processes from previous runs

### Failure Mode
- If verification hits a problem you can't resolve in 2 attempts, commit the work to the branch and report what failed
- Do not spin on the same failure

### Boundaries
- Do not create PRs. Push the branch and stop.
- Do not attempt to install CLI tools (gh, hub, etc.)
- Do not modify files in `concepts/` or `docs/` unless the task brief explicitly says to

## Legal & Ethical

- Only test systems you own, control, or have explicit permission to test
- Responsible disclosure for all vulnerabilities
- Frame all tooling as defensive security testing tools
