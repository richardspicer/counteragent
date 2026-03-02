# CounterAgent

[![CI](https://github.com/q-uestionable-AI/counteragent/actions/workflows/ci.yml/badge.svg)](https://github.com/q-uestionable-AI/counteragent/actions/workflows/ci.yml)
[![CodeQL](https://github.com/q-uestionable-AI/counteragent/actions/workflows/codeql.yml/badge.svg)](https://github.com/q-uestionable-AI/counteragent/actions/workflows/codeql.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Docs](https://img.shields.io/badge/docs-counteragent.dev-8b5cf6)](https://docs.counteragent.dev)

**Open source AI agent red team platform for testing MCP server security, intercepting agent traffic, and mapping vulnerabilities to OWASP frameworks.**

Covers MCP server vulnerabilities, tool poisoning, prompt injection via tools, and agent-to-agent exploitation. Maps findings to [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) and [OWASP Top 10 for Agentic AI](https://genai.owasp.org/).

> Research program by [Richard Spicer](https://richardspicer.io) · [GitHub](https://github.com/richardspicer)

---

## Install

```bash
git clone https://github.com/q-uestionable-AI/counteragent.git
cd counteragent
uv sync --group dev
```

Or with pip:

```bash
pip install -e .
```

---

## Usage

### Audit — MCP Server Security Scanner

Automated security scanner for MCP server implementations. Runs modular checks against the OWASP MCP Top 10.

```bash
# Scan a local MCP server
counteragent audit scan --transport stdio --command "python my_server.py"

# See available checks
counteragent audit list-checks

# Enumerate server capabilities
counteragent audit enumerate --transport stdio --command "python my_server.py"

# Generate report from scan results (coming soon)
counteragent audit report --input results.json --format html
```

### Proxy — MCP Traffic Interceptor

Interactive MCP traffic interceptor — "Burp Suite for MCP." Sits between client and server, intercepting JSON-RPC messages for inspection, modification, and replay.

```bash
# Start proxy for a stdio server
counteragent proxy start --transport stdio --target-command "python my_server.py"

# Replay a captured session
counteragent proxy replay --session-file session.json

# Export session data
counteragent proxy export --session-file session.json --output report.json

# Inspect session contents
counteragent proxy inspect --session-file session.json
```

### Future Modules

```bash
counteragent inject --help   # Tool poisoning & prompt injection
counteragent chain --help    # Multi-agent attack chains
```

---

## OWASP MCP Top 10 Coverage

| ID | Vulnerability | Scanner | Status |
|----|--------------|---------|--------|
| MCP01 | Token Mismanagement & Secret Exposure | `token_exposure.py` | Built |
| MCP02 | Privilege Escalation via Scope Creep | `permissions.py` | Built |
| MCP03 | Tool Poisoning | `tool_poisoning.py` | Built |
| MCP04 | Software Supply Chain Attacks | `supply_chain.py` | Built |
| MCP05 | Command Injection & Execution | `injection.py` | Built |
| MCP06 | Prompt Injection via Contextual Payloads | `prompt_injection.py` | Built |
| MCP07 | Insufficient Authentication & Authorization | `auth.py` | Built |
| MCP08 | Lack of Audit and Telemetry | `audit_telemetry.py` | Built |
| MCP09 | Shadow MCP Servers | `shadow_servers.py` | Built |
| MCP10 | Context Injection & Over-Sharing | `context_sharing.py` | Built |

See [docs/owasp_mapping.md](docs/owasp_mapping.md) for detailed scanner coverage.

---

## Development

```bash
# Install with dev dependencies
uv sync --group dev

# Run tests
uv run pytest -q

# Lint and format
uv run ruff check .
uv run ruff format .

# Type checking
uv run mypy src/
```

Pre-commit hooks run automatically: ruff, mypy, gitleaks, trailing whitespace, large file checks.

---

## Documentation

| Document | Purpose |
|----------|---------|
| [Architecture](docs/Architecture.md) | Technical architecture and module design |
| [OWASP Mapping](docs/owasp_mapping.md) | Scanner coverage mapped to OWASP MCP Top 10 |
| [Roadmap](docs/Roadmap.md) | Phased development plan and success metrics |
| [CONTRIBUTING](CONTRIBUTING.md) | Development setup, branch workflow, code standards |
| [SECURITY](SECURITY.md) | Vulnerability reporting and responsible disclosure |

---

## Legal

All tools are intended for authorized security testing only. Only test systems you own, control, or have explicit permission to test. Responsible disclosure for all vulnerabilities discovered.

## License

[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)

## AI Disclosure

This project uses a human-led, AI-augmented workflow. See [AI-STATEMENT.md](AI-STATEMENT.md).
