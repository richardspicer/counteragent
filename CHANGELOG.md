# Changelog

All notable changes to CounterAgent are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-03-02

First public release. MCP security audit scanner and traffic proxy, with full
OWASP MCP Top 10 coverage.

### Added

#### Audit Module
- 10 scanner modules covering the complete OWASP MCP Top 10 (MCP01–MCP10)
- Transport support: stdio, SSE, and Streamable HTTP
- `audit scan` — run security scanners against live MCP servers
- `audit enumerate` — list server capabilities without scanning
- `audit list-checks` — show available scanner modules and OWASP mappings
- `audit report` — convert saved scan JSON to other formats
- SARIF 2.1.0 report output (`--format sarif`) for GitHub Code Scanning integration
- JSON report output with finding deduplication and severity mapping

#### Proxy Module
- Interactive MCP traffic interceptor with TUI (Textual)
- `proxy start` — launch intercepting proxy with live message inspection
- `proxy replay` — replay captured sessions against live servers
- `proxy export` — export sessions to JSON
- `proxy inspect` — print session contents to stdout
- Intercept mode for message modification and forwarding
- Session recording and auto-save

#### Infrastructure
- Unified CLI via Typer (`counteragent audit ...`, `counteragent proxy ...`)
- CI pipeline: ruff lint/format, mypy, pytest on Ubuntu + Windows (Python 3.11–3.14)
- Pre-commit hooks: ruff, gitleaks, trailing whitespace, merge conflict detection
- 558 tests passing across Ubuntu and Windows
- Dependabot for GitHub Actions and pip ecosystem monitoring
- SECURITY.md with vulnerability reporting contact

#### Documentation
- Mintlify docs site at [docs.counteragent.dev](https://docs.counteragent.dev)
- Quickstart guide with install and first scan walkthrough
- CLI reference for all audit and proxy commands
- Scanner coverage page with OWASP MCP Top 10 mapping table

[0.1.0]: https://github.com/q-uestionable-AI/counteragent/releases/tag/v0.1.0
