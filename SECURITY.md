# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in CounterAgent, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Email **security@q-uestionable.ai** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
3. Allow up to 72 hours for initial response
4. We will coordinate disclosure timeline with you

## Scope

CounterAgent is a security testing tool. Vulnerabilities in the tool itself (not in targets being tested) are in scope:

- Command injection in CLI argument handling
- Credential leakage in reports or logs
- Dependency vulnerabilities with exploitable paths
- Unsafe deserialization of scan results or MCP messages

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
