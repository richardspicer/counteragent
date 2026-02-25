"""Intentionally vulnerable MCP server: Context Sharing (MCP10).

This server over-shares context in tool responses, leaks session
identifiers, exposes previous request data in errors, and provides
resources with no access scoping and embedded credentials. Used to
test the context_sharing scanner.

DO NOT deploy this server in any real environment.

Usage:
    python -m fixtures.vulnerable_servers.vuln_context
    # or
    fastmcp run fixtures/vulnerable_servers/vuln_context.py
"""

from fastmcp import FastMCP

mcp = FastMCP(
    name="vuln-context-server",
    version="0.1.0",
)

# Simulated "database" of user records for the excessive-context tool
_FAKE_USERS_DB = [
    {
        "id": i,
        "name": f"User {i}",
        "email": f"user{i}@example.com",
        "role": "admin" if i == 1 else "viewer",
        "department": "Engineering",
        "phone": f"555-{i:04d}",
        "address": f"{i * 100} Main Street, Springfield, IL 62701",
        "hire_date": f"2023-{(i % 12) + 1:02d}-15",
        "salary": 50000 + i * 5000,
        "manager_id": max(1, i - 1),
        "notes": f"Employee record {i} — last reviewed Q4 2024",
    }
    for i in range(1, 51)
]


@mcp.tool()
def get_user_name(user_id: int) -> str:
    """Get a user's name by ID.

    Deliberately returns the ENTIRE user record plus all other users
    when only the name was requested — triggers MCP10-001.
    """
    # Over-share: return all records instead of just the name
    records = "\n".join(str(record) for record in _FAKE_USERS_DB)
    return f"Requested user_id={user_id}. Full database dump follows:\n{records}"


@mcp.tool()
def check_status(service: str) -> str:
    """Check the status of an internal service.

    Deliberately leaks session IDs and internal state — triggers MCP10-002.
    """
    return (
        f"Service '{service}' is healthy. "
        f"session_id=abc123-def456-ghi789 "
        f"request_id=req-2024-99001 "
        f"internal_state=RUNNING "
        f"worker_id=w-42 "
        f"trace_id=trace-deadbeef-cafe"
    )


@mcp.tool()
def process_payment(amount: str) -> str:
    """Process a payment.

    Deliberately leaks previous request context and credentials
    in error messages — triggers MCP10-003.
    """
    # Simulate error that leaks context from a "previous request"
    if not amount or amount == "not_a_number":
        raise ValueError(
            f"Payment processing failed for amount='{amount}'. "
            f"Previous request session_id=old-session-xyz789. "
            f"Retry with api_key=sk-live-abc123def456ghi789jkl012. "  # gitleaks:allow
            f"Last successful transaction for user admin@internal.corp."
        )
    return f"Payment of {amount} processed"


# --- Resources: no scoping + sensitive data ---


@mcp.resource("config://app/settings")
def app_settings() -> str:
    """Application settings.

    Globally accessible with no access controls — triggers MCP10-004.
    Contains embedded credentials — triggers MCP10-005.
    """
    return (
        "# Application Configuration\n"
        "app_name=vuln-context-server\n"
        "debug=true\n"
        "database_url=postgres://admin:SuperSecret123@db.internal:5432/prod\n"
        "api_key=sk-prod-a1b2c3d4e5f6g7h8i9j0k1l2m3\n"  # gitleaks:allow
        "secret=jwt-signing-key-do-not-share-ABCDEF123456\n"
        "admin_email=admin@internal.corp\n"
        "redis_password=r3d1s_p@ssw0rd\n"
    )


@mcp.resource("data://reports/all")
def all_reports() -> str:
    """All reports — globally accessible.

    No access controls on this endpoint — triggers MCP10-004.
    Contains PII — triggers MCP10-005.
    """
    return (
        "Report 1: Q4 Revenue — contact cfo@internal.corp\n"
        "Report 2: HR Summary — SSN on file: 123-45-6789\n"
        "Report 3: IT Audit — password=changeme123\n"
    )


# --- Clean tools (should NOT trigger findings) ---


@mcp.tool()
def ping() -> str:
    """Check server health."""
    return "pong"


@mcp.tool()
def echo(message: str) -> str:
    """Echo back the provided message."""
    return message


if __name__ == "__main__":
    mcp.run()
