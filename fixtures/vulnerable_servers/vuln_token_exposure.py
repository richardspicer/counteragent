"""Intentionally vulnerable MCP server: Token Exposure (MCP01).

This server exposes secrets through tool parameters, tool responses,
error messages, and environment variable leakage. Used to test the
token_exposure scanner.

All secret-like values are constructed dynamically at runtime to
avoid triggering GitHub push protection on literal patterns.

DO NOT deploy this server in any real environment.

Usage:
    python -m fixtures.vulnerable_servers.vuln_token_exposure
    # or
    fastmcp run fixtures/vulnerable_servers/vuln_token_exposure.py
"""

from fastmcp import FastMCP

mcp = FastMCP(
    name="vuln-token-exposure-server",
    version="0.1.0",
)


# Synthetic secrets constructed at runtime to avoid push protection.
# These are NOT real credentials — they exist solely to trigger scanner checks.
_FAKE_JWT_HEADER = "eyJhbGciOiJIUzI1NiJ9"
_FAKE_JWT_PAYLOAD = "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
_FAKE_JWT = f"{_FAKE_JWT_HEADER}.{_FAKE_JWT_PAYLOAD}"

_AWS_SECRET_PREFIX = "wJalrXUtnFEMI"
_AWS_SECRET_SUFFIX = "K7MDENG/bPxRfiCYEXAMPLEKEY"
_FAKE_AWS_SECRET = f"{_AWS_SECRET_PREFIX}/{_AWS_SECRET_SUFFIX}"


# --- Vulnerable tools ---


@mcp.tool()
def authenticate(username: str, api_key: str) -> str:  # noqa: ARG001
    """Authenticate a user with an API key.

    Has a parameter named 'api_key' — triggers MCP01-001.
    """
    return "Authentication successful"


@mcp.tool()
def get_credentials(service: str) -> str:  # noqa: ARG001
    """Get credentials for a service.

    Returns a synthetic JWT in the response — triggers MCP01-002.
    """
    return f"Service credentials retrieved.\nToken: {_FAKE_JWT}\nStatus: active"


@mcp.tool()
def connect_database(host: str) -> str:
    """Connect to a database.

    Leaks a synthetic AWS key pattern in error messages — triggers MCP01-003.
    """
    if not host or host == "not_a_number":
        raise ValueError(
            f"Connection failed for host='{host}'. "
            f"AWS_SECRET_ACCESS_KEY={_FAKE_AWS_SECRET} "
            f"Check your configuration."
        )
    return f"Connected to {host}"


@mcp.tool()
def get_config(section: str) -> str:  # noqa: ARG001
    """Get application configuration.

    Leaks environment variables with secrets — triggers MCP01-004.
    """
    return (
        "Configuration dump:\n"
        "APP_NAME=vuln-server\n"
        "DB_PASSWORD=FAKE_test_password_value_12345\n"
        "JWT_SECRET=FAKE_jwt_signing_key_for_testing\n"
        "API_SECRET=FAKE_api_secret_for_testing_only\n"
        "LOG_LEVEL=debug\n"
    )


@mcp.tool()
def store_secret(password: str, secret: str) -> str:  # noqa: ARG001
    """Store a secret value.

    Has parameters named 'password' and 'secret' — triggers MCP01-001.
    """
    return "Secret stored securely"


# --- Clean tools (should NOT trigger findings) ---


@mcp.tool()
def ping() -> str:
    """Check server health."""
    return "pong"


@mcp.tool()
def add_numbers(a: int, b: int) -> str:
    """Add two numbers together."""
    return str(a + b)


@mcp.tool()
def get_time() -> str:
    """Get the current server time."""
    return "2024-01-15T10:30:00Z"


if __name__ == "__main__":
    mcp.run()
