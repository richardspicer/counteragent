"""Intentionally vulnerable MCP server: Privilege Escalation via Scope Creep (MCP02).

This server exposes an excessive number of tools with dangerous capabilities
and no input constraints. Models the "overprivileged agent" pattern where
a server grants far more capability than any single workflow requires.

Includes:
- Shell execution tools with unbounded command parameters
- File system tools accepting arbitrary paths
- Database tools with unrestricted SQL
- Network tools with arbitrary URL access
- A high ratio of write/execute to read-only tools
- No enum constraints or pattern validation on parameters

DO NOT deploy this server in any real environment.

Usage:
    python -m fixtures.vulnerable_servers.vuln_permissions
    # or
    fastmcp run fixtures/vulnerable_servers/vuln_permissions.py
"""

from fastmcp import FastMCP

mcp = FastMCP(
    name="vuln-permissions-server",
    instructions="A test server with excessive privileges and dangerous tools.",
)


# --- Shell execution tools (dangerous) ---


@mcp.tool()
def run_command(command: str) -> str:
    """Execute an arbitrary shell command on the server.

    Args:
        command: The shell command to execute.
    """
    return f"[simulated output for: {command}]"


@mcp.tool()
def run_script(script_path: str, args: str = "") -> str:
    """Execute a script file with optional arguments.

    Args:
        script_path: Path to the script to execute.
        args: Command-line arguments to pass.
    """
    return f"[simulated script execution: {script_path} {args}]"


# --- File system tools (dangerous) ---


@mcp.tool()
def read_file(path: str) -> str:
    """Read the contents of any file on the server.

    Args:
        path: Absolute or relative path to the file.
    """
    return f"[simulated file contents from {path}]"


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Write content to any file on the server.

    Args:
        path: Absolute or relative path to write to.
        content: The content to write.
    """
    return f"[simulated write to {path}: {len(content)} bytes]"


@mcp.tool()
def delete_file(path: str) -> str:
    """Delete a file from the server.

    Args:
        path: Path to the file to delete.
    """
    return f"[simulated delete: {path}]"


@mcp.tool()
def list_directory(path: str = "/") -> str:
    """List contents of a directory.

    Args:
        path: Directory path to list.
    """
    return f"[simulated directory listing for {path}]"


# --- Database tools (dangerous) ---


@mcp.tool()
def execute_query(sql: str) -> str:
    """Execute an arbitrary SQL query against the database.

    Args:
        sql: The SQL query to execute.
    """
    return f"[simulated query result for: {sql}]"


@mcp.tool()
def drop_table(table_name: str) -> str:
    """Drop a database table.

    Args:
        table_name: Name of the table to drop.
    """
    return f"[simulated drop table: {table_name}]"


# --- Network tools (dangerous) ---


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch content from any URL.

    Args:
        url: The URL to fetch.
    """
    return f"[simulated fetch from {url}]"


@mcp.tool()
def deploy_service(service_name: str, image: str) -> str:
    """Deploy a service to the cluster.

    Args:
        service_name: Name of the service to deploy.
        image: Container image to deploy.
    """
    return f"[simulated deploy: {service_name} from {image}]"


# --- Credential tools (dangerous) ---


@mcp.tool()
def get_secret(secret_name: str) -> str:
    """Retrieve a secret from the vault.

    Args:
        secret_name: Name of the secret to retrieve.
    """
    return f"[simulated secret value for {secret_name}]"


@mcp.tool()
def set_secret(secret_name: str, value: str) -> str:
    """Store or update a secret in the vault.

    Args:
        secret_name: Name of the secret.
        value: The secret value to store.
    """
    return f"[simulated secret stored: {secret_name}]"


@mcp.tool()
def create_user(username: str, role: str = "admin") -> str:
    """Create a new user account.

    Args:
        username: Username for the new account.
        role: Role to assign (defaults to admin).
    """
    return f"[simulated user created: {username} with role {role}]"


# --- Safe / read-only tools ---


@mcp.tool()
def server_status() -> str:
    """Check server health and uptime."""
    return "Server OK | Uptime: 12d 5h | Version: 2.1.0"


@mcp.tool()
def get_version() -> str:
    """Get the server version string."""
    return "vuln-permissions-server v2.1.0"


@mcp.tool()
def execute_process(command: str, background: bool = False) -> str:
    """Execute a system process with optional background mode.

    Args:
        command: The command to execute.
        background: Whether to run in the background.
    """
    return f"[simulated process execution: {command}]"


@mcp.tool()
def upload_backup(path: str, destination: str) -> str:
    """Upload a file to the backup server.

    Args:
        path: Local file path to upload.
        destination: Remote destination path.
    """
    return f"[simulated upload: {path} -> {destination}]"


if __name__ == "__main__":
    mcp.run()
