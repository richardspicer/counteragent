"""Intentionally vulnerable MCP server: Argument Injection (CWE-88) & Path Traversal (CWE-22).

This server has tools that pass user input as subprocess arguments or
file paths without sanitization. Used for testing mcp-audit's injection
scanner with argument injection and path traversal payloads.

DO NOT deploy this server in any real environment.

Usage:
    python -m fixtures.vulnerable_servers.vuln_argument_injection
    # or
    fastmcp run fixtures/vulnerable_servers/vuln_argument_injection.py
"""

import os
import subprocess

from fastmcp import FastMCP

mcp = FastMCP(
    name="vuln-argument-injection-server",
    instructions="A test server with intentional argument injection "
    "and path traversal vulnerabilities.",
)


@mcp.tool()
def git_diff(repo_path: str, target: str) -> str:
    """Show git diff for a target ref.

    Args:
        repo_path: Path to the git repository.
        target: The git ref to diff against (branch, commit, tag).
    """
    # VULNERABLE: target passed directly as argument, not sanitized for flags.
    # If target is "--help", git interprets it as a flag instead of a ref.
    cwd = repo_path if os.path.isdir(repo_path) else None
    try:
        result = subprocess.run(
            ["git", "diff", target],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout or result.stderr or "No diff output."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def read_file(base_dir: str, filename: str) -> str:
    """Read a file from the base directory.

    Args:
        base_dir: The base directory to read from.
        filename: The filename to read (relative to base_dir).
    """
    # VULNERABLE: no path validation, allows traversal outside base_dir.
    path = os.path.join(base_dir, filename)
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return "Error: file not found"
    except Exception:
        return "Error: could not read file"


@mcp.tool()
def safe_git_diff(repo_path: str, target: str) -> str:
    """Show git diff with sanitized input.

    Args:
        repo_path: Path to the git repository.
        target: The git ref to diff against (branch, commit, tag).
    """
    # SAFE: rejects flag-like arguments and control characters
    if target.startswith("-") or "\n" in target or "\r" in target:
        return "Error: invalid ref"
    cwd = repo_path if os.path.isdir(repo_path) else None
    try:
        result = subprocess.run(
            ["git", "diff", target],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout or result.stderr or "No diff output."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def safe_read_file(base_dir: str, filename: str) -> str:
    """Read a file from the base directory with path validation.

    Args:
        base_dir: The base directory to read from.
        filename: The filename to read (relative to base_dir).
    """
    # SAFE: validates path stays within base_dir
    base = os.path.realpath(base_dir)
    path = os.path.realpath(os.path.join(base_dir, filename))
    if not path.startswith(base):
        return "Error: path traversal detected"
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return "Error: file not found"
    except Exception:
        return "Error: could not read file"


if __name__ == "__main__":
    mcp.run()
