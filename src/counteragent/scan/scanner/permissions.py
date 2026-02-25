"""Permissions & privilege escalation scanner (MCP02).

Static analysis of tool capabilities exposed by an MCP server.
Identifies excessive privileges, dangerous tool categories, missing
input constraints, and overprivileged server configurations.

Maps to: OWASP MCP Top 10 — MCP02: Privilege Escalation via Scope Creep

This scanner does NOT invoke tools — it analyzes the enumerated
metadata (names, descriptions, schemas) to assess risk.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from counteragent.scan.scanner.base import BaseScanner, Finding, ScanContext, Severity

logger = logging.getLogger("counteragent.scan.scanner.permissions")

# Threshold for flagging excessive tool counts.
# Servers above this have a large attack surface worth auditing.
_EXCESSIVE_TOOL_THRESHOLD = 15

# Dangerous capability categories with keyword patterns.
# Each category maps tool name/description keywords to a risk label.
_DANGEROUS_CATEGORIES: dict[str, dict[str, Any]] = {
    "shell_execution": {
        "keywords": [
            "exec",
            "execute",
            "shell",
            "command",
            "cmd",
            "bash",
            "powershell",
            "subprocess",
            "spawn",
            "system",
            "eval",
            "run_command",
            "run_script",
            "terminal",
        ],
        "label": "Shell/Command Execution",
        "severity": Severity.CRITICAL,
        "description": "Can execute arbitrary system commands",
    },
    "file_write": {
        "keywords": [
            "write_file",
            "create_file",
            "save_file",
            "upload",
            "delete_file",
            "remove_file",
            "unlink",
            "move_file",
            "rename_file",
            "mkdir",
            "rmdir",
            "chmod",
            "chown",
        ],
        "label": "File System Write/Delete",
        "severity": Severity.HIGH,
        "description": "Can modify or delete files on the server",
    },
    "database": {
        "keywords": [
            "query",
            "sql",
            "database",
            "drop_table",
            "truncate",
            "insert",
            "update",
            "delete_row",
            "migrate",
            "execute_query",
            "db_",
        ],
        "label": "Database Operations",
        "severity": Severity.HIGH,
        "description": "Can read or modify database contents",
    },
    "network": {
        "keywords": [
            "fetch",
            "request",
            "curl",
            "wget",
            "http_",
            "post_",
            "get_url",
            "fetch_url",
            "download",
            "deploy",
            "send_request",
        ],
        "label": "Network/HTTP Access",
        "severity": Severity.MEDIUM,
        "description": "Can make outbound network requests (SSRF risk)",
    },
    "credential": {
        "keywords": [
            "secret",
            "password",
            "credential",
            "token",
            "api_key",
            "vault",
            "keystore",
            "set_secret",
            "get_secret",
            "create_user",
            "delete_user",
            "set_role",
            "grant",
        ],
        "label": "Credential/Identity Management",
        "severity": Severity.CRITICAL,
        "description": "Can access or modify credentials and user accounts",
    },
}

# Parameter name patterns that indicate unconstrained dangerous inputs.
_UNCONSTRAINED_PARAM_PATTERNS: list[dict[str, Any]] = [
    {
        "pattern": re.compile(r"(path|file|dir|folder|filename)", re.IGNORECASE),
        "label": "file path",
        "risk": "Accepts arbitrary file paths without restriction",
    },
    {
        "pattern": re.compile(r"(url|uri|endpoint|href|link)", re.IGNORECASE),
        "label": "URL",
        "risk": "Accepts arbitrary URLs (SSRF risk)",
    },
    {
        "pattern": re.compile(r"(command|cmd|shell|exec|script)", re.IGNORECASE),
        "label": "command",
        "risk": "Accepts arbitrary commands for execution",
    },
    {
        "pattern": re.compile(r"(query|sql|statement)", re.IGNORECASE),
        "label": "query",
        "risk": "Accepts arbitrary query strings (injection risk)",
    },
]


def _classify_tool_category(tool: dict[str, Any]) -> list[dict[str, Any]]:
    """Classify a tool into dangerous capability categories.

    Checks the tool's name and description against keyword patterns
    for each danger category.

    Args:
        tool: Tool dict with 'name' and 'description' fields.

    Returns:
        List of matched category dicts (from _DANGEROUS_CATEGORIES),
        each augmented with the matched 'keyword'.
    """
    name = tool.get("name", "").lower()
    desc = tool.get("description", "").lower()
    combined = f"{name} {desc}"

    matches = []
    for cat_id, cat in _DANGEROUS_CATEGORIES.items():
        for kw in cat["keywords"]:
            if kw in combined:
                matches.append(
                    {
                        "category_id": cat_id,
                        "label": cat["label"],
                        "severity": cat["severity"],
                        "description": cat["description"],
                        "matched_keyword": kw,
                    }
                )
                break  # One match per category is enough
    return matches


def _check_param_constraints(tool: dict[str, Any]) -> list[dict[str, str]]:
    """Check if tool parameters lack input constraints.

    Identifies string parameters whose names suggest dangerous inputs
    (file paths, URLs, commands, queries) but have no enum, pattern,
    or format restrictions in their schema.

    Args:
        tool: Tool dict with 'inputSchema' containing parameter definitions.

    Returns:
        List of dicts with 'param', 'label', and 'risk' for each
        unconstrained dangerous parameter found.
    """
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})
    issues = []

    for param_name, param_def in properties.items():
        param_type = param_def.get("type", "")
        if param_type != "string":
            continue

        # Check if the parameter has any constraints
        has_enum = "enum" in param_def
        has_pattern = "pattern" in param_def
        has_format = "format" in param_def
        has_max_length = "maxLength" in param_def

        if has_enum or has_pattern or has_format:
            continue  # Parameter has some constraint

        # Check if the param name matches a dangerous pattern
        for pat in _UNCONSTRAINED_PARAM_PATTERNS:
            if pat["pattern"].search(param_name):
                issues.append(
                    {
                        "param": param_name,
                        "tool": tool.get("name", "unknown"),
                        "label": pat["label"],
                        "risk": pat["risk"],
                        "has_max_length": has_max_length,
                    }
                )
                break

    return issues


class PermissionsScanner(BaseScanner):
    """Scanner for privilege escalation and scope creep (MCP02).

    Performs static analysis of tool metadata to identify:
    - Excessive tool counts (large attack surface)
    - Dangerous tool categories (shell, file write, DB, network, creds)
    - Unconstrained dangerous parameters (paths, URLs, commands, queries)
    - High write-to-read ratio (overprivileged server)

    No tools are invoked — this scanner works entirely from the
    enumerated tool list and schemas.

    Attributes:
        name: Scanner identifier used in CLI (--checks permissions).
        owasp_id: OWASP MCP Top 10 category.
        description: What this scanner tests.
    """

    name = "permissions"
    owasp_id = "MCP02"
    description = "Tests for privilege escalation and excessive tool permissions"

    async def scan(self, context: ScanContext) -> list[Finding]:
        """Run all permission checks against enumerated tools.

        Args:
            context: ScanContext with tools list from server enumeration.

        Returns:
            List of Findings for each permission issue detected.
        """
        findings: list[Finding] = []

        if not context.tools:
            logger.debug("No tools enumerated — skipping permissions scan")
            return findings

        # Check 1: Excessive tool count
        finding = self._check_excessive_tools(context)
        if finding:
            findings.append(finding)

        # Check 2: Dangerous capability categories
        findings.extend(self._check_dangerous_capabilities(context))

        # Check 3: Unconstrained parameters
        findings.extend(self._check_unconstrained_params(context))

        # Check 4: Write/execute ratio
        finding = self._check_write_ratio(context)
        if finding:
            findings.append(finding)

        return findings

    def _check_excessive_tools(self, context: ScanContext) -> Finding | None:
        """Check if the server exposes an excessive number of tools.

        A high tool count increases attack surface and suggests the
        server may not follow least-privilege principles.

        Args:
            context: ScanContext with tools list.

        Returns:
            A Finding if tool count exceeds threshold, None otherwise.
        """
        count = len(context.tools)
        if count <= _EXCESSIVE_TOOL_THRESHOLD:
            return None

        tool_names = [t.get("name", "unknown") for t in context.tools]

        logger.warning(
            "EXCESSIVE TOOLS: %d tools exposed (threshold: %d)",
            count,
            _EXCESSIVE_TOOL_THRESHOLD,
        )
        return Finding(
            rule_id="MCP02-001",
            owasp_id="MCP02",
            title=f"Excessive tool count: {count} tools exposed",
            description=(
                f"Server exposes {count} tools (threshold: {_EXCESSIVE_TOOL_THRESHOLD}). "
                f"A large tool count increases attack surface and suggests the "
                f"server may not follow least-privilege principles. Consider "
                f"splitting into focused servers with minimal capabilities."
            ),
            severity=Severity.MEDIUM,
            evidence=f"{count} tools: {', '.join(tool_names)}",
            remediation=(
                "Apply least-privilege principles: split large servers into "
                "focused services with only the tools each workflow requires. "
                "Remove unused or development-only tools from production."
            ),
            metadata={
                "tool_count": count,
                "threshold": _EXCESSIVE_TOOL_THRESHOLD,
                "tool_names": tool_names,
            },
        )

    def _check_dangerous_capabilities(self, context: ScanContext) -> list[Finding]:
        """Identify tools with dangerous capabilities.

        Classifies each tool against known danger categories (shell exec,
        file write, database, network, credential management) and produces
        a finding per dangerous tool found.

        Args:
            context: ScanContext with tools list.

        Returns:
            List of Findings, one per dangerous tool detected.
        """
        findings = []

        for tool in context.tools:
            tool_name = tool.get("name", "unknown")
            categories = _classify_tool_category(tool)

            if not categories:
                continue

            # Use the highest severity among matched categories
            max_severity = max(categories, key=lambda c: _severity_rank(c["severity"]))
            category_labels = [c["label"] for c in categories]

            logger.warning(
                "DANGEROUS TOOL: %s — %s",
                tool_name,
                ", ".join(category_labels),
            )
            findings.append(
                Finding(
                    rule_id="MCP02-002",
                    owasp_id="MCP02",
                    title=f"Dangerous tool capability: '{tool_name}'",
                    description=(
                        f"Tool '{tool_name}' provides {', '.join(category_labels).lower()} "
                        f"capabilities. "
                        + " ".join(c["description"] + "." for c in categories)
                        + " Without proper authorization controls, this tool could "
                        "be exploited for privilege escalation."
                    ),
                    severity=max_severity["severity"],
                    evidence=(
                        f"Tool '{tool_name}' matched categories: "
                        + ", ".join(
                            c["label"] + " (keyword: " + c["matched_keyword"] + ")"
                            for c in categories
                        )
                    ),
                    remediation=(
                        "Apply least-privilege: restrict tool parameters with enum "
                        "constraints, path allowlists, or command allowlists. "
                        "Require explicit authorization for destructive operations. "
                        "Consider removing this tool if not required for the workflow."
                    ),
                    tool_name=tool_name,
                    metadata={
                        "categories": [
                            {"label": c["label"], "keyword": c["matched_keyword"]}
                            for c in categories
                        ],
                    },
                )
            )

        return findings

    def _check_unconstrained_params(self, context: ScanContext) -> list[Finding]:
        """Find dangerous parameters without input constraints.

        Identifies string parameters whose names suggest they accept
        file paths, URLs, commands, or queries, but lack schema-level
        restrictions (enum, pattern, format).

        Args:
            context: ScanContext with tools list.

        Returns:
            List of Findings, one per unconstrained dangerous parameter.
        """
        findings = []

        for tool in context.tools:
            issues = _check_param_constraints(tool)
            for issue in issues:
                logger.warning(
                    "UNCONSTRAINED PARAM: %s.%s — %s",
                    issue["tool"],
                    issue["param"],
                    issue["label"],
                )
                findings.append(
                    Finding(
                        rule_id="MCP02-003",
                        owasp_id="MCP02",
                        title=(
                            f"Unconstrained {issue['label']} parameter: "
                            f"'{issue['tool']}.{issue['param']}'"
                        ),
                        description=(
                            f"Parameter '{issue['param']}' on tool '{issue['tool']}' "
                            f"accepts arbitrary string input with no schema constraints. "
                            f"{issue['risk']}."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=(
                            f"Parameter '{issue['param']}' (type: string) has no "
                            f"enum, pattern, or format constraint"
                        ),
                        remediation=(
                            f"Add input constraints to '{issue['param']}': use 'enum' "
                            f"for known values, 'pattern' for regex validation, or "
                            f"'format' for standard types. Implement server-side "
                            f"allowlists for {issue['label']} parameters."
                        ),
                        tool_name=issue["tool"],
                        metadata={
                            "param": issue["param"],
                            "label": issue["label"],
                            "risk": issue["risk"],
                            "has_max_length": issue.get("has_max_length", False),
                        },
                    )
                )

        return findings

    def _check_write_ratio(self, context: ScanContext) -> Finding | None:
        """Check if write/execute tools significantly outnumber read-only tools.

        A high ratio of destructive to read-only tools suggests the server
        is overprivileged for most workflows.

        Args:
            context: ScanContext with tools list.

        Returns:
            A Finding if write/execute tools dominate, None otherwise.
        """
        write_tools = []
        read_tools = []

        for tool in context.tools:
            categories = _classify_tool_category(tool)
            if categories:
                write_tools.append(tool.get("name", "unknown"))
            else:
                read_tools.append(tool.get("name", "unknown"))

        total = len(context.tools)
        if total < 4:
            # Too few tools to meaningfully assess ratio
            return None

        write_count = len(write_tools)
        read_count = len(read_tools)
        write_pct = (write_count / total) * 100

        # Flag if >75% of tools are write/execute
        if write_pct <= 75:
            return None

        logger.warning(
            "HIGH WRITE RATIO: %d/%d tools (%.0f%%) are write/execute",
            write_count,
            total,
            write_pct,
        )
        return Finding(
            rule_id="MCP02-004",
            owasp_id="MCP02",
            title=f"High write/execute ratio: {write_count}/{total} tools ({write_pct:.0f}%)",
            description=(
                f"Server has {write_count} write/execute tools vs {read_count} "
                f"read-only tools ({write_pct:.0f}% destructive). This suggests "
                f"the server is overprivileged for most workflows. "
                f"Destructive tools: {', '.join(write_tools)}."
            ),
            severity=Severity.MEDIUM,
            evidence=(
                f"Write/execute: {write_count} ({', '.join(write_tools)}) | "
                f"Read-only: {read_count} ({', '.join(read_tools)})"
            ),
            remediation=(
                "Review whether all write/execute tools are required. "
                "Split into separate read-only and read-write servers. "
                "Apply least-privilege by removing tools not needed for "
                "the intended workflow."
            ),
            metadata={
                "write_count": write_count,
                "read_count": read_count,
                "write_percentage": round(write_pct, 1),
                "write_tools": write_tools,
                "read_tools": read_tools,
            },
        )


def _severity_rank(severity: Severity) -> int:
    """Map severity to numeric rank for comparison.

    Args:
        severity: Severity enum value.

    Returns:
        Integer rank (higher = more severe).
    """
    return {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }.get(severity, 0)
