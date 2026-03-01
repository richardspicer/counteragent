"""Tests for the command injection scanner (MCP05).

Tests the injection scanner using both fixture servers (integration)
and synthetic ScanContext with mock sessions (unit). Covers shell
injection (CWE-78), argument injection (CWE-88), and path traversal
(CWE-22) detection modes.
"""

import sys
from dataclasses import dataclass, field
from typing import Any

import pytest

from counteragent.audit.payloads.injection import (
    CANARY,
    InjectionPayload,
    _argument_injection_payloads,
    _path_traversal_payloads,
    _unix_payloads,
    _windows_payloads,
    get_injection_payloads,
)
from counteragent.audit.scanner.injection import InjectionScanner
from counteragent.core.connection import MCPConnection
from counteragent.core.discovery import enumerate_server
from counteragent.core.models import ScanContext, Severity

VULN_INJECTION_SERVER = "fixtures/vulnerable_servers/vuln_injection.py"
VULN_ARG_INJECTION_SERVER = "fixtures/vulnerable_servers/vuln_argument_injection.py"
PYTHON = sys.executable


# ---------------------------------------------------------------------------
# Mock session helpers for synthetic tests
# ---------------------------------------------------------------------------


@dataclass
class MockTextContent:
    """Simulates MCP TextContent."""

    text: str
    type: str = "text"


@dataclass
class MockCallToolResult:
    """Simulates MCP CallToolResult."""

    content: list[Any] = field(default_factory=list)
    isError: bool = False  # noqa: N815 — matches MCP SDK field name


class MockSession:
    """Mock MCP session that returns configurable responses per tool call.

    Args:
        responses: Dict mapping (tool_name, payload_substring) -> response text.
            If payload_substring is found in any argument value, that response is used.
        default_response: Default response when no match is found.
        error_responses: Dict mapping (tool_name, payload_substring) -> error text.
    """

    def __init__(
        self,
        responses: dict[tuple[str, str], str] | None = None,
        default_response: str = "OK",
        error_responses: dict[tuple[str, str], str] | None = None,
    ):
        self.responses = responses or {}
        self.default_response = default_response
        self.error_responses = error_responses or {}

    async def call_tool(self, tool_name: str, args: dict[str, Any]) -> MockCallToolResult:
        """Simulate a tool call, returning configured response."""
        args_str = " ".join(str(v) for v in args.values())

        # Check error responses first
        for (t_name, substr), err_text in self.error_responses.items():
            if t_name == tool_name and substr in args_str:
                return MockCallToolResult(
                    content=[MockTextContent(text=err_text)],
                    isError=True,
                )

        # Check normal responses
        for (t_name, substr), resp_text in self.responses.items():
            if t_name == tool_name and substr in args_str:
                return MockCallToolResult(content=[MockTextContent(text=resp_text)])

        return MockCallToolResult(content=[MockTextContent(text=self.default_response)])


def _make_tool(name: str, string_params: list[str]) -> dict[str, Any]:
    """Build a minimal tool dict for synthetic tests."""
    properties = {p: {"type": "string"} for p in string_params}
    return {
        "name": name,
        "description": f"Test tool {name}",
        "inputSchema": {
            "type": "object",
            "properties": properties,
        },
    }


# ---------------------------------------------------------------------------
# Integration tests — shell injection fixture (existing)
# ---------------------------------------------------------------------------


class TestInjectionScanner:
    """Test the injection scanner against the shell injection fixture server."""

    @pytest.mark.asyncio
    async def test_finds_injections(self):
        """Scanner detects injection vulnerabilities in fixture server."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = InjectionScanner()
            findings = await scanner.scan(ctx)

            # The fixture has 3 vulnerable tools and 1 safe tool
            assert len(findings) >= 1, "Should find at least one injection"
            assert all(f.owasp_id == "MCP05" for f in findings)
            assert all(f.severity.value == "critical" for f in findings)

    @pytest.mark.asyncio
    async def test_vulnerable_tools_identified(self):
        """Each vulnerable tool is flagged with a finding."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = InjectionScanner()
            findings = await scanner.scan(ctx)

            flagged_tools = {f.tool_name for f in findings}
            # file_search and run_diagnostics are the most reliably
            # injectable tools in the fixture (they use find/ping).
            # list_processes uses 'ps' which may not exist on Windows.
            assert "file_search" in flagged_tools or "run_diagnostics" in flagged_tools

    @pytest.mark.asyncio
    async def test_safe_tool_not_flagged(self):
        """The safe_echo tool should not produce findings."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = InjectionScanner()
            findings = await scanner.scan(ctx)

            flagged_tools = {f.tool_name for f in findings}
            assert "safe_echo" not in flagged_tools

    @pytest.mark.asyncio
    async def test_finding_has_remediation(self):
        """Each finding includes remediation guidance."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = InjectionScanner()
            findings = await scanner.scan(ctx)

            for f in findings:
                assert f.remediation, f"Finding {f.rule_id} missing remediation"
                assert "shell" in f.remediation.lower() or "subprocess" in f.remediation.lower()


# ---------------------------------------------------------------------------
# Integration tests — argument injection fixture
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Inherently slow (~5 min): 160+ sequential MCP tool calls with subprocess.run. "
    "pytest-timeout cannot interrupt Windows IOCP event loop, causing CI to hang forever.",
)
class TestArgumentInjectionIntegration:
    """Test the injection scanner against the argument injection fixture server."""

    @pytest.mark.asyncio
    async def test_finds_argument_injection(self):
        """Scanner detects flag injection in vulnerable git_diff tool."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_ARG_INJECTION_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = InjectionScanner()
            findings = await scanner.scan(ctx)

            flagged_tools = {f.tool_name for f in findings}
            assert "git_diff" in flagged_tools, (
                f"Expected git_diff to be flagged, got: {flagged_tools}"
            )

    @pytest.mark.asyncio
    async def test_safe_tool_not_flagged_argument(self):
        """safe_git_diff (rejects '-' prefix) should not produce findings."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_ARG_INJECTION_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = InjectionScanner()
            findings = await scanner.scan(ctx)

            flagged_tools = {f.tool_name for f in findings}
            assert "safe_git_diff" not in flagged_tools
            assert "safe_read_file" not in flagged_tools


# ---------------------------------------------------------------------------
# Synthetic tests — canary detection (shell injection)
# ---------------------------------------------------------------------------


class TestSyntheticCanaryDetection:
    """Unit tests for canary-based shell injection detection."""

    @pytest.mark.asyncio
    async def test_canary_in_response_triggers_finding(self):
        """Canary in response (without full payload) confirms injection."""
        session = MockSession(
            responses={
                ("vuln_tool", f"; echo {CANARY}"): f"some output\n{CANARY}\n",
            }
        )
        ctx = ScanContext(
            tools=[_make_tool("vuln_tool", ["input"])],
            session=session,
        )
        scanner = InjectionScanner()
        findings = await scanner.scan(ctx)

        assert len(findings) >= 1
        f = findings[0]
        assert f.tool_name == "vuln_tool"
        assert f.owasp_id == "MCP05"
        assert "CWE78" in f.rule_id
        assert f.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_reflected_payload_not_flagged(self):
        """Tool that echoes the full payload back is not flagged (reflection guard)."""
        payload_value = f"; echo {CANARY}"
        session = MockSession(
            responses={
                # Full payload is reflected — not a real injection
                ("echo_tool", payload_value): f"Echo: {payload_value}",
            }
        )
        ctx = ScanContext(
            tools=[_make_tool("echo_tool", ["message"])],
            session=session,
        )
        scanner = InjectionScanner()
        findings = await scanner.scan(ctx)

        flagged_tools = {f.tool_name for f in findings}
        assert "echo_tool" not in flagged_tools

    @pytest.mark.asyncio
    async def test_no_canary_returns_empty(self):
        """Normal response without canary produces no findings."""
        session = MockSession(default_response="Normal output, nothing to see here")
        ctx = ScanContext(
            tools=[_make_tool("normal_tool", ["input"])],
            session=session,
        )
        scanner = InjectionScanner()
        findings = await scanner.scan(ctx)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_shell_findings_have_cwe78_rule_id(self):
        """Shell injection findings use CWE78 in rule_id."""
        session = MockSession(
            responses={
                ("vuln_tool", f"; echo {CANARY}"): f"output\n{CANARY}\n",
            }
        )
        ctx = ScanContext(
            tools=[_make_tool("vuln_tool", ["input"])],
            session=session,
        )
        scanner = InjectionScanner()
        findings = await scanner.scan(ctx)

        for f in findings:
            assert "CWE78" in f.rule_id, f"Expected CWE78 in {f.rule_id}"
            assert f.metadata["cwe"] == "CWE78"
            assert f.metadata["detection_mode"] == "canary"


# ---------------------------------------------------------------------------
# Synthetic tests — pattern detection (argument injection)
# ---------------------------------------------------------------------------


class TestSyntheticPatternDetection:
    """Unit tests for pattern-based argument injection detection."""

    @pytest.mark.asyncio
    async def test_help_flag_triggers_finding(self):
        """--help payload matched by usage pattern in response."""
        session = MockSession(
            responses={
                ("git_diff", "--help"): (
                    "usage: git diff [<options>] [<commit>] [--] [<path>...]\n"
                    "   or: git diff [<options>] --no-index [--] <path> <path>\n"
                    "    --stat                show diffstat\n"
                ),
            }
        )
        ctx = ScanContext(
            tools=[_make_tool("git_diff", ["target"])],
            session=session,
        )
        scanner = InjectionScanner()
        findings = await scanner.scan(ctx)

        flagged_tools = {f.tool_name for f in findings}
        assert "git_diff" in flagged_tools
        git_findings = [f for f in findings if f.tool_name == "git_diff"]
        f = git_findings[0]
        assert "CWE88" in f.rule_id
        assert f.severity == Severity.HIGH
        assert f.metadata["detection_mode"] == "pattern"

    @pytest.mark.asyncio
    async def test_version_flag_triggers_finding(self):
        """--version payload matched by version pattern in response."""
        session = MockSession(
            responses={
                ("git_diff", "--version"): "git version 2.43.0\n",
            }
        )
        ctx = ScanContext(
            tools=[_make_tool("git_diff", ["target"])],
            session=session,
        )
        scanner = InjectionScanner()
        findings = await scanner.scan(ctx)

        flagged_tools = {f.tool_name for f in findings}
        assert "git_diff" in flagged_tools

    @pytest.mark.asyncio
    async def test_safe_tool_rejects_flags(self):
        """Tool that rejects flag-like input produces no pattern findings."""
        session = MockSession(
            responses={
                ("safe_git_diff", "--help"): "Error: invalid ref",
                ("safe_git_diff", "--version"): "Error: invalid ref",
            },
            default_response="Error: invalid ref",
        )
        ctx = ScanContext(
            tools=[_make_tool("safe_git_diff", ["target"])],
            session=session,
        )
        scanner = InjectionScanner()
        findings = await scanner.scan(ctx)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_path_traversal_triggers_finding(self):
        """Path traversal payload matched by /etc/passwd pattern."""
        session = MockSession(
            responses={
                ("read_file", "../../../etc/passwd"): (
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                ),
            }
        )
        ctx = ScanContext(
            tools=[_make_tool("read_file", ["filename"])],
            session=session,
        )
        scanner = InjectionScanner()
        findings = await scanner.scan(ctx)

        path_findings = [f for f in findings if "CWE22" in f.rule_id]
        assert len(path_findings) >= 1
        f = path_findings[0]
        assert f.severity == Severity.CRITICAL
        assert f.metadata["detection_mode"] == "pattern"

    @pytest.mark.asyncio
    async def test_safe_path_tool_not_flagged(self):
        """Tool with path validation produces no traversal findings."""
        session = MockSession(
            default_response="Error: path traversal detected",
        )
        ctx = ScanContext(
            tools=[_make_tool("safe_read_file", ["filename"])],
            session=session,
        )
        scanner = InjectionScanner()
        findings = await scanner.scan(ctx)

        path_findings = [f for f in findings if "CWE22" in f.rule_id]
        assert len(path_findings) == 0

    @pytest.mark.asyncio
    async def test_reflected_payload_not_flagged_pattern(self):
        """Response that is just the reflected payload is not flagged."""
        session = MockSession(
            responses={
                ("echo_tool", "--help"): "--help",
            }
        )
        ctx = ScanContext(
            tools=[_make_tool("echo_tool", ["input"])],
            session=session,
        )
        scanner = InjectionScanner()
        findings = await scanner.scan(ctx)

        # --help payload matches "--help" pattern, but the response IS the payload
        pattern_findings = [f for f in findings if f.metadata.get("detection_mode") == "pattern"]
        assert len(pattern_findings) == 0


# ---------------------------------------------------------------------------
# Synthetic tests — error-based detection
# ---------------------------------------------------------------------------


class TestSyntheticErrorBasedDetection:
    """Unit tests for error-based argument injection detection."""

    @pytest.mark.asyncio
    async def test_error_referencing_flag_triggers_finding(self):
        """Error message mentioning injected flag confirms arg injection."""
        session = MockSession(
            error_responses={
                ("git_tool", "--output"): "error: unknown option `--output=/dev/null'",
            }
        )
        ctx = ScanContext(
            tools=[_make_tool("git_tool", ["target"])],
            session=session,
        )
        scanner = InjectionScanner()
        findings = await scanner.scan(ctx)

        error_findings = [f for f in findings if f.metadata.get("detection_mode") == "error_based"]
        assert len(error_findings) >= 1
        f = error_findings[0]
        assert f.severity == Severity.MEDIUM
        assert "CWE88" in f.rule_id

    @pytest.mark.asyncio
    async def test_generic_error_not_flagged(self):
        """Error that doesn't reference the injected flag is not flagged."""
        session = MockSession(
            error_responses={
                ("git_tool", "--output"): "error: repository not found",
            }
        )
        ctx = ScanContext(
            tools=[_make_tool("git_tool", ["target"])],
            session=session,
        )
        scanner = InjectionScanner()
        findings = await scanner.scan(ctx)

        error_findings = [f for f in findings if f.metadata.get("detection_mode") == "error_based"]
        assert len(error_findings) == 0


# ---------------------------------------------------------------------------
# Payload structure and category tests
# ---------------------------------------------------------------------------


class TestPayloadCategories:
    """Test payload category filtering and structure."""

    def test_payload_categories_filter_shell(self):
        """categories=['shell'] returns only shell payloads."""
        payloads = get_injection_payloads(categories=["shell"])
        techniques = {p.technique for p in payloads}
        # Should include shell techniques
        assert "semicolon_chaining" in techniques or "pipe_injection" in techniques
        # Should NOT include argument or path traversal techniques
        assert "flag_injection_help" not in techniques
        assert "path_traversal_unix" not in techniques

    def test_payload_categories_filter_argument(self):
        """categories=['argument'] returns only argument injection payloads."""
        payloads = get_injection_payloads(categories=["argument"])
        for p in payloads:
            assert p.technique.startswith("flag_injection") or p.technique.startswith(
                "short_flag"
            ), f"Unexpected technique: {p.technique}"

    def test_payload_categories_filter_path_traversal(self):
        """categories=['path_traversal'] returns only path traversal payloads."""
        payloads = get_injection_payloads(categories=["path_traversal"])
        for p in payloads:
            assert p.technique.startswith("path_traversal"), f"Unexpected technique: {p.technique}"

    def test_default_categories_returns_all(self):
        """Default (categories=None) returns all payload types."""
        payloads = get_injection_payloads()
        techniques = {p.technique for p in payloads}
        assert "semicolon_chaining" in techniques  # shell
        assert "flag_injection_help" in techniques  # argument
        assert "path_traversal_unix" in techniques  # path_traversal

    def test_platform_filter_with_categories(self):
        """Platform filter works alongside category filter."""
        payloads = get_injection_payloads(platform="unix", categories=["path_traversal"])
        for p in payloads:
            assert p.platform in ("unix", "any"), f"Unexpected platform: {p.platform}"
        # Windows path traversal should be filtered out
        techniques = {p.technique for p in payloads}
        assert "path_traversal_windows" not in techniques

    def test_backward_compatible_shell_only(self):
        """categories=['shell'] returns same count as old get_injection_payloads."""
        shell_payloads = get_injection_payloads(categories=["shell"])
        unix = _unix_payloads()
        windows = _windows_payloads()
        assert len(shell_payloads) == len(unix) + len(windows)


class TestDetectionModes:
    """Test that detection mode metadata is correct on payloads."""

    def test_argument_payloads_have_patterns(self):
        """All pattern-mode argument payloads have response_patterns set."""
        payloads = _argument_injection_payloads()
        pattern_payloads = [p for p in payloads if p.detection_mode == "pattern"]
        assert len(pattern_payloads) >= 1
        for p in pattern_payloads:
            assert len(p.response_patterns) > 0, (
                f"Payload {p.technique} has pattern mode but no patterns"
            )

    def test_path_traversal_payloads_have_patterns(self):
        """All path traversal payloads have response_patterns set."""
        payloads = _path_traversal_payloads()
        for p in payloads:
            assert p.detection_mode == "pattern", f"Payload {p.technique} should use pattern mode"
            assert len(p.response_patterns) > 0, f"Payload {p.technique} missing response_patterns"

    def test_backward_compatibility(self):
        """Existing shell payloads still have detection_mode='canary'."""
        for p in _unix_payloads():
            assert p.detection_mode == "canary", (
                f"Unix payload {p.technique} should use canary mode"
            )
        for p in _windows_payloads():
            assert p.detection_mode == "canary", (
                f"Windows payload {p.technique} should use canary mode"
            )

    def test_error_based_payloads_exist(self):
        """At least one argument payload uses error_based detection."""
        payloads = _argument_injection_payloads()
        error_based = [p for p in payloads if p.detection_mode == "error_based"]
        assert len(error_based) >= 1, "Should have at least one error_based payload"

    def test_injection_payload_fields(self):
        """InjectionPayload has detection_mode and response_patterns fields."""
        p = InjectionPayload(
            value="test",
            canary="",
            technique="test",
            detection_mode="pattern",
            response_patterns=("foo", "bar"),
        )
        assert p.detection_mode == "pattern"
        assert p.response_patterns == ("foo", "bar")

    def test_injection_payload_defaults(self):
        """InjectionPayload defaults detection_mode to 'canary' and response_patterns to ()."""
        p = InjectionPayload(value="test", canary="c", technique="test")
        assert p.detection_mode == "canary"
        assert p.response_patterns == ()
