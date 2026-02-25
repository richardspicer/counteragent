"""Scanner module registry.

Maintains a registry of available scanner modules. The CLI and
orchestrator use this to discover, filter, and instantiate scanners.
"""

from __future__ import annotations

from counteragent.scan.scanner.audit_telemetry import AuditTelemetryScanner
from counteragent.scan.scanner.auth import AuthScanner
from counteragent.scan.scanner.base import BaseScanner
from counteragent.scan.scanner.context_sharing import ContextSharingScanner
from counteragent.scan.scanner.injection import InjectionScanner
from counteragent.scan.scanner.permissions import PermissionsScanner
from counteragent.scan.scanner.prompt_injection import PromptInjectionScanner
from counteragent.scan.scanner.shadow_servers import ShadowServersScanner
from counteragent.scan.scanner.supply_chain import SupplyChainScanner
from counteragent.scan.scanner.token_exposure import TokenExposureScanner
from counteragent.scan.scanner.tool_poisoning import ToolPoisoningScanner

# All available scanner classes, keyed by their CLI name.
# Add new scanners here as they're implemented.
_REGISTRY: dict[str, type[BaseScanner]] = {
    "injection": InjectionScanner,
    "auth": AuthScanner,
    "permissions": PermissionsScanner,
    "tool_poisoning": ToolPoisoningScanner,
    "prompt_injection": PromptInjectionScanner,
    "audit_telemetry": AuditTelemetryScanner,
    "context_sharing": ContextSharingScanner,
    "shadow_servers": ShadowServersScanner,
    "supply_chain": SupplyChainScanner,
    "token_exposure": TokenExposureScanner,
}


def get_scanner(name: str) -> BaseScanner:
    """Instantiate a scanner by name.

    Args:
        name: Scanner CLI name (e.g., 'injection').

    Returns:
        An instance of the requested scanner.

    Raises:
        KeyError: If the scanner name is not registered.
    """
    if name not in _REGISTRY:
        available = ", ".join(sorted(_REGISTRY.keys()))
        raise KeyError(f"Unknown scanner '{name}'. Available: {available}")
    return _REGISTRY[name]()


def get_all_scanners() -> list[BaseScanner]:
    """Instantiate all registered scanners.

    Returns:
        List of all available scanner instances.
    """
    return [cls() for cls in _REGISTRY.values()]


def list_scanner_names() -> list[str]:
    """Get names of all registered scanners.

    Returns:
        Sorted list of scanner CLI names.
    """
    return sorted(_REGISTRY.keys())
