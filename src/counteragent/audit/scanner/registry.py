"""Scanner module registry.

Maintains a registry of available scanner modules. The CLI and
orchestrator use this to discover, filter, and instantiate scanners.
"""

from __future__ import annotations

from counteragent.audit.scanner.audit_telemetry import AuditTelemetryScanner
from counteragent.audit.scanner.auth import AuthScanner
from counteragent.audit.scanner.base import BaseScanner
from counteragent.audit.scanner.context_sharing import ContextSharingScanner
from counteragent.audit.scanner.injection import InjectionScanner
from counteragent.audit.scanner.permissions import PermissionsScanner
from counteragent.audit.scanner.prompt_injection import PromptInjectionScanner
from counteragent.audit.scanner.shadow_servers import ShadowServersScanner
from counteragent.audit.scanner.supply_chain import SupplyChainScanner
from counteragent.audit.scanner.token_exposure import TokenExposureScanner
from counteragent.audit.scanner.tool_poisoning import ToolPoisoningScanner

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
