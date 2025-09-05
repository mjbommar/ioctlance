"""Registry for vulnerability verifiers."""

import logging
from typing import Type, Optional, Any

from .base import VulnerabilityVerifier

logger = logging.getLogger(__name__)


class VerifierRegistry:
    """Registry for managing vulnerability verifiers."""

    def __init__(self):
        """Initialize verifier registry."""
        self._verifiers: dict[str, Type[VulnerabilityVerifier]] = {}
        self._instances: dict[str, VulnerabilityVerifier] = {}

    def register(self, verifier_class: Type[VulnerabilityVerifier]) -> None:
        """Register a verifier class.

        Args:
            verifier_class: Verifier class to register
        """
        # Create a temporary instance to get the name
        temp = verifier_class(None)
        name = temp.name

        if name in self._verifiers:
            logger.warning(f"Overwriting verifier: {name}")

        self._verifiers[name] = verifier_class
        logger.debug(f"Registered verifier: {name}")

    def unregister(self, name: str) -> None:
        """Unregister a verifier.

        Args:
            name: Name of verifier to unregister
        """
        if name in self._verifiers:
            del self._verifiers[name]
            if name in self._instances:
                del self._instances[name]
            logger.debug(f"Unregistered verifier: {name}")

    def get_verifier(self, name: str, context: Any) -> Optional[VulnerabilityVerifier]:
        """Get a verifier instance.

        Args:
            name: Name of verifier
            context: Analysis context

        Returns:
            Verifier instance or None
        """
        if name not in self._verifiers:
            return None

        # Create instance if needed
        if name not in self._instances:
            self._instances[name] = self._verifiers[name](context)

        return self._instances[name]

    def get_applicable_verifiers(self, vuln_info: dict, context: Any) -> list[VulnerabilityVerifier]:
        """Get all verifiers that can handle a vulnerability.

        Args:
            vuln_info: Vulnerability information
            context: Analysis context

        Returns:
            List of applicable verifier instances
        """
        applicable = []

        for name, verifier_class in self._verifiers.items():
            if name not in self._instances:
                self._instances[name] = verifier_class(context)

            verifier = self._instances[name]
            if verifier.enabled and verifier.can_verify(vuln_info):
                applicable.append(verifier)

        return applicable

    def list_verifiers(self) -> list[str]:
        """List all registered verifier names.

        Returns:
            List of verifier names
        """
        return list(self._verifiers.keys())


# Global registry instance
verifier_registry = VerifierRegistry()
