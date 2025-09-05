"""Base class for vulnerability verifiers."""

from abc import ABC, abstractmethod
from typing import Any, Optional
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class VerificationResult(Enum):
    """Result of vulnerability verification."""

    CONFIRMED = "confirmed"  # Vulnerability is real
    FALSE_POSITIVE = "false_positive"  # Definitely a false positive
    RECLASSIFIED = "reclassified"  # Different vulnerability type
    NEEDS_REVIEW = "needs_review"  # Cannot determine automatically


class VulnerabilityVerifier(ABC):
    """Base class for post-detection vulnerability verification.

    Verifiers perform deep analysis on suspected vulnerabilities to:
    - Confirm true positives
    - Filter false positives
    - Reclassify misidentified vulnerabilities
    - Add root cause analysis
    """

    def __init__(self, context: Any):
        """Initialize verifier.

        Args:
            context: Analysis context containing configuration and state
        """
        self.context = context
        self.enabled = True

    @property
    @abstractmethod
    def name(self) -> str:
        """Return verifier name."""
        pass

    @property
    @abstractmethod
    def vulnerability_types(self) -> list[str]:
        """Return list of vulnerability types this verifier handles.

        Examples: ["buffer_overflow", "null_pointer", "unconstrained_state"]
        """
        pass

    @abstractmethod
    def can_verify(self, vuln_info: dict[str, Any]) -> bool:
        """Check if this verifier can handle this vulnerability.

        Args:
            vuln_info: Vulnerability information from initial detection

        Returns:
            True if this verifier should analyze this vulnerability
        """
        pass

    @abstractmethod
    def verify(self, vuln_info: dict[str, Any]) -> tuple[VerificationResult, dict[str, Any]]:
        """Perform deep verification of suspected vulnerability.

        Args:
            vuln_info: Initial vulnerability detection info

        Returns:
            Tuple of (result, enhanced_info) where:
            - result: Verification result enum
            - enhanced_info: Updated vulnerability info with root cause analysis
        """
        pass

    def extract_ioctl_code(self, vuln_info: dict[str, Any]) -> Optional[int]:
        """Extract IOCTL code from vulnerability info.

        Args:
            vuln_info: Vulnerability information

        Returns:
            IOCTL code as integer or None
        """
        try:
            # Try eval field first
            if "eval" in vuln_info and "IoControlCode" in vuln_info["eval"]:
                ioctl_str = vuln_info["eval"]["IoControlCode"]
                if isinstance(ioctl_str, str) and ioctl_str.startswith("0x"):
                    return int(ioctl_str, 16)

            # Try state globals
            state = vuln_info.get("state")
            if state and hasattr(state, "globals") and "IoControlCode" in state.globals:
                return state.globals["IoControlCode"]

            # Try context io_control_code
            if self.context and hasattr(self.context, "io_control_code"):
                icc = self.context.io_control_code
                if state and hasattr(state, "solver"):
                    return state.solver.eval_one(icc, default=None)

        except Exception as e:
            logger.debug(f"Failed to extract IOCTL code: {e}")

        return None

    def get_state(self, vuln_info: dict[str, Any]) -> Optional[Any]:
        """Extract SimState from vulnerability info.

        Args:
            vuln_info: Vulnerability information

        Returns:
            SimState object or None
        """
        state = vuln_info.get("state")
        if state and hasattr(state, "solver"):
            return state
        return None
