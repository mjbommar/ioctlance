"""Verifier for double-free vulnerabilities."""

import logging
from typing import Any, Optional

from .base import VulnerabilityVerifier, VerificationResult
from .registry import verifier_registry

logger = logging.getLogger(__name__)


class DoubleFreeVerifier(VulnerabilityVerifier):
    """Verifies double-free vulnerabilities to filter false positives."""

    @property
    def name(self) -> str:
        return "double_free_verifier"

    @property
    def vulnerability_types(self) -> list[str]:
        return ["double_free", "double-free"]

    def can_verify(self, vuln_info: dict[str, Any]) -> bool:
        """Check if this is a double-free vulnerability."""
        title = vuln_info.get("title", "").lower()
        return "double" in title and "free" in title

    def verify(self, vuln_info: dict[str, Any]) -> tuple[VerificationResult, dict[str, Any]]:
        """Verify double-free vulnerability.

        Common false positive patterns:
        1. first_free_site == second_free_site (same location)
        2. Free site at impossible addresses (0x100038)
        3. No allocation site tracked
        """
        params = vuln_info.get("parameters", {})

        # Extract free sites
        first_site = params.get("first_free_site", "unknown")
        second_site = params.get("second_free_site", "unknown")
        allocation_site = params.get("allocation_site", "unknown")
        address = params.get("address", "unknown")

        # Check for false positive patterns
        confidence = 1.0
        evidence = []

        # Pattern 1: Same free sites (likely detection bug)
        if first_site == second_site:
            evidence.append(f"First and second free sites identical: {first_site}")
            confidence *= 0.3  # High chance of false positive

        # Pattern 2: Suspicious addresses
        if isinstance(first_site, str):
            try:
                site_int = int(first_site, 16) if first_site.startswith("0x") else int(first_site)
                # Check for unrealistic addresses
                if site_int < 0x400000:  # Below typical driver base
                    evidence.append(f"Suspicious free site address: {first_site}")
                    confidence *= 0.5

                # Common false positive addresses from hooks
                if site_int in [0x100038, 0x100030, 0x100060]:
                    evidence.append(f"Hook stub address detected: {first_site}")
                    confidence *= 0.2
            except:
                pass

        # Pattern 3: No allocation tracking
        if allocation_site == "unknown" or allocation_site == "0x0":
            evidence.append("No allocation site tracked")
            confidence *= 0.7

        # Pattern 4: Check address validity
        if isinstance(address, str) and address.startswith("0x5"):
            # Addresses starting with 0x5 are typically symbolic/test addresses
            evidence.append(f"Symbolic test address: {address}")
            confidence *= 0.8

        # Determine result based on confidence
        if confidence < 0.3:
            # Likely false positive
            enhanced = vuln_info.copy()
            enhanced["false_positive_evidence"] = evidence
            enhanced["confidence"] = confidence
            logger.info(f"Double-free likely false positive: {evidence}")
            return VerificationResult.FALSE_POSITIVE, enhanced

        elif confidence < 0.7:
            # Needs manual review
            enhanced = vuln_info.copy()
            enhanced["review_notes"] = evidence
            enhanced["confidence"] = confidence

            if "others" not in enhanced:
                enhanced["others"] = {}
            enhanced["others"]["requires_manual_review"] = True
            enhanced["others"]["confidence"] = "LOW"

            return VerificationResult.NEEDS_REVIEW, enhanced

        else:
            # Appears legitimate
            enhanced = vuln_info.copy()
            enhanced["verification_confidence"] = confidence

            if evidence:
                enhanced["verification_notes"] = evidence

            return VerificationResult.CONFIRMED, enhanced


# Register the verifier
verifier_registry.register(DoubleFreeVerifier)
