"""Verification manager for post-detection analysis."""

import logging
from typing import Any, Optional
from enum import Enum

from .base import VerificationResult
from .registry import verifier_registry

logger = logging.getLogger(__name__)


class VerificationLevel(Enum):
    """Verification depth levels."""

    NONE = 0  # No verification (fastest)
    BASIC = 1  # Basic checks only
    STANDARD = 2  # Standard verification (default)
    DEEP = 3  # Deep analysis (slowest)


class VerificationManager:
    """Manages post-detection verification of vulnerabilities."""

    def __init__(self, context: Any, level: VerificationLevel = VerificationLevel.STANDARD):
        """Initialize verification manager.

        Args:
            context: Analysis context
            level: Verification level to use
        """
        self.context = context
        self.level = level
        self.stats = {
            "total_verified": 0,
            "confirmed": 0,
            "false_positives": 0,
            "reclassified": 0,
            "needs_review": 0,
            "skipped": 0,
        }

    @property
    def enabled(self) -> bool:
        """Check if verification is enabled."""
        return self.level != VerificationLevel.NONE

    def verify_vulnerability(self, vuln_info: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Verify a detected vulnerability.

        Args:
            vuln_info: Initial vulnerability detection

        Returns:
            Enhanced vulnerability info or None if filtered as false positive
        """
        if not self.enabled:
            self.stats["skipped"] += 1
            return vuln_info

        self.stats["total_verified"] += 1

        # Get applicable verifiers
        verifiers = verifier_registry.get_applicable_verifiers(vuln_info, self.context)

        if not verifiers:
            # No verifiers available, return original
            logger.debug(f"No verifiers for: {vuln_info.get('title', 'unknown')}")
            return vuln_info

        # Apply verifiers based on level
        if self.level == VerificationLevel.BASIC:
            verifiers = verifiers[:1]  # Use only first/primary verifier
        elif self.level == VerificationLevel.DEEP:
            pass  # Use all verifiers
        else:  # STANDARD
            verifiers = verifiers[:2]  # Use up to 2 verifiers

        # Run verification
        final_result = None
        final_info = vuln_info

        for verifier in verifiers:
            try:
                logger.debug(f"Running verifier: {verifier.name}")
                result, enhanced_info = verifier.verify(final_info)

                # Update stats
                if result == VerificationResult.CONFIRMED:
                    self.stats["confirmed"] += 1
                    final_result = result
                    final_info = enhanced_info

                elif result == VerificationResult.FALSE_POSITIVE:
                    self.stats["false_positives"] += 1
                    logger.info(f"False positive filtered: {vuln_info.get('title')}")
                    return None  # Filter out false positive

                elif result == VerificationResult.RECLASSIFIED:
                    self.stats["reclassified"] += 1
                    final_result = result
                    final_info = enhanced_info
                    logger.info(f"Vulnerability reclassified: {vuln_info.get('title')} -> {enhanced_info.get('title')}")

                elif result == VerificationResult.NEEDS_REVIEW:
                    self.stats["needs_review"] += 1
                    if final_result is None:
                        final_result = result
                    final_info = enhanced_info

            except Exception as e:
                logger.error(f"Verifier {verifier.name} failed: {e}")
                continue

        # Add verification metadata
        if "verification" not in final_info:
            final_info["verification"] = {}

        final_info["verification"]["level"] = self.level.name
        final_info["verification"]["result"] = final_result.value if final_result else "unverified"
        final_info["verification"]["verifiers_run"] = [v.name for v in verifiers]

        return final_info

    def verify_batch(self, vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Verify a batch of vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability detections

        Returns:
            Filtered and enhanced vulnerability list
        """
        verified = []

        for vuln in vulnerabilities:
            result = self.verify_vulnerability(vuln)
            if result is not None:
                verified.append(result)

        logger.info(f"Verification complete: {len(verified)}/{len(vulnerabilities)} passed")
        logger.info(
            f"Stats: {self.stats['confirmed']} confirmed, "
            f"{self.stats['reclassified']} reclassified, "
            f"{self.stats['false_positives']} false positives filtered"
        )

        return verified

    def print_stats(self) -> None:
        """Print verification statistics."""
        if self.stats["total_verified"] == 0:
            print("No vulnerabilities verified")
            return

        print(f"\nVerification Statistics (Level: {self.level.name}):")
        print(f"  Total Verified: {self.stats['total_verified']}")
        print(f"  Confirmed: {self.stats['confirmed']}")
        print(f"  Reclassified: {self.stats['reclassified']}")
        print(f"  False Positives: {self.stats['false_positives']}")
        print(f"  Needs Review: {self.stats['needs_review']}")
        print(f"  Skipped: {self.stats['skipped']}")

        if self.stats["false_positives"] > 0:
            fp_rate = (self.stats["false_positives"] / self.stats["total_verified"]) * 100
            print(f"  False Positive Rate: {fp_rate:.1f}%")
