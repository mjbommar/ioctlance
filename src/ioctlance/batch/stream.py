"""Streaming JSONL writer for batch results."""

from __future__ import annotations

import json
import os
import logging
from pathlib import Path
from typing import Any, Optional

from .models import DriverResult, BatchConfig
from ..output.manager import UnifiedAnalysisResult

logger = logging.getLogger(__name__)


class JSONLStreamer:
    """Minimal, robust JSONL writer with optional fsync and verification."""

    def __init__(self, cfg: BatchConfig):
        self.cfg = cfg
        mode = "ab" if cfg.resume_from and cfg.resume_from == cfg.output_path else "wb"
        # Unbuffered binary mode for immediate writes regardless of stdio buffering
        self._fh = open(cfg.output_path, mode, buffering=0)

        # Initialize verification manager if enabled
        self._verification_manager: Optional[Any] = None
        self._verification_stats = {"total": 0, "verified": 0, "false_positives": 0, "reclassified": 0}

        if cfg.verification_enabled and cfg.verification_level != "none":
            try:
                from ..verification.manager import VerificationManager, VerificationLevel
                from ..verification.registry import verifier_registry

                # Import verifiers to register them
                from ..verification.unconstrained_verifier import UnconstrainedStateVerifier
                from ..verification.double_free_verifier import DoubleFreeVerifier

                level_map = {
                    "basic": VerificationLevel.BASIC,
                    "standard": VerificationLevel.STANDARD,
                    "deep": VerificationLevel.DEEP,
                }
                level = level_map.get(cfg.verification_level, VerificationLevel.STANDARD)

                # Create mock context for verification
                class MockContext:
                    def __init__(self):
                        self.config = cfg
                        self.io_control_code = None

                self._verification_manager = VerificationManager(MockContext(), level)
                logger.info(f"Verification enabled at level: {cfg.verification_level}")
            except Exception as e:
                logger.warning(f"Failed to initialize verification: {e}")
                self._verification_manager = None

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass

    def _write(self, obj: dict[str, Any]) -> None:
        data = (json.dumps(obj, default=str) + "\n").encode("utf-8")
        self._fh.write(data)
        if self.cfg.fsync_writes:
            os.fsync(self._fh.fileno())

    def write_event(self, event_type: str, **fields: Any) -> None:
        rec = {"type": event_type}
        rec.update(fields)
        self._write(rec)

    def _verify_vulnerability(self, vuln_dict: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Verify a vulnerability and return verified version or None if filtered."""
        if not self._verification_manager:
            return vuln_dict

        self._verification_stats["total"] += 1

        # Create mock state if eval parameters exist
        if "eval" in vuln_dict.get("vulnerability", {}):
            eval_params = vuln_dict["vulnerability"]["eval"]

            # Create minimal mock state for verification
            class MockState:
                def __init__(self, params):
                    self.solver = MockSolver(params)
                    self.inspect = MockInspect(params)
                    self.globals = params
                    self.history = MockHistory()

            class MockSolver:
                def __init__(self, params):
                    self.params = params

                def eval_one(self, val, default=None):
                    # Check for NULL buffer
                    sys_buf = self.params.get("SystemBuffer", "0x0")
                    if sys_buf == "0x0":
                        return 0
                    return default if default is not None else 0x1000

                def symbolic(self, val):
                    return False

            class MockInspect:
                def __init__(self, params):
                    sys_buf = params.get("SystemBuffer", "0x0")
                    if sys_buf == "0x0":
                        self.mem_read_address = 0
                        self.mem_write_address = 0
                    else:
                        self.mem_read_address = None
                        self.mem_write_address = None

            class MockHistory:
                def __init__(self):
                    self.descriptions = type("obj", (object,), {"hardcopy": []})()

            vuln_dict["vulnerability"]["state"] = MockState(eval_params)

        # Verify the vulnerability
        verified = self._verification_manager.verify_vulnerability(vuln_dict["vulnerability"])

        if verified is None:
            self._verification_stats["false_positives"] += 1
            return None  # Filtered as false positive

        # Check for reclassification
        original_title = vuln_dict["vulnerability"].get("title", "")
        new_title = verified.get("title", "")
        if new_title != original_title:
            self._verification_stats["reclassified"] += 1
            logger.debug(f"Reclassified: {original_title} -> {new_title}")

        self._verification_stats["verified"] += 1

        # Remove non-serializable state
        if "state" in verified:
            del verified["state"]

        vuln_dict["vulnerability"] = verified
        return vuln_dict

    def write_unified(self, driver: Path, unified: UnifiedAnalysisResult) -> None:
        # Process vulnerabilities through verification queue
        verified_vulns = []

        for vuln in unified.vulnerabilities:
            vuln_dict = {
                "vulnerability": vuln.to_summary_dict(),
                "metadata": {"driver": str(driver), "fingerprint": unified.fingerprint.model_dump()},
            }

            # Verify vulnerability (may filter false positives)
            if self._verification_manager and self.cfg.verification_enabled:
                verified_dict = self._verify_vulnerability(vuln_dict)
                if verified_dict is None and self.cfg.filter_false_positives:
                    continue  # Skip false positive
                elif verified_dict:
                    vuln_dict = verified_dict

            verified_vulns.append(vuln_dict)

        # Write verified vulnerabilities
        for vuln_dict in verified_vulns:
            self._write(
                {
                    "type": "vulnerability",
                    "driver": str(driver),
                    "fingerprint": vuln_dict["metadata"]["fingerprint"],
                    "data": vuln_dict["vulnerability"],
                }
            )

        # Log verification stats periodically
        if self._verification_stats["total"] > 0 and self._verification_stats["total"] % 100 == 0:
            logger.info(
                f"Verification stats: {self._verification_stats['verified']}/{self._verification_stats['total']} verified, "
                f"{self._verification_stats['false_positives']} FPs filtered, "
                f"{self._verification_stats['reclassified']} reclassified"
            )

        # Summary line
        self._write(
            {
                "type": "summary",
                "driver": str(driver),
                "fingerprint": unified.fingerprint.model_dump(),
                "data": unified.summary.model_dump(),
                "metrics": unified.metrics,
                "errors": unified.errors,
                "warnings": unified.warnings,
                "verification_stats": self._verification_stats if self._verification_manager else None,
            }
        )

    def write_legacy(self, driver: Path, legacy: dict[str, Any]) -> None:
        self._write(
            {
                "type": "legacy_result",
                "driver": str(driver),
                "data": legacy,
            }
        )

    def write_driver_result(self, result: DriverResult) -> None:
        if isinstance(result.data, UnifiedAnalysisResult):
            self.write_unified(result.driver_path, result.data)
        elif isinstance(result.data, dict):
            self.write_legacy(result.driver_path, result.data)
        else:
            # Fallback minimal line
            self._write(
                {
                    "type": "driver_result",
                    "driver": str(result.driver_path),
                    "success": result.success,
                    "analysis_time": result.analysis_time,
                    "vuln_count": result.vuln_count,
                    "error": result.error,
                }
            )
