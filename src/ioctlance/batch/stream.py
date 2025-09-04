"""Streaming JSONL writer for batch results."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .models import DriverResult, BatchConfig
from ..output.manager import UnifiedAnalysisResult


class JSONLStreamer:
    """Minimal, robust JSONL writer with optional fsync."""

    def __init__(self, cfg: BatchConfig):
        self.cfg = cfg
        mode = "ab" if cfg.resume_from and cfg.resume_from == cfg.output_path else "wb"
        # Unbuffered binary mode for immediate writes regardless of stdio buffering
        self._fh = open(cfg.output_path, mode, buffering=0)

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

    def write_unified(self, driver: Path, unified: UnifiedAnalysisResult) -> None:
        # Vulnerabilities
        for vuln in unified.vulnerabilities:
            self._write(
                {
                    "type": "vulnerability",
                    "driver": str(driver),
                    "fingerprint": unified.fingerprint.model_dump(),
                    "data": vuln.to_summary_dict(),
                }
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
