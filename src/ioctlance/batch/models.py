"""Data models for batch analysis."""

import json
from enum import Enum
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field, field_validator

# Import OutputFormat from unified location
from ..output.formats import OutputFormat
from ..output.manager import UnifiedAnalysisResult


class ProcessingMode(str, Enum):
    """Processing strategies for batch analysis."""

    PARALLEL = "parallel"
    SAFE = "safe"
    SEQUENTIAL = "sequential"


class BatchConfig(BaseModel):
    """Configuration for batch analysis."""

    output_path: Path = Field(description="Output file path")
    output_format: OutputFormat = Field(default=OutputFormat.JSON)
    timeout_per_driver: int = Field(default=120, ge=1, description="Timeout per driver in seconds")
    processing_mode: ProcessingMode = Field(default=ProcessingMode.PARALLEL)
    num_workers: int | None = Field(None, ge=1, description="Number of parallel workers")
    batch_size: int = Field(default=100, ge=1, description="Batch size for safe mode")
    memory_threshold_gb: float = Field(default=80.0, ge=1.0, description="Memory threshold in GB")
    memory_percent_threshold: int = Field(default=85, ge=1, le=100, description="Memory percent threshold")
    recursive_search: bool = Field(default=True, description="Recursively search subdirectories")
    filter_vulnerable: bool = Field(default=False, description="Only output drivers with vulnerabilities")
    resume_from: Path | None = Field(None, description="Resume from previous results file")
    verbose: bool = Field(default=False, description="Enable verbose output")
    show_progress: bool = Field(default=True, description="Show progress display")
    analysis_profile: str | None = Field(None, description="Analysis profile (fast, balanced, thorough, paranoid)")

    @field_validator("output_path")
    @classmethod
    def validate_output_path(cls, v: Path) -> Path:
        """Ensure output directory exists."""
        v.parent.mkdir(parents=True, exist_ok=True)
        return v


class DriverResult(BaseModel):
    """Result for a single driver analysis."""

    driver_path: Path
    filename: str
    success: bool
    analysis_time: float
    vuln_count: int = 0
    error: list[str] | None = None
    data: UnifiedAnalysisResult | dict[str, Any] = Field(
        default_factory=dict, description="Complete analysis data - preferably UnifiedAnalysisResult"
    )

    class Config:
        arbitrary_types_allowed = True

    @property
    def unified_result(self) -> UnifiedAnalysisResult | None:
        """Get unified analysis result if available."""
        if isinstance(self.data, UnifiedAnalysisResult):
            return self.data
        return None

    def to_legacy_format(self) -> dict[str, Any]:
        """Convert to legacy format for backward compatibility."""
        if isinstance(self.data, UnifiedAnalysisResult):
            # Convert unified result back to legacy format
            legacy_data = {}

            # Basic information
            if self.data.raw_result:
                legacy_data.update(self.data.raw_result.model_dump())

            # Add metadata
            legacy_data["driver_path"] = str(self.driver_path)
            legacy_data["filename"] = self.filename
            legacy_data["analysis_time"] = self.analysis_time
            legacy_data["success"] = self.success
            legacy_data["vuln_count"] = self.vuln_count
            if self.error:
                legacy_data["error"] = self.error

            return legacy_data
        else:
            # Already in legacy format
            return self.data if isinstance(self.data, dict) else {}


class AnalysisStats(BaseModel):
    """Statistics for batch analysis."""

    total_drivers: int = 0
    analyzed: int = 0
    failed: int = 0
    with_vulnerabilities: int = 0
    total_vulnerabilities: int = 0
    analysis_time: float = 0.0
    average_time_per_driver: float = 0.0
    memory_peak_gb: float | None = None
    workers_used: int | None = None


class BatchResult(BaseModel):
    """Complete batch analysis result."""

    stats: AnalysisStats
    results: list[DriverResult] = Field(default_factory=list)
    config: BatchConfig

    def save(self, path: Path | None = None) -> None:
        """Save results to file."""
        output_path = path or self.config.output_path

        if self.config.output_format == OutputFormat.JSONL:
            with open(output_path, "w") as f:
                for result in self.results:
                    # Save unified results in JSONL format
                    if result.unified_result:
                        # Save each vulnerability as a separate line
                        for vuln in result.unified_result.vulnerabilities:
                            vuln_data = {
                                "type": "vulnerability",
                                "driver": str(result.driver_path),
                                "data": vuln.to_summary_dict(),
                            }
                            f.write(json.dumps(vuln_data, default=str) + "\n")

                        # Save summary as separate line
                        summary_data = {
                            "type": "summary",
                            "driver": str(result.driver_path),
                            "data": result.unified_result.summary.model_dump(),
                        }
                        f.write(json.dumps(summary_data, default=str) + "\n")
                    else:
                        # Fallback to legacy format
                        legacy_data = {
                            "type": "legacy_result",
                            "driver": str(result.driver_path),
                            "data": result.to_legacy_format(),
                        }
                        f.write(json.dumps(legacy_data, default=str) + "\n")

                # Save stats
                f.write(json.dumps({"type": "batch_stats", "data": self.stats.model_dump()}, default=str) + "\n")
        else:
            # JSON format

            with open(output_path, "w") as f:
                results_data = []
                for result in self.results:
                    if result.unified_result:
                        # Use unified format
                        result_data = {
                            "driver": str(result.driver_path),
                            "success": result.success,
                            "analysis_time": result.analysis_time,
                            "vuln_count": result.vuln_count,
                            "unified_analysis": result.unified_result.model_dump(),
                        }
                        if result.error:
                            result_data["error"] = result.error
                    else:
                        # Use legacy format
                        result_data = {
                            "driver": str(result.driver_path),
                            "success": result.success,
                            "analysis_time": result.analysis_time,
                            "vuln_count": result.vuln_count,
                            "legacy_analysis": result.to_legacy_format(),
                        }
                        if result.error:
                            result_data["error"] = result.error

                    results_data.append(result_data)

                data = {**self.stats.model_dump(), "results": results_data}

                json.dump(data, f, indent=2, default=str)
