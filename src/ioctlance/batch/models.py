"""Data models for batch analysis."""

from enum import Enum
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field, field_validator


class ProcessingMode(str, Enum):
    """Processing strategies for batch analysis."""

    PARALLEL = "parallel"
    SAFE = "safe"
    SEQUENTIAL = "sequential"


class OutputFormat(str, Enum):
    """Output formats for results."""

    JSON = "json"
    JSONL = "jsonl"


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
    data: dict[str, Any] = Field(default_factory=dict, description="Complete analysis data")

    class Config:
        arbitrary_types_allowed = True


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
                    f.write(result.model_dump_json() + "\n")
                f.write(self.stats.model_dump_json() + "\n")
        else:
            with open(output_path, "w") as f:
                data = {**self.stats.model_dump(), "results": [r.model_dump() for r in self.results]}
                import json

                json.dump(data, f, indent=2, default=str)
