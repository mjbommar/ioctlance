"""Models for redesigned batch processing pipeline."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from ..output.formats import OutputFormat
from ..output.manager import UnifiedAnalysisResult


class ProcessingMode(str, Enum):
    """Processing strategies for batch analysis."""

    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"


class BatchConfig(BaseModel):
    """Configuration for batch analysis runs."""

    output_path: Path = Field(description="Output file path (JSON or JSONL)")
    output_format: OutputFormat = Field(default=OutputFormat.JSONL)
    timeout_per_driver: int = Field(default=120, ge=1, description="Timeout per driver in seconds")
    processing_mode: ProcessingMode = Field(default=ProcessingMode.PARALLEL)
    num_workers: int | None = Field(None, ge=1, description="Number of parallel workers")
    recursive_search: bool = Field(default=True, description="Recursively search subdirectories")
    filter_vulnerable: bool = Field(default=False, description="Only emit drivers with vulnerabilities")
    resume_from: Path | None = Field(None, description="Resume from previous result file (JSON/JSONL)")
    verbose: bool = Field(default=False, description="Enable verbose output")
    show_progress: bool = Field(default=True, description="Show progress display via Rich")
    analysis_profile: str | None = Field(None, description="Analysis profile (fast, balanced, thorough, paranoid)")
    fsync_writes: bool = Field(default=True, description="Force fsync after each JSONL write")
    # Search strategy controls
    search_strategy: str = Field(default="beam", description="Search strategy: dfs or beam")
    beam_width: int = Field(default=64, ge=1, description="Beam width for beam search")
    triage_steps: int = Field(default=3000, ge=0, description="Triage window steps for beam search")
    triage_beam_width: int | None = Field(default=24, description="Beam width during triage window")

    @field_validator("output_path")
    @classmethod
    def _ensure_parent_dir(cls, v: Path) -> Path:
        v.parent.mkdir(parents=True, exist_ok=True)
        return v


class DriverResult(BaseModel):
    """Result of a single driver analysis."""

    driver_path: Path
    filename: str
    success: bool
    analysis_time: float
    vuln_count: int = 0
    error: list[str] | None = None
    data: UnifiedAnalysisResult | dict[str, Any] = Field(default_factory=dict)

    class Config:
        arbitrary_types_allowed = True

    @property
    def unified(self) -> UnifiedAnalysisResult | None:
        return self.data if isinstance(self.data, UnifiedAnalysisResult) else None


class AnalysisStats(BaseModel):
    total_drivers: int = 0
    analyzed: int = 0
    failed: int = 0
    with_vulnerabilities: int = 0
    total_vulnerabilities: int = 0
    analysis_time: float = 0.0
    average_time_per_driver: float = 0.0
    workers_used: int | None = None


class BatchResult(BaseModel):
    stats: AnalysisStats
    results: list[DriverResult] = Field(default_factory=list)
    config: BatchConfig
