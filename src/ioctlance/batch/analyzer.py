"""Core batch analyzer for processing multiple drivers."""

import json
import logging
import os
import time
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

from .models import BatchConfig, BatchResult, DriverResult, AnalysisStats, ProcessingMode, OutputFormat
from .processor import ProcessingStrategy, SequentialProcessor, ParallelProcessor, SafeProcessor
from .progress import ProgressTracker, ConsoleProgressTracker, SilentProgressTracker

logger = logging.getLogger(__name__)


class BatchAnalyzer:
    """Main batch analyzer for processing multiple Windows drivers."""

    def __init__(self, config: BatchConfig, console: Console | None = None):
        """Initialize batch analyzer.

        Args:
            config: Batch analysis configuration
            console: Optional Rich console for output
        """
        self.config = config
        self.console = console or Console()
        self.progress_tracker = self._create_progress_tracker()
        self.processor = self._create_processor()

        # Track results
        self.results: list[DriverResult] = []
        self.vulnerable_drivers: list[tuple[str, int]] = []
        self.failed_drivers: list[tuple[str, str]] = []
        self.clean_drivers: list[str] = []

        # Resume support
        self.analyzed_drivers: set[str] = set()
        self._load_previous_results()

    def _create_progress_tracker(self) -> ProgressTracker:
        """Create appropriate progress tracker based on config."""
        if self.config.show_progress:
            return ConsoleProgressTracker(self.console)
        else:
            return SilentProgressTracker()

    def _create_processor(self) -> ProcessingStrategy:
        """Create processing strategy based on config."""
        strategy_map = {
            ProcessingMode.SEQUENTIAL: SequentialProcessor,
            ProcessingMode.PARALLEL: ParallelProcessor,
            ProcessingMode.SAFE: SafeProcessor,
        }

        processor_class = strategy_map.get(self.config.processing_mode, ParallelProcessor)

        return processor_class(self.config, self.progress_tracker)

    def _load_previous_results(self) -> None:
        """Load previous results if resuming."""
        if self.config.resume_from and self.config.resume_from.exists():
            try:
                with open(self.config.resume_from) as f:
                    if self.config.resume_from.suffix == ".jsonl":
                        # Load JSONL format
                        for line in f:
                            data = json.loads(line)
                            if "driver_path" in data:
                                result = DriverResult(**data)
                                self.results.append(result)
                                self.analyzed_drivers.add(str(result.driver_path))
                                self._update_stats_from_result(result)
                    else:
                        # Load JSON format
                        data = json.load(f)
                        if isinstance(data, dict) and "results" in data:
                            for res_data in data["results"]:
                                result = DriverResult(**res_data)
                                self.results.append(result)
                                self.analyzed_drivers.add(str(result.driver_path))
                                self._update_stats_from_result(result)

                if self.analyzed_drivers:
                    self.console.print(
                        f"[yellow]↻[/yellow] Resuming: {len(self.analyzed_drivers)} drivers already analyzed"
                    )
            except Exception as e:
                logger.warning(f"Failed to load previous results: {e}")

    def _update_stats_from_result(self, result: DriverResult) -> None:
        """Update internal statistics from a result."""
        if result.success:
            if result.vuln_count > 0:
                self.vulnerable_drivers.append((result.filename, result.vuln_count))
            else:
                self.clean_drivers.append(result.filename)
        else:
            error_msg = result.error[0] if result.error else "Unknown error"
            self.failed_drivers.append((result.filename, error_msg))

    def find_drivers(self, path: Path) -> list[Path]:
        """Find all .sys files in the given path.

        Args:
            path: Path to search for drivers

        Returns:
            List of driver paths
        """
        if path.is_file():
            return [path] if path.suffix == ".sys" else []

        if self.config.recursive_search:
            return list(path.rglob("*.sys"))
        else:
            return list(path.glob("*.sys"))

    def analyze_path(self, path: Path) -> BatchResult:
        """Analyze all drivers in the given path.

        Args:
            path: Path containing drivers to analyze

        Returns:
            BatchResult with analysis results and statistics
        """
        # Validate path
        if not path.exists():
            raise ValueError(f"Path not found: {path}")

        # Find drivers
        self.console.print(Panel.fit("🔍 Scanning for driver files...", style="cyan"))
        all_drivers = self.find_drivers(path)

        if not all_drivers:
            self.console.print("[red]No .sys files found[/red]")
            return BatchResult(stats=AnalysisStats(), results=[], config=self.config)

        self.console.print(f"[green]✓[/green] Found [bold]{len(all_drivers)}[/bold] driver(s)")

        # Filter out already analyzed drivers
        drivers_to_analyze = [d for d in all_drivers if str(d) not in self.analyzed_drivers]

        if not drivers_to_analyze:
            self.console.print("[green]All drivers already analyzed[/green]")
            return self._create_result()

        # Show analysis configuration
        num_workers = self.config.num_workers or (
            4 if self.config.processing_mode == ProcessingMode.SAFE else len(drivers_to_analyze)
        )

        self.console.print(
            Panel(
                f"[bold]Starting Analysis[/bold]\n"
                f"Drivers to analyze: {len(drivers_to_analyze)}\n"
                f"Processing mode: {self.config.processing_mode.value}\n"
                f"Parallel workers: {num_workers}\n"
                f"Timeout per driver: {self.config.timeout_per_driver}s",
                style="blue",
            )
        )

        # Start analysis
        start_time = time.time()

        # Open output file for streaming if JSONL
        output_file = None
        if self.config.output_format == OutputFormat.JSONL:
            # Open with line buffering (1) for immediate writes
            output_file = open(self.config.output_path, "a" if self.config.resume_from else "w", buffering=1)
            # Write previous results if starting fresh
            if not self.config.resume_from:
                for result in self.results:
                    output_file.write(result.model_dump_json() + "\n")
                    output_file.flush()
                    # Force OS to write to disk
                    os.fsync(output_file.fileno())

        try:
            # Start progress tracking
            self.progress_tracker.start(len(drivers_to_analyze), "Analyzing drivers...")

            # Process drivers
            for result in self.processor.process(drivers_to_analyze):
                self.results.append(result)
                self._update_stats_from_result(result)

                # Stream to JSONL file if configured
                if output_file:
                    output_file.write(result.model_dump_json() + "\n")
                    output_file.flush()
                    # Force OS to write to disk immediately
                    os.fsync(output_file.fileno())

                    # Debug: Log file size after write
                    if self.config.verbose:
                        file_size = self.config.output_path.stat().st_size
                        logger.info(f"Written result for {result.filename}, file size: {file_size} bytes")

            # Finish progress tracking
            self.progress_tracker.finish()

        finally:
            if output_file:
                output_file.close()

        analysis_time = time.time() - start_time

        # Create final result
        result = self._create_result(analysis_time)

        # Apply filters if requested
        if self.config.filter_vulnerable:
            result.results = [r for r in result.results if r.vuln_count > 0]

        # Save results (skip if JSONL since we already streamed)
        if self.config.output_format != OutputFormat.JSONL:
            result.save()
        else:
            # For JSONL, just append the summary stats
            with open(self.config.output_path, "a") as f:
                f.write(result.stats.model_dump_json() + "\n")

        # Show summary
        if isinstance(self.progress_tracker, ConsoleProgressTracker):
            self.progress_tracker.show_summary(
                result.stats.model_dump(), self.vulnerable_drivers if self.vulnerable_drivers else None
            )

        self.console.print(f"\n[green]Results saved to:[/green] {self.config.output_path}")

        return result

    def _create_result(self, analysis_time: float | None = None) -> BatchResult:
        """Create BatchResult from current state.

        Args:
            analysis_time: Total analysis time in seconds

        Returns:
            BatchResult object
        """
        # Calculate statistics
        total_vulns = sum(r.vuln_count for r in self.results)
        analyzed_count = len([r for r in self.results if r.success])

        stats = AnalysisStats(
            total_drivers=len(self.results),
            analyzed=analyzed_count,
            failed=len(self.failed_drivers),
            with_vulnerabilities=len(self.vulnerable_drivers),
            total_vulnerabilities=total_vulns,
            analysis_time=analysis_time or 0,
            average_time_per_driver=(analysis_time / analyzed_count if analysis_time and analyzed_count else 0),
            workers_used=getattr(self.processor, "num_workers", None),
        )

        # Add memory stats for safe mode
        if self.config.processing_mode == ProcessingMode.SAFE:
            if hasattr(self.processor, "memory_monitor"):
                mem_stats = self.processor.memory_monitor.get_stats()
                stats.memory_peak_gb = mem_stats.get("peak_gb")

        return BatchResult(stats=stats, results=self.results, config=self.config)
