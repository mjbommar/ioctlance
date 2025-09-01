"""Processing strategies for batch analysis."""

import logging
import time
from abc import ABC, abstractmethod
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from collections.abc import Iterator
import multiprocessing

from ..core.analysis_context import AnalysisConfig, AnalysisContext
from ..core.driver_analyzer import DriverAnalyzer
from ..output.manager import OutputManager, UnifiedAnalysisResult
from ..output.formats import OutputFormat, OutputLevel
from .models import BatchConfig, DriverResult
from .memory import MemoryMonitor
from .progress import ProgressTracker

logger = logging.getLogger(__name__)


def analyze_single_driver(
    driver_path: Path, timeout: int = 120, verbose: bool = False, safe_mode: bool = False, profile: str = "fast"
) -> UnifiedAnalysisResult:
    """Analyze a single driver - worker process function.

    This function runs in a separate process and must be pickleable.
    """
    import logging
    import os

    # Set up logging for worker process
    if verbose:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [PID:%(process)d] %(message)s")
        logger = logging.getLogger(__name__)
        logger.info(f"Starting analysis of {driver_path.name} (timeout: {timeout}s)")

    try:
        start_time = time.time()

        # Create output manager for unified results
        output_manager = OutputManager(
            output_level=OutputLevel.VERBOSE if verbose else OutputLevel.NORMAL,
            output_format=OutputFormat.JSON,
            dedup_vulnerabilities=True,
            capture_raw_state=False,  # Keep lightweight for batch processing
        )

        if safe_mode:
            # Use safe analyzer with conservative settings
            from .safe_analyzer import analyze_driver_safe_with_unified_output

            unified_result = analyze_driver_safe_with_unified_output(
                driver_path, profile=profile, timeout_override=timeout, verbose=verbose, output_manager=output_manager
            )
            return unified_result
        else:
            # Original analysis mode with unified output
            config = AnalysisConfig(timeout=timeout, debug=False, verbose=verbose)
            context = AnalysisContext.create_for_driver(driver_path, config, output_manager=output_manager)

            analyzer = DriverAnalyzer(context)
            result = analyzer.analyze()

            # Calculate analysis time and create unified result
            analysis_time = time.time() - start_time
            unified_result = output_manager.create_result(raw_result=result, analysis_time=analysis_time)

            if verbose:
                logger.info(f"Completed analysis of {driver_path.name} in {analysis_time:.2f}s")

            return unified_result

    except Exception as e:
        if verbose:
            logger.error(f"Failed to analyze {driver_path.name}: {e}")

        # Create a minimal output manager for error result
        output_manager = OutputManager(
            output_level=OutputLevel.NORMAL,
            output_format=OutputFormat.JSON,
            dedup_vulnerabilities=True,
            capture_raw_state=False,
        )
        output_manager.initialize(driver_path, {})

        # Create unified error result
        error_result = output_manager.create_result(raw_result=None, analysis_time=0, errors=[str(e)])

        return error_result


class ProcessingStrategy(ABC):
    """Abstract base class for processing strategies."""

    def __init__(self, config: BatchConfig, progress_tracker: ProgressTracker | None = None):
        self.config = config
        self.progress = progress_tracker

    @abstractmethod
    def process(self, drivers: list[Path]) -> Iterator[DriverResult]:
        """Process a list of drivers.

        Yields:
            DriverResult objects as they complete
        """
        pass


class SequentialProcessor(ProcessingStrategy):
    """Sequential processing - one driver at a time."""

    def process(self, drivers: list[Path]) -> Iterator[DriverResult]:
        """Process drivers sequentially."""
        for driver_path in drivers:
            if self.progress:
                self.progress.update(description=f"Analyzing {driver_path.name}")

            unified_result = analyze_single_driver(
                driver_path,
                self.config.timeout_per_driver,
                self.config.verbose,
                safe_mode=bool(self.config.analysis_profile),
                profile=self.config.analysis_profile or "fast",
            )

            result = DriverResult(
                driver_path=driver_path,
                filename=driver_path.name,
                success=(len(unified_result.errors) == 0),
                analysis_time=unified_result.analysis_time,
                vuln_count=len(unified_result.vulnerabilities),
                error=unified_result.errors if unified_result.errors else None,
                data=unified_result,  # Store the unified result directly
            )

            if result.success:
                if result.vuln_count > 0:
                    if self.progress:
                        self.progress.log(f"{driver_path.name}: {result.vuln_count} vulnerability(ies)", "warning")
                elif self.config.verbose and self.progress:
                    self.progress.log(f"{driver_path.name}: Clean", "success")
            else:
                if self.progress:
                    self.progress.log(f"{driver_path.name}: Failed", "error")

            if self.progress:
                self.progress.update(advance=1)

            yield result


class ParallelProcessor(ProcessingStrategy):
    """Parallel processing using ProcessPoolExecutor."""

    def __init__(self, config: BatchConfig, progress_tracker: ProgressTracker | None = None):
        super().__init__(config, progress_tracker)
        self.num_workers = config.num_workers or multiprocessing.cpu_count()

    def process(self, drivers: list[Path]) -> Iterator[DriverResult]:
        """Process drivers in parallel."""
        import time

        start_times = {}

        with ProcessPoolExecutor(max_workers=self.num_workers) as executor:
            # Submit all jobs
            future_to_driver = {}
            for driver_path in drivers:
                future = executor.submit(
                    analyze_single_driver,
                    driver_path,
                    self.config.timeout_per_driver,
                    self.config.verbose,
                    safe_mode=bool(self.config.analysis_profile),
                    profile=self.config.analysis_profile or "fast",
                )
                future_to_driver[future] = driver_path
                start_times[driver_path] = time.time()

                # Log job submission
                if self.config.verbose and self.progress:
                    self.progress.log(f"→ Starting: {driver_path.name}", "info")

            # Process results as they complete
            for future in as_completed(future_to_driver):
                driver_path = future_to_driver[future]
                elapsed = time.time() - start_times.get(driver_path, time.time())

                try:
                    unified_result = future.result()

                    result = DriverResult(
                        driver_path=driver_path,
                        filename=driver_path.name,
                        success=(len(unified_result.errors) == 0),
                        analysis_time=unified_result.analysis_time,
                        vuln_count=len(unified_result.vulnerabilities),
                        error=unified_result.errors if unified_result.errors else None,
                        data=unified_result,  # Store the unified result directly
                    )

                    if result.success:
                        if result.vuln_count > 0:
                            if self.progress:
                                self.progress.log(
                                    f"✓ {driver_path.name}: {result.vuln_count} vulnerability(ies) [{elapsed:.1f}s]",
                                    "warning",
                                )
                        elif self.config.verbose and self.progress:
                            self.progress.log(f"✓ {driver_path.name}: Clean [{elapsed:.1f}s]", "success")
                    else:
                        if self.progress:
                            error_msg = result.error[0] if result.error else "Unknown error"
                            self.progress.log(f"✗ {driver_path.name}: {error_msg} [{elapsed:.1f}s]", "error")

                except Exception as e:
                    # Create error result using unified output format
                    output_manager = OutputManager(output_level=OutputLevel.NORMAL, output_format=OutputFormat.JSON)
                    output_manager.initialize(driver_path, {})
                    error_result = output_manager.create_result(raw_result=None, analysis_time=elapsed, errors=[str(e)])

                    result = DriverResult(
                        driver_path=driver_path,
                        filename=driver_path.name,
                        success=False,
                        analysis_time=elapsed,
                        error=[str(e)],
                        data=error_result,
                    )
                    if self.progress:
                        self.progress.log(f"✗ {driver_path.name}: Error - {e} [{elapsed:.1f}s]", "error")

                if self.progress:
                    self.progress.update(advance=1)

                yield result


class SafeProcessor(ProcessingStrategy):
    """Memory-safe batch processing with worker recycling."""

    def __init__(self, config: BatchConfig, progress_tracker: ProgressTracker | None = None):
        super().__init__(config, progress_tracker)
        self.num_workers = config.num_workers or min(4, multiprocessing.cpu_count())
        self.memory_monitor = MemoryMonitor(config.memory_threshold_gb, config.memory_percent_threshold)

    def _process_batch(self, batch: list[Path], batch_num: int) -> list[DriverResult]:
        """Process a single batch of drivers."""
        import time

        results = []
        start_times = {}

        # Check if we should recycle workers
        if self.memory_monitor.should_recycle_workers(batch_num):
            self.memory_monitor.force_cleanup()
            if self.progress:
                self.progress.log(f"Recycled workers at batch {batch_num + 1}", "info")

        # Process batch with fresh executor
        with ProcessPoolExecutor(max_workers=self.num_workers) as executor:
            future_to_driver = {}
            for driver_path in batch:
                future = executor.submit(
                    analyze_single_driver,
                    driver_path,
                    self.config.timeout_per_driver,
                    self.config.verbose,
                    safe_mode=bool(self.config.analysis_profile),
                    profile=self.config.analysis_profile or "fast",
                )
                future_to_driver[future] = driver_path
                start_times[driver_path] = time.time()

            for future in as_completed(future_to_driver):
                driver_path = future_to_driver[future]
                elapsed = time.time() - start_times.get(driver_path, time.time())

                try:
                    unified_result = future.result()

                    result = DriverResult(
                        driver_path=driver_path,
                        filename=driver_path.name,
                        success=(len(unified_result.errors) == 0),
                        analysis_time=unified_result.analysis_time,
                        vuln_count=len(unified_result.vulnerabilities),
                        error=unified_result.errors if unified_result.errors else None,
                        data=unified_result,  # Store the unified result directly
                    )

                    if result.success:
                        if result.vuln_count > 0:
                            if self.progress:
                                self.progress.log(
                                    f"✓ {driver_path.name}: {result.vuln_count} vulnerability(ies) [{elapsed:.1f}s]",
                                    "warning",
                                )
                        elif self.config.verbose and self.progress:
                            self.progress.log(f"✓ {driver_path.name}: Clean [{elapsed:.1f}s]", "success")
                    else:
                        if self.progress:
                            error_msg = result.error[0] if result.error else "Unknown error"
                            self.progress.log(f"✗ {driver_path.name}: {error_msg} [{elapsed:.1f}s]", "error")

                except Exception as e:
                    # Create error result using unified output format
                    output_manager = OutputManager(output_level=OutputLevel.NORMAL, output_format=OutputFormat.JSON)
                    output_manager.initialize(driver_path, {})
                    error_result = output_manager.create_result(raw_result=None, analysis_time=elapsed, errors=[str(e)])

                    result = DriverResult(
                        driver_path=driver_path,
                        filename=driver_path.name,
                        success=False,
                        analysis_time=elapsed,
                        error=[str(e)],
                        data=error_result,
                    )
                    if self.progress:
                        self.progress.log(f"✗ {driver_path.name}: Error - {e} [{elapsed:.1f}s]", "error")

                results.append(result)

                if self.progress:
                    self.progress.update(advance=1)

        return results

    def process(self, drivers: list[Path]) -> Iterator[DriverResult]:
        """Process drivers in memory-safe batches."""
        total_batches = (len(drivers) + self.config.batch_size - 1) // self.config.batch_size

        for batch_num in range(total_batches):
            start_idx = batch_num * self.config.batch_size
            end_idx = min(start_idx + self.config.batch_size, len(drivers))
            batch = drivers[start_idx:end_idx]

            if self.progress:
                self.progress.log(f"Processing batch {batch_num + 1}/{total_batches} ({len(batch)} drivers)", "info")

            batch_results = self._process_batch(batch, batch_num)

            yield from batch_results

            # Memory stats after batch
            mem_stats = self.memory_monitor.get_stats()
            if self.progress and self.config.verbose:
                self.progress.log(
                    f"Memory: {mem_stats['current_gb']:.2f}GB ({mem_stats['current_percent']:.1f}%)", "info"
                )
