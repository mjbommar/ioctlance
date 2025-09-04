"""Worker-side analysis function and processing utilities."""

from __future__ import annotations

import logging
import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Iterator

from ..core.analysis_context import AnalysisConfig, AnalysisContext
from ..core.driver_analyzer import DriverAnalyzer
from ..output.formats import OutputFormat, OutputLevel
from ..output.manager import OutputManager, UnifiedAnalysisResult
from .models import BatchConfig, DriverResult

logger = logging.getLogger(__name__)


def analyze_single_driver(
    driver_path: Path,
    timeout: int = 120,
    verbose: bool = False,
    profile: str | None = None,
    search_strategy: str | None = None,
    beam_width: int | None = None,
    triage_steps: int | None = None,
    triage_beam_width: int | None = None,
) -> UnifiedAnalysisResult:
    """Analyze a single driver and return a UnifiedAnalysisResult.

    Designed to run in a worker process (pickleable).
    """
    if verbose:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [PID:%(process)d] %(message)s")
        logging.getLogger(__name__).info(f"Starting analysis of {driver_path.name} (timeout: {timeout}s)")

    try:
        start = time.time()
        output_manager = OutputManager(
            output_level=OutputLevel.VERBOSE if verbose else OutputLevel.NORMAL,
            output_format=OutputFormat.JSON,
            dedup_vulnerabilities=True,
            capture_raw_state=False,
        )

        # Use profile when provided; otherwise use basic timeout-only config
        if profile:
            try:
                cfg = AnalysisConfig.from_profile(profile)
            except ValueError:
                cfg = AnalysisConfig.fast()
            if timeout and timeout != cfg.timeout:
                scale = timeout / cfg.timeout
                cfg.timeout = timeout
                cfg.ioctl_timeout = max(1, int(cfg.ioctl_timeout * scale))
        else:
            cfg = AnalysisConfig(timeout=timeout)

        cfg.verbose = verbose
        cfg.debug = verbose
        # Apply search strategy overrides
        if search_strategy is not None:
            cfg.search_strategy = search_strategy
        if beam_width is not None:
            cfg.beam_width = beam_width
        if triage_steps is not None:
            cfg.triage_steps = triage_steps
        if triage_beam_width is not None:
            cfg.triage_beam_width = triage_beam_width

        context = AnalysisContext.create_for_driver(driver_path, cfg, output_manager=output_manager)
        analyzer = DriverAnalyzer(context)
        raw = analyzer.analyze()
        analysis_time = time.time() - start
        unified = output_manager.create_result(
            raw_result=raw, analysis_time=analysis_time, metrics=getattr(context, "metrics", {})
        )
        if verbose:
            logging.getLogger(__name__).info(f"Completed {driver_path.name} in {analysis_time:.2f}s")
        return unified
    except Exception as e:
        if verbose:
            logging.getLogger(__name__).error(f"Failed to analyze {driver_path.name}: {e}")
        # Minimal error result
        output_manager = OutputManager(
            output_level=OutputLevel.NORMAL,
            output_format=OutputFormat.JSON,
            dedup_vulnerabilities=True,
            capture_raw_state=False,
        )
        output_manager.initialize(driver_path, {})
        return output_manager.create_result(raw_result=None, analysis_time=0, errors=[str(e)])


def parallel_process(cfg: BatchConfig, drivers: list[Path]) -> Iterator[DriverResult]:
    """Process drivers in parallel and yield DriverResult as they complete."""
    workers = cfg.num_workers or multiprocessing.cpu_count()
    start_times: dict[Path, float] = {}
    with ProcessPoolExecutor(max_workers=workers) as ex:
        future_to_driver = {}
        for d in drivers:
            fut = ex.submit(
                analyze_single_driver,
                d,
                cfg.timeout_per_driver,
                cfg.verbose,
                cfg.analysis_profile,
                cfg.search_strategy,
                cfg.beam_width,
                cfg.triage_steps,
                cfg.triage_beam_width,
            )
            future_to_driver[fut] = d
            start_times[d] = time.time()
        for fut in as_completed(future_to_driver):
            d = future_to_driver[fut]
            try:
                unified = fut.result()
                yield DriverResult(
                    driver_path=d,
                    filename=d.name,
                    success=(len(unified.errors) == 0),
                    analysis_time=unified.analysis_time,
                    vuln_count=len(unified.vulnerabilities),
                    error=unified.errors or None,
                    data=unified,
                )
            except Exception as e:
                # Return error wrapper
                om = OutputManager(output_level=OutputLevel.NORMAL, output_format=OutputFormat.JSON)
                om.initialize(d, {})
                err_res = om.create_result(raw_result=None, analysis_time=0, errors=[str(e)])
                yield DriverResult(
                    driver_path=d,
                    filename=d.name,
                    success=False,
                    analysis_time=0.0,
                    vuln_count=0,
                    error=[str(e)],
                    data=err_res,
                )


def sequential_process(cfg: BatchConfig, drivers: list[Path]) -> Iterator[DriverResult]:
    for d in drivers:
        unified = analyze_single_driver(
            d,
            cfg.timeout_per_driver,
            cfg.verbose,
            cfg.analysis_profile,
            cfg.search_strategy,
            cfg.beam_width,
            cfg.triage_steps,
            cfg.triage_beam_width,
        )
        yield DriverResult(
            driver_path=d,
            filename=d.name,
            success=(len(unified.errors) == 0),
            analysis_time=unified.analysis_time,
            vuln_count=len(unified.vulnerabilities),
            error=unified.errors or None,
            data=unified,
        )
