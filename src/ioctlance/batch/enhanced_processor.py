"""Enhanced processor with better status tracking for stuck drivers."""

import logging
import time
from concurrent.futures import ProcessPoolExecutor, Future
from pathlib import Path
from typing import Dict, Any
from collections.abc import Iterator
import multiprocessing
from datetime import datetime

from .models import BatchConfig, DriverResult
from .processor import analyze_single_driver
from .progress import ProgressTracker

logger = logging.getLogger(__name__)


class EnhancedParallelProcessor:
    """Parallel processor with better status tracking."""

    def __init__(self, config: BatchConfig, progress_tracker: ProgressTracker | None = None):
        self.config = config
        self.progress = progress_tracker
        self.num_workers = config.num_workers or multiprocessing.cpu_count()
        self.active_jobs: dict[Future, tuple[Path, float]] = {}

    def process(self, drivers: list[Path]) -> Iterator[DriverResult]:
        """Process drivers in parallel with status tracking."""
        with ProcessPoolExecutor(max_workers=self.num_workers) as executor:
            # Submit all jobs and track them
            future_to_driver = {}

            for driver_path in drivers:
                future = executor.submit(
                    analyze_single_driver, driver_path, self.config.timeout_per_driver, self.config.verbose
                )
                future_to_driver[future] = driver_path
                self.active_jobs[future] = (driver_path, time.time())

                # Log submission
                if self.progress:
                    self.progress.log(f"Queued: {driver_path.name}", "info")

            # Process results as they complete
            completed = 0
            last_status_time = time.time()

            while future_to_driver:
                # Check for completed futures with a short timeout
                done_futures = []
                for future in future_to_driver:
                    if future.done():
                        done_futures.append(future)

                # Process completed futures
                for future in done_futures:
                    driver_path = future_to_driver.pop(future)
                    start_time = self.active_jobs.pop(future, (None, time.time()))[1]
                    elapsed = time.time() - start_time

                    try:
                        result_data = future.result(timeout=1)

                        result = DriverResult(
                            driver_path=driver_path,
                            filename=driver_path.name,
                            success=result_data["success"],
                            analysis_time=result_data["analysis_time"],
                            vuln_count=result_data["vuln_count"],
                            error=result_data.get("error"),
                            data=result_data,
                        )

                        if result.success:
                            if result.vuln_count > 0:
                                if self.progress:
                                    self.progress.log(
                                        f"✓ {driver_path.name}: {result.vuln_count} vulnerability(ies) ({elapsed:.1f}s)",
                                        "warning",
                                    )
                            elif self.config.verbose and self.progress:
                                self.progress.log(f"✓ {driver_path.name}: Clean ({elapsed:.1f}s)", "success")
                        else:
                            if self.progress:
                                self.progress.log(f"✗ {driver_path.name}: Failed ({elapsed:.1f}s)", "error")

                    except Exception as e:
                        result = DriverResult(
                            driver_path=driver_path,
                            filename=driver_path.name,
                            success=False,
                            analysis_time=elapsed,
                            error=[str(e)],
                            data={},
                        )
                        if self.progress:
                            self.progress.log(f"✗ {driver_path.name}: Error - {e} ({elapsed:.1f}s)", "error")

                    completed += 1
                    if self.progress:
                        self.progress.update(advance=1)

                    yield result

                # Periodically show status of active jobs
                current_time = time.time()
                if current_time - last_status_time > 10 and self.active_jobs:  # Every 10 seconds
                    last_status_time = current_time

                    # Show currently analyzing drivers
                    if self.progress and self.config.verbose:
                        active_list = []
                        for future, (path, start) in list(self.active_jobs.items())[:10]:  # Show max 10
                            if future in future_to_driver:
                                elapsed = current_time - start
                                if elapsed > 30:  # Warn if taking too long
                                    active_list.append(f"{path.name} ({elapsed:.0f}s ⚠)")
                                else:
                                    active_list.append(f"{path.name} ({elapsed:.0f}s)")

                        if active_list:
                            self.progress.log(f"Currently analyzing: {', '.join(active_list)}", "info")

                            # Warn about potential timeouts
                            timeout_warning = [
                                path.name
                                for future, (path, start) in self.active_jobs.items()
                                if current_time - start > self.config.timeout_per_driver * 0.8
                            ]
                            if timeout_warning:
                                self.progress.log(f"⚠ Approaching timeout: {', '.join(timeout_warning[:5])}", "warning")

                # Small sleep to avoid busy waiting
                if future_to_driver:
                    time.sleep(0.1)
