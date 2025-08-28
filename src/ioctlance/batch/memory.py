"""Memory management utilities for batch processing."""

import gc
import logging
import os
import psutil

logger = logging.getLogger(__name__)


class MemoryMonitor:
    """Monitor and manage memory usage during batch processing."""

    def __init__(self, threshold_gb: float = 80.0, percent_threshold: int = 85):
        """Initialize memory monitor.

        Args:
            threshold_gb: Absolute memory threshold in GB
            percent_threshold: Percentage memory threshold
        """
        self.threshold_gb = threshold_gb
        self.percent_threshold = percent_threshold
        self.process = psutil.Process(os.getpid())
        self.initial_memory = self.get_memory_info()
        self.peak_memory = self.initial_memory

    def get_memory_info(self) -> tuple[float, float]:
        """Get current memory usage.

        Returns:
            Tuple of (used_gb, percent_used)
        """
        memory = psutil.virtual_memory()
        used_gb = memory.used / (1024**3)
        percent = memory.percent
        return used_gb, percent

    def get_process_memory(self) -> float:
        """Get current process memory usage in GB."""
        return self.process.memory_info().rss / (1024**3)

    def check_memory_threshold(self) -> bool:
        """Check if memory usage exceeds thresholds.

        Returns:
            True if memory threshold exceeded
        """
        used_gb, percent = self.get_memory_info()

        # Update peak memory
        if used_gb > self.peak_memory[0]:
            self.peak_memory = (used_gb, percent)

        if used_gb >= self.threshold_gb:
            logger.warning(f"Memory usage ({used_gb:.2f}GB) exceeds threshold ({self.threshold_gb}GB)")
            return True

        if percent >= self.percent_threshold:
            logger.warning(f"Memory usage ({percent:.1f}%) exceeds threshold ({self.percent_threshold}%)")
            return True

        return False

    def force_cleanup(self) -> None:
        """Force memory cleanup."""
        logger.info("Forcing memory cleanup...")

        # Clear all module-level caches
        try:
            import angr

            if hasattr(angr, "_global_factory"):
                angr._global_factory = None
        except:
            pass

        # Force garbage collection
        gc.collect()
        gc.collect()
        gc.collect()

        used_gb, percent = self.get_memory_info()
        logger.info(f"Memory after cleanup: {used_gb:.2f}GB ({percent:.1f}%)")

    def get_stats(self) -> dict:
        """Get memory statistics.

        Returns:
            Dictionary with memory stats
        """
        current = self.get_memory_info()
        process_mem = self.get_process_memory()

        return {
            "current_gb": current[0],
            "current_percent": current[1],
            "peak_gb": self.peak_memory[0],
            "peak_percent": self.peak_memory[1],
            "process_gb": process_mem,
            "threshold_gb": self.threshold_gb,
            "threshold_percent": self.percent_threshold,
        }

    def should_recycle_workers(self, batch_num: int, batch_interval: int = 5) -> bool:
        """Determine if workers should be recycled.

        Args:
            batch_num: Current batch number
            batch_interval: Recycle workers every N batches

        Returns:
            True if workers should be recycled
        """
        # Check memory threshold
        if self.check_memory_threshold():
            return True

        # Periodic recycling
        if batch_num > 0 and batch_num % batch_interval == 0:
            logger.info(f"Recycling workers after batch {batch_num}")
            return True

        return False
