"""Race condition (double-fetch/TOCTOU) detector for IOCTLance."""

import logging
from typing import Any

from angr import SimState

from .base import VulnerabilityDetector, detector_registry
from ..utils.error_handler import SymbolicExecutionErrorHandler

logger = logging.getLogger(__name__)


class RaceConditionDetector(VulnerabilityDetector):
    """Detects double-fetch and TOCTOU race condition vulnerabilities."""

    def __init__(self, context: Any) -> None:
        """Initialize the race condition detector.

        Args:
            context: Analysis context
        """
        super().__init__(context)
        # Track addresses that have been read from user space
        # Format: {address: (first_read_state_addr, first_read_value)}
        self.user_space_reads: dict[int, tuple[int, Any]] = {}
        # Deduplication of reported double-fetch vulnerabilities
        self._reported: set[tuple[int, int]] = set()

    @property
    def name(self) -> str:
        """Get detector name."""
        return "race_condition"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects double-fetch and TOCTOU race condition vulnerabilities"

    def _is_user_space_address(self, address: int) -> bool:
        """Check if address is in user space.

        Args:
            address: Address to check

        Returns:
            True if address is in user space
        """
        # Windows x64: User space is 0x0 - 0x7FFFFFFFFFFF
        # Windows x86: User space is 0x0 - 0x7FFFFFFF
        if self.context.project.arch.bits == 64:
            return 0 <= address < 0x800000000000
        else:
            return 0 <= address < 0x80000000

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check for race condition vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event ('memory_read', 'memory_write')
            **kwargs: Event-specific data (address, size, value)

        Returns:
            Vulnerability info if found, None otherwise
        """
        # Normalize to mem_read events as emitted by breakpoints
        if event_type != "mem_read":
            return None

        address = kwargs.get("address")
        size = kwargs.get("size", 0)

        if address is None:
            return None

        # Try to get concrete address
        try:
            # Try to evaluate the address to a concrete value
            if SymbolicExecutionErrorHandler.safe_symbolic_check(address):
                solutions = state.solver.eval_upto(address, 2)
                if len(solutions) != 1:
                    # Multiple solutions or unsolvable - can't track
                    return None
                concrete_addr = solutions[0]
            else:
                # Safe evaluation for non-symbolic values
                concrete_addr = (
                    SymbolicExecutionErrorHandler.safe_eval(state, address, default=None)
                    if hasattr(state, "solver")
                    else int(address)
                )
            # Ensure it's an int
            concrete_addr = int(concrete_addr) if concrete_addr is not None else None
        except Exception as e:
            logger.debug(f"RaceConditionDetector: failed to concretize address: {e}")
            return None

        # Check if this is a user-space address
        if not self._is_user_space_address(concrete_addr):
            return None

        # Check if we've seen this address before (double-fetch)
        for tracked_addr in list(self.user_space_reads.keys()):
            # Check for overlapping reads
            tracked_end = (
                tracked_addr + self.user_space_reads[tracked_addr][1]
                if len(self.user_space_reads[tracked_addr]) > 1
                else tracked_addr + 8
            )
            current_end = concrete_addr + size

            # Check if the reads overlap
            if (tracked_addr <= concrete_addr < tracked_end) or (concrete_addr <= tracked_addr < current_end):
                # Double-fetch detected!
                first_state_addr = self.user_space_reads[tracked_addr][0]
                # Deduplicate per concrete address and current basic block site
                report_key = (tracked_addr, state.addr if hasattr(state, "addr") else 0)
                if report_key in self._reported:
                    return None
                self._reported.add(report_key)

                return self.create_vulnerability_info(
                    title="Double-Fetch Race Condition",
                    description=f"Multiple reads from user-space address {hex(concrete_addr)}",
                    state=state,
                    others={
                        "first_read_address": hex(tracked_addr),
                        "first_read_state": hex(first_state_addr),
                        "second_read_address": hex(concrete_addr),
                        "second_read_state": hex(state.addr if hasattr(state, "addr") else 0),
                        "read_size": str(size),
                        "vulnerability_type": "TOCTOU",
                        "exploitation": "Attacker can modify data between reads to bypass checks",
                    },
                )

        # Track this read for future detection
        state_addr = state.addr if hasattr(state, "addr") else 0
        self.user_space_reads[concrete_addr] = (state_addr, size)

        # Limit tracking to prevent memory issues
        if len(self.user_space_reads) > 1000:
            # Remove oldest entries
            oldest_keys = list(self.user_space_reads.keys())[:100]
            for key in oldest_keys:
                del self.user_space_reads[key]

        return None

    def check_probeforread_pattern(self, state: SimState, probe_addr: Any, probe_size: Any) -> None:
        """Track ProbeForRead calls for TOCTOU pattern detection.

        Args:
            state: Current simulation state
            probe_addr: Address being probed
            probe_size: Size being probed
        """
        # This can be called by ProbeForRead hooks to help detect
        # the pattern: ProbeForRead -> use data -> use data again (TOCTOU)
        try:
            if SymbolicExecutionErrorHandler.safe_symbolic_check(probe_addr):
                return

            concrete_addr = SymbolicExecutionErrorHandler.safe_eval(state, probe_addr, default=None)
            concrete_size = SymbolicExecutionErrorHandler.safe_eval(state, probe_size, default=0)

            if concrete_addr is None:
                return

            # Mark this region as "probed" - any subsequent double-read is highly suspicious
            state_addr = state.addr if hasattr(state, "addr") else 0
            self.user_space_reads[int(concrete_addr)] = (state_addr, int(concrete_size))

        except Exception as e:
            logger.debug(f"RaceConditionDetector: failed to record ProbeForRead pattern: {e}")


# Register the detector
detector_registry.register(RaceConditionDetector)
