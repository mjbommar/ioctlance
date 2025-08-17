"""Race condition (double-fetch/TOCTOU) detector for IOCTLance."""

from typing import Any

from angr import SimState

from .base import VulnerabilityDetector, detector_registry


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
        if event_type != "memory_read":
            return None

        address = kwargs.get("address")
        size = kwargs.get("size", 0)

        if address is None:
            return None

        # Try to get concrete address
        try:
            # Try to evaluate the address to a concrete value
            if hasattr(address, "__class__") and hasattr(state.solver, "eval"):
                # Check if it's symbolic and has a single solution
                if state.solver.symbolic(address):
                    solutions = state.solver.eval_upto(address, 2)
                    if len(solutions) != 1:
                        # Multiple solutions or unsolvable - can't track
                        return None
                    concrete_addr = solutions[0]
                else:
                    concrete_addr = state.solver.eval(address)
            else:
                concrete_addr = int(address)
        except Exception:
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

                return self.create_vulnerability_info(
                    title="double-fetch race condition",
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
            if hasattr(probe_addr, "symbolic") and probe_addr.symbolic:
                return

            concrete_addr = state.solver.eval(probe_addr) if hasattr(probe_addr, "__class__") else int(probe_addr)
            concrete_size = state.solver.eval(probe_size) if hasattr(probe_size, "__class__") else int(probe_size)

            # Mark this region as "probed" - any subsequent double-read is highly suspicious
            state_addr = state.addr if hasattr(state, "addr") else 0
            self.user_space_reads[concrete_addr] = (state_addr, concrete_size)

        except:
            pass


# Register the detector
detector_registry.register(RaceConditionDetector)
