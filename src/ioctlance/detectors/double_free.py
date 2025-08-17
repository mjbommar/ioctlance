"""Double-free and use-after-free vulnerability detector."""

import logging
from typing import Any, cast

from angr import SimState

from ..core.analysis_context import AnalysisContext
from ..utils.helpers import safe_hex, get_state_globals
from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


class DoubleFreeDetector(VulnerabilityDetector):
    """Detects double-free and use-after-free vulnerabilities in kernel drivers."""

    name = "double_free"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects double-free and use-after-free vulnerabilities"

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the double-free detector.

        Args:
            context: Analysis context
        """
        super().__init__(context)
        # Track allocations and frees per state
        self.allocations = {}  # ptr -> (size, alloc_site)
        self.freed_pointers = set()  # Set of freed pointers
        self.detected_vulns = set()

    def detect(self, state: SimState) -> dict[str, Any] | None:
        """Detect double-free vulnerabilities.

        Args:
            state: Current simulation state

        Returns:
            Vulnerability information if detected, None otherwise
        """
        # Called from hooks
        return None

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check if a vulnerability exists in the current state.

        Args:
            state: Current simulation state
            event_type: Type of event (e.g., 'mem_read', 'mem_write', 'call')
            **kwargs: Additional event-specific parameters

        Returns:
            Vulnerability information if detected, None otherwise
        """
        # This detector works through specific API hooks
        return None

    def check_exallocatepool(self, state: SimState, pool_type: Any, size: Any, tag: Any = None) -> Any:
        """Track ExAllocatePool allocations.

        Args:
            state: Current simulation state
            pool_type: Type of pool (PagedPool, NonPagedPool, etc.)
            size: Size of allocation
            tag: Optional pool tag

        Returns:
            Allocated pointer (for hook to return)
        """
        # Generate a symbolic pointer for the allocation
        alloc_ptr = state.solver.BVS(f"pool_alloc_{state.addr:x}", state.arch.bits)

        # Track this allocation
        state_id = id(state)
        if state_id not in self.allocations:
            self.allocations[state_id] = {}

        self.allocations[state_id][alloc_ptr] = {
            "size": size,
            "alloc_site": state.addr,
            "pool_type": pool_type,
        }

        logger.debug(f"Tracked allocation at {state.addr:x}")

        return alloc_ptr

    def check_exfreepool(self, state: SimState, pool_ptr: Any) -> dict[str, Any] | None:
        """Check ExFreePool for double-free.

        Args:
            state: Current simulation state
            pool_ptr: Pointer to free

        Returns:
            Vulnerability info if detected
        """
        state_id = id(state)

        # Check if pointer is NULL (not a vuln but worth noting)
        try:
            if hasattr(pool_ptr, "concrete"):
                ptr_val = state.solver.eval_one(pool_ptr)
            else:
                ptr_val = pool_ptr

            if ptr_val == 0:
                # Freeing NULL is usually safe
                return None
        except:
            pass

        # Check if this pointer was already freed (double-free)
        if pool_ptr in self.freed_pointers:
            vuln_key = (state.addr, "double_free", str(pool_ptr)[:20])
            if vuln_key not in self.detected_vulns:
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Double-Free Vulnerability",
                    description="ExFreePool called on already freed pointer",
                    state=state,
                    parameters={
                        "pool_ptr": str(pool_ptr)[:100],
                        "free_site": hex(state.addr),
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "CRITICAL",
                        "exploitation": "Heap corruption, code execution",
                        "impact": "Memory corruption, potential RCE",
                    },
                )

        # Check if freeing untracked pointer (potential issue)
        if state_id not in self.allocations or pool_ptr not in self.allocations[state_id]:
            # Check if it's tainted - could be freeing user-controlled pointer
            if self._is_tainted(pool_ptr):
                vuln_key = (state.addr, "tainted_free")
                if vuln_key not in self.detected_vulns:
                    self.detected_vulns.add(vuln_key)

                    return self.create_vulnerability_info(
                        title="Tainted Pointer Free",
                        description="ExFreePool called with user-controlled pointer",
                        state=state,
                        parameters={
                            "pool_ptr": str(pool_ptr)[:100],
                            "ioctl_code": self._get_ioctl_code(state),
                        },
                        others={
                            "severity": "HIGH",
                            "exploitation": "Arbitrary free primitive",
                            "impact": "Heap corruption",
                        },
                    )

        # Mark as freed
        self.freed_pointers.add(pool_ptr)

        # Remove from allocations
        if state_id in self.allocations and pool_ptr in self.allocations[state_id]:
            del self.allocations[state_id][pool_ptr]

        return None

    def check_memory_access(self, state: SimState, address: Any, size: Any, is_write: bool) -> dict[str, Any] | None:
        """Check for use-after-free on memory access.

        Args:
            state: Current simulation state
            address: Address being accessed
            size: Size of access
            is_write: True if write, False if read

        Returns:
            Vulnerability info if detected
        """
        # Check if accessing a freed pointer
        if address in self.freed_pointers:
            vuln_key = (state.addr, "use_after_free", str(address)[:20])
            if vuln_key not in self.detected_vulns:
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Use-After-Free Vulnerability",
                    description=f"{'Write' if is_write else 'Read'} to freed memory",
                    state=state,
                    parameters={
                        "address": str(address)[:100],
                        "size": str(size)[:100],
                        "access_type": "write" if is_write else "read",
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "CRITICAL",
                        "exploitation": "Code execution via freed object reuse",
                        "impact": "Memory corruption, RCE",
                    },
                )

        # Check if we're accessing memory within a freed allocation
        state_id = id(state)
        if state_id in self.allocations:
            for alloc_ptr, alloc_info in self.allocations[state_id].items():
                if alloc_ptr in self.freed_pointers:
                    # Check if address falls within the freed allocation
                    try:
                        alloc_start = state.solver.eval_one(alloc_ptr) if hasattr(alloc_ptr, "concrete") else alloc_ptr
                        alloc_size = (
                            state.solver.eval_one(alloc_info["size"])
                            if hasattr(alloc_info["size"], "concrete")
                            else alloc_info["size"]
                        )
                        addr_val = state.solver.eval_one(address) if hasattr(address, "concrete") else address

                        if alloc_start <= addr_val < alloc_start + alloc_size:
                            vuln_key = (state.addr, "uaf_range", str(alloc_ptr)[:20])
                            if vuln_key not in self.detected_vulns:
                                self.detected_vulns.add(vuln_key)

                                return self.create_vulnerability_info(
                                    title="Use-After-Free (Range Check)",
                                    description="Access within freed allocation range",
                                    state=state,
                                    parameters={
                                        "address": hex(addr_val),
                                        "freed_base": hex(alloc_start),
                                        "freed_size": str(alloc_size),
                                        "ioctl_code": self._get_ioctl_code(state),
                                    },
                                    others={
                                        "severity": "CRITICAL",
                                        "exploitation": "Freed object manipulation",
                                        "technique": "Heap spray and reallocation",
                                    },
                                )
                    except:
                        pass

        return None

    def check_exallocatepoolwithtag(self, state: SimState, pool_type: Any, size: Any, tag: Any) -> Any:
        """Track ExAllocatePoolWithTag allocations.

        Args:
            state: Current simulation state
            pool_type: Type of pool
            size: Size of allocation
            tag: Pool tag

        Returns:
            Allocated pointer (for hook to return)
        """
        return self.check_exallocatepool(state, pool_type, size, tag)

    def check_exfreepoolwithtag(self, state: SimState, pool_ptr: Any, tag: Any) -> dict[str, Any] | None:
        """Check ExFreePoolWithTag for double-free.

        Args:
            state: Current simulation state
            pool_ptr: Pointer to free
            tag: Pool tag

        Returns:
            Vulnerability info if detected
        """
        return self.check_exfreepool(state, pool_ptr)

    def _is_tainted(self, value: Any) -> bool:
        """Check if a value is tainted (user-controlled).

        Args:
            value: Value to check

        Returns:
            True if value is tainted
        """
        if value is None:
            return False
        if hasattr(value, "symbolic"):
            return value.symbolic
        elif hasattr(value, "variables"):
            return len(value.variables) > 0
        return False

    def _get_ioctl_code(self, state: SimState) -> str:
        """Get IOCTL code from state if available.

        Args:
            state: Current simulation state

        Returns:
            IOCTL code as hex string or '0x0'
        """
        globals_dict = get_state_globals(state)
        if "IoControlCode" in globals_dict:
            return safe_hex(globals_dict["IoControlCode"])
        elif self.context and self.context.io_control_code:
            try:
                return safe_hex(state.solver.eval(self.context.io_control_code))
            except:
                pass
        return "0x0"


# Register the detector
detector_registry.register(DoubleFreeDetector)
